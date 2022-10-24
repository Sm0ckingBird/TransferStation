#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/pstrace.h>
#include <linux/export.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
pid_t pstrace_tgid = -2;        /* Global variable for current tgid to trace */
atomic_t total_count = ATOMIC_INIT(0);
atomic_t oldest_valid_log = ATOMIC_INIT(0);
long pstrace_clear_flag; /*Global flag to trigger wakeup */
long pstrace_was_cleared_flag; /* Sole purpose is to notify rbuf_add that a clear happened */
long waking_flag;
int read_count;          /* Global read counter for tracking locks */
atomic_t sleeper_count = ATOMIC_INIT(0);
struct pstrace my_rbuf[PSTRACE_BUF_SIZE];       /* Global ring buffer */
DECLARE_WAIT_QUEUE_HEAD(pstrace_get_wait);          /* Global wait queue */
DECLARE_WAIT_QUEUE_HEAD(pstrace_add_wait);          /* Global wait queue */
DEFINE_SPINLOCK(r_lock);
DEFINE_SPINLOCK(w_lock);
atomic_t using_lock = ATOMIC_INIT(0);
unsigned long flags;
/*
 * Helper function to check if process state is what we are looking
 * for. Returns 1 if true, 0 is false.
 */
static int check_task_type(long state)
{
 if (state == TASK_RUNNING ||
  state == TASK_RUNNABLE ||
  state == TASK_INTERRUPTIBLE ||
  state == TASK_UNINTERRUPTIBLE ||
  state == TASK_STOPPED ||
  state == EXIT_DEAD ||
  state == EXIT_ZOMBIE) {
  return 1;
 }
 return 0;
}
/*
 * Helper function to add items to the global ring buffer my_rbuf.
 */
static void rbuf_add(struct task_struct *p, long state)
{
 struct pstrace r;
 struct wait_queue_entry *qp;
 struct list_head *ptr;
 /* We shouldn't need to lock here because task struct should be protected by kernel */
 strcpy(r.comm, p->comm);
 r.state = state;
 r.pid = task_pid_vnr(p);
 r.tid = task_tgid_vnr(p);
 /* Should only happen when buffer is full */
 if (atomic_read(&total_count) > PSTRACE_BUF_SIZE + atomic_read(&oldest_valid_log))
  atomic_inc(&oldest_valid_log);
 spin_lock_irqsave(&r_lock, flags);
 my_rbuf[atomic_read(&total_count) % PSTRACE_BUF_SIZE] = r;
 spin_unlock_irqrestore(&r_lock, flags);
 atomic_inc(&total_count);
 spin_lock_irqsave(&pstrace_get_wait.lock, flags);
 list_for_each(ptr, &pstrace_get_wait.head) {
  qp = list_entry(ptr, struct wait_queue_entry, entry);
  if (*((int *) qp->private) == atomic_read(&total_count))
   wake_up(&pstrace_get_wait);
 }
 spin_unlock_irqrestore(&pstrace_get_wait.lock, flags);
}
/*
 * Called in the kernel to log a process state transition.
 */
void pstrace_add(struct task_struct *p, long state)
{
 if (pstrace_tgid == -2 || !check_task_type(state))
  return;
 if (pstrace_tgid == p->tgid || pstrace_tgid == -1)
  rbuf_add(p, state);
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *task;
 /* trace all processes */
 if (pid == -1)
  pstrace_tgid = -1;
 else if (pid < 0)
  return -EINVAL;
 rcu_read_lock();
 task = find_task_by_vpid(pid);
 rcu_read_unlock();
 if (!task || task->tgid < 0)
  return -ESRCH;
 pstrace_tgid = task->tgid;
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 pstrace_tgid = -2;
 return 0;
}
/*
 * Helper function to copy the buffer over to the user space.
 */
long copy_over_buf(struct pstrace *buf, long l_oldest_valid_log, long num_to_copy)
{
 int i = 0;
 int index;
 struct pstrace *kbuf;
 int buf_size = sizeof(struct pstrace) * num_to_copy;
 if (num_to_copy == 0)
  return 0;
 kbuf = kmalloc(buf_size, GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
 spin_lock_irqsave(&r_lock, flags);
 index = l_oldest_valid_log;
 for (i = 0; i < num_to_copy; i++) {
  kbuf[i] = my_rbuf[index % PSTRACE_BUF_SIZE];
  index++;
 }
 spin_unlock_irqrestore(&r_lock, flags);
 if (copy_to_user(buf, kbuf, sizeof(struct pstrace) * num_to_copy)) {
  kfree(kbuf);
  return -EINVAL;
 }
 kfree(kbuf);
 return num_to_copy;
}
/*
 * Syscall No. 443
 *
 * Copy the pstrace ring buffer info @buf.
 * If @counter > 0, the caller process will wait until a full buffer can
 * be returned after record @counter (i.e. return record @counter + 1 to
 * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
 *
 * Returns the number of records copied.
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 long kcounter;         /* Counter in kernal space. */
 long num_to_copy = PSTRACE_BUF_SIZE; /* Number of records to copy. */
 long l_total_count;        /* Local copy of total number of records. */
 long l_oldest_valid_log;   /* Local copy of oldest valid record. */
 long queue_number;
 DEFINE_WAIT(wait);
 l_total_count = atomic_read(&total_count);
 l_oldest_valid_log = atomic_read(&oldest_valid_log);
 if (get_user(kcounter, counter))
  return -EFAULT;
 /* Case 1: counter < 0 */
 if (kcounter < 0)
  return -EINVAL;
 /* Ensure there are any valid records to copy. */
 if (l_total_count == 0) {
  if (put_user(l_total_count, counter))
   return -EFAULT;
  return 0;
 }
 /*
  * Case 2: counter == 0, non-blocking, return buffer
  * Note: if # of records is less than PSTRACE_BUF_SIZE, we should
  * kmalloc and return only that (I think..)
  */
 if (kcounter == 0) {
  if (l_total_count - l_oldest_valid_log  < PSTRACE_BUF_SIZE) {
   num_to_copy = l_total_count - l_oldest_valid_log;
   if (put_user(l_oldest_valid_log + num_to_copy, counter))
    return -EFAULT;
  } else {
   num_to_copy = PSTRACE_BUF_SIZE;
   if (put_user(l_total_count, counter))
    return -EFAULT;
  }
  return copy_over_buf(buf, l_oldest_valid_log, num_to_copy);
 }
 /*
  * Case 3: DESIRED ENTRIES ALREADY IN RBUF
  * counter + PSTRACE_BUF_SIZE <= total_count
  * i.e. total_count == 700, they pass in 100, we
  * return 200-600.
  */
 if (kcounter + PSTRACE_BUF_SIZE <= l_total_count) {
  /*
   * Case 3.1: kcounter + 500 is lower than our oldest_valid log
   * we return 0 and put total_count into user counter
   */
  if (kcounter + PSTRACE_BUF_SIZE < l_oldest_valid_log) {
   if (put_user(l_total_count, counter))
    return -EFAULT;
   return 0;
  }
  num_to_copy = (kcounter + PSTRACE_BUF_SIZE) - l_oldest_valid_log;
  if (put_user(l_oldest_valid_log + num_to_copy, counter))
   return -EFAULT;
  return copy_over_buf(buf, l_oldest_valid_log, num_to_copy);
 }
 /*
  * Case 4: DESIRED ENTRIES ARE FUTURE ENTRIES
  * (HARD) counter + PSTRACE_BUF_SIZE > total_count, block and
  * wait until counter+PSTRACE_BUF_SIZE <= total_count
  */
 else /*(kcounter + PSTRACE_BUF_SIZE > l_total_count)*/ {
  if (pstrace_clear_flag)
   pstrace_clear_flag = 0;
  queue_number = kcounter + PSTRACE_BUF_SIZE;
  wait.private = &queue_number;
  while (atomic_read(&total_count) < kcounter + PSTRACE_BUF_SIZE) {
   prepare_to_wait(&pstrace_get_wait, &wait, TASK_INTERRUPTIBLE);
   schedule();
  }
  finish_wait(&pstrace_get_wait, &wait);
  l_total_count = atomic_read(&total_count);
  l_oldest_valid_log = atomic_read(&oldest_valid_log);
  if (!atomic_read(&sleeper_count)) {
   pstrace_clear_flag = 0;
   waking_flag = 0;
  }
  if (put_user(l_total_count, counter))
   return -EFAULT;
  num_to_copy = l_total_count - l_oldest_valid_log;
  return copy_over_buf(buf, l_oldest_valid_log, num_to_copy);
 }
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 spin_lock_irqsave(&r_lock, flags);
 oldest_valid_log = total_count;
 pstrace_clear_flag = 1;
 spin_unlock_irqrestore(&r_lock, flags);
 wake_up(&pstrace_get_wait);
 return 0;
}
EXPORT_SYMBOL_GPL(pstrace_add);