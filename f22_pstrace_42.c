#include <linux/kernel.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
static struct pstrace
 pstrace_buf[PSTRACE_BUF_SIZE]; /* change to dynamical allocation later */
static size_t pstrace_buf_beg = 0, pstrace_buf_size = 0;
static size_t pstrace_beg_counter = 0;
static int pstrace_enabled = 0;
static pid_t pstrace_pid = -1; /* -1 for tracing all threads */
static DEFINE_SPINLOCK(pstrace_data_lock);
static DEFINE_SPINLOCK(pstrace_ctl_lock);
static DECLARE_WAIT_QUEUE_HEAD(pstrace_wait);
static inline size_t get_pstrace_buf_size(void)
{
 size_t retval;
 unsigned long flags;
 spin_lock_irqsave(&pstrace_data_lock, flags);
 retval = pstrace_buf_size;
 spin_unlock_irqrestore(&pstrace_data_lock, flags);
 return retval;
}
static inline int pstrace_get_cond(long counter)
{
 int retval;
 unsigned long flags;
 spin_lock_irqsave(&pstrace_data_lock, flags);
 retval = pstrace_beg_counter + pstrace_buf_size >=
   counter + PSTRACE_BUF_SIZE;
 spin_unlock_irqrestore(&pstrace_data_lock, flags);
 return retval;
}
void pstrace_add(struct task_struct *p, long state)
{
 int enabled;
 char comm[16];
 pid_t pid;
 pid_t tid;
 struct pstrace *target;
 unsigned long flags;
 spin_lock_irqsave(&pstrace_ctl_lock, flags);
 enabled = pstrace_enabled;
 if (likely(!(enabled && ((pid = task_tgid_nr(p)) == pstrace_pid ||
     pstrace_pid == -1)))) {
  spin_unlock_irqrestore(&pstrace_ctl_lock, flags);
  return;
 }
 spin_unlock_irqrestore(&pstrace_ctl_lock, flags);
 tid = task_pid_nr(p);
 get_task_comm(comm, p);
 spin_lock_irqsave(&pstrace_data_lock, flags);
 if (pstrace_buf_size >= PSTRACE_BUF_SIZE) {
  pstrace_buf_beg = (pstrace_buf_beg + 1) % PSTRACE_BUF_SIZE;
  pstrace_beg_counter += 1;
  pstrace_buf_size -= 1;
 }
 target = &pstrace_buf[(pstrace_buf_beg + pstrace_buf_size) %
         PSTRACE_BUF_SIZE];
 strncpy(target->comm, comm, 16);
 target->state = state;
 target->pid = pid;
 target->tid = tid;
 pstrace_buf_size += 1;
 spin_unlock_irqrestore(&pstrace_data_lock, flags);
}
void pstrace_wakeup(void)
{
 wake_up_interruptible(&pstrace_wait);
}
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flags;
 rcu_read_lock();
 if (pid != -1 && get_root(pid) == NULL) {
  rcu_read_unlock();
  return -EFAULT;
 }
 rcu_read_unlock();
 spin_lock_irqsave(&pstrace_ctl_lock, flags);
 pstrace_enabled = 1;
 pstrace_pid = pid;
 spin_unlock_irqrestore(&pstrace_ctl_lock, flags);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
*/
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flags;
 spin_lock_irqsave(&pstrace_ctl_lock, flags);
 pstrace_enabled = 0;
 spin_unlock_irqrestore(&pstrace_ctl_lock, flags);
 return 0;
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter)
{
 long kcounter, kglobal_counter;
 struct pstrace *kbuf;
 long i, cur_size;
 unsigned long flags;
 if (get_user(kcounter, counter)) {
  return -EFAULT;
 }
 if (kcounter < 0) {
  return -EFAULT;
 }
 /* Allocate enough memory in advance, since kmalloc can't be used in spin_lock */
 if (!(kbuf = kmalloc(PSTRACE_BUF_SIZE * sizeof(struct pstrace),
        GFP_KERNEL))) {
  return -ENOMEM;
 }
 if (kcounter > 0) {
  wait_event_interruptible(pstrace_wait,
      pstrace_get_cond(kcounter));
 }
 spin_lock_irqsave(&pstrace_data_lock, flags);
 if (kcounter > 0)
  cur_size = max((long)pstrace_buf_size -
           ((long)pstrace_beg_counter - kcounter),
          0l);
 else
  cur_size = (long)pstrace_buf_size;
 for (i = 0; i < cur_size; ++i)
  kbuf[i] = pstrace_buf[(pstrace_buf_beg + i) % PSTRACE_BUF_SIZE];
 kglobal_counter = pstrace_beg_counter + cur_size;
 spin_unlock_irqrestore(&pstrace_data_lock, flags);
 if (copy_to_user((void *)buf, (void *)kbuf,
    cur_size * sizeof(struct pstrace))) {
  kfree(kbuf);
  return -EFAULT;
 }
 if (put_user(kglobal_counter, counter)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return cur_size;
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
 unsigned long flags;
 spin_lock_irqsave(&pstrace_data_lock, flags);
 pstrace_buf_size = 0;
 pstrace_beg_counter = 0;
 spin_unlock_irqrestore(&pstrace_data_lock, flags);
 return 0;
}