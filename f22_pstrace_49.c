#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/pstrace.h>
#define PSTRACE_BUF_SIZE 500
long total_counter;
int tracing_enabled;
int clear;
struct pstrace ring_buf[PSTRACE_BUF_SIZE];
struct pstrace empty = {0};
int ring_buf_iter;
DEFINE_SPINLOCK(ring_buf_lock);
pid_t traced_processes[PSTRACE_BUF_SIZE];
int num_traced_procs;
DEFINE_SPINLOCK(traced_proc_lock);
static DECLARE_WAIT_QUEUE_HEAD(get_wait);
long user_counter;
void copy_kern_to_user(struct pstrace *ubuf, struct pstrace *rbuf)
{
 memcpy(ubuf->comm, rbuf->comm, 16);
 ubuf->state = rbuf->state;
 ubuf->pid = rbuf->pid;
 ubuf->tid = rbuf->tid;
}
int find_pid(pid_t pid)
{
 int found = 0;
 int i;
 for (i = 0; i < num_traced_procs; i++) {
  if (traced_processes[i] == pid)
   found = 1;
  }
 return found;
}
int check_state(long state)
{
 int found = 0;
 if (state == TASK_RUNNING)
  found = 1;
 else if (state == TASK_RUNNABLE)
  found = 1;
 else if (state == TASK_INTERRUPTIBLE)
  found = 1;
 else if (state == TASK_UNINTERRUPTIBLE)
  found = 1;
 else if (state == __TASK_STOPPED)
  found = 1;
 else if (state == EXIT_ZOMBIE)
  found = 1;
 else if (state == EXIT_DEAD)
  found = 1;
 return found;
}
static struct task_struct *test_pid(int pid)
{
 if (pid == 0)
  return &init_task;
 return find_task_by_vpid(pid);
}
void pstrace_add(struct task_struct *p, long state)
{
 struct wait_queue_entry *pos, *n;
 unsigned long flags;
 spin_lock(&traced_proc_lock);
 spin_lock(&ring_buf_lock);
 /* Three checks before adding to ring buffer
  * 1) Check if the state is a traceable state
  * 2) Check if tracing is enabled
  * 3) Check if the pid of the passed process is being traced
  */
 if ((check_state(state)) &&
  (((tracing_enabled) && (find_pid(p->pid))) ||
  ((tracing_enabled) && (num_traced_procs == -1)))
 ) {
  struct pstrace p_add;
  memcpy(p_add.comm, p->comm, 16);
  p_add.state = state;
  p_add.pid = p->tgid;
  p_add.tid = p->pid;
  ring_buf[ring_buf_iter] = p_add;
  total_counter++;
  ring_buf_iter++;
  if (ring_buf_iter == PSTRACE_BUF_SIZE)
   ring_buf_iter = 0;
 }
 spin_unlock(&ring_buf_lock);
 spin_unlock(&traced_proc_lock);
 spin_lock_irqsave(&ring_buf_lock, flags);
 list_for_each_entry_safe(pos, n, &get_wait.head, entry) {
  if (user_counter + PSTRACE_BUF_SIZE > total_counter)
   wake_up_all(&get_wait);
 }
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 user_counter = 0;
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if ((pid != -1) && (test_pid(pid) == NULL))
  return -EINVAL;
 if (pid == -1) {
  /*
   * PID = -1
   * --------
   * When the PID argument is equal to -1, it means that
   * we need to trace all processes. We increment the
   * count of traced processes for each process we find, so
   * we know how many indices to iterate through.
   */
  spin_lock(&traced_proc_lock);
  tracing_enabled = 1;
  num_traced_procs = -1;
  spin_unlock(&traced_proc_lock);
 } else {
  /*
   * PID != -1
   * --------
   * When the PID argument is not equal to -1, we just need
   * to trace the given PID. We just replace the first element
   * of the traced processes buffer with the given PID. We also
   * set the number of elements in the buffer to 1, so only its
   * value is checked.
   */
  spin_lock(&traced_proc_lock);
  tracing_enabled = 1;
  traced_processes[0] = pid;
  num_traced_procs = 1;
  spin_unlock(&traced_proc_lock);
 }
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 spin_lock(&traced_proc_lock);
 tracing_enabled = 0;
 spin_unlock(&traced_proc_lock);
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 /* TODO Need to return error on signal interruptions!*/
 struct pstrace *kbuf;
 long kcounter;
 int k_iter, buf_vals;
 size_t size;
 unsigned long flags;
 struct pstrace_evt;
 DECLARE_WAITQUEUE(wait, current);
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 user_counter = kcounter;
 if (kcounter < 0)
  return -EINVAL;
 if (total_counter < PSTRACE_BUF_SIZE) {
  size = total_counter * sizeof(struct pstrace);
  buf_vals = total_counter;
 } else {
  size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
  buf_vals = PSTRACE_BUF_SIZE;
 }
 kbuf = kmalloc(size, GFP_KERNEL);
 if (kcounter == 0) {
  /*no sleep call, return buffer contents*/
  /*
   * Process context: Disable interrupts when locking:
   * since we are going to access shared resource which is
   * the ring buffer, we will need a mechanism of locking
   * resource: https://linux-kernel-labs.github.io/refs/pull/183/merge/labs/interrupts.html
   */
  buf_vals = ring_buf_iter;
  spin_lock_irqsave(&ring_buf_lock, flags);
  for (k_iter = 0; k_iter < buf_vals; k_iter++)
   copy_kern_to_user(&kbuf[k_iter], &ring_buf[k_iter]);
  spin_unlock_irqrestore(&ring_buf_lock, flags);
     user_counter = total_counter;
 } else if (kcounter > 0 &&
  (kcounter + PSTRACE_BUF_SIZE <= total_counter)) {
  /*
   * no sleep, return buffer, but need to check on valid entries
   * such as calling with counter == 100, but total_counter is 700
   * and 101-200 have been rewritten, only return 201-600????
   *
   * This means to sort the ring_buf into proper chronological
   * order using my kbuf.
   */
  long real_counter = total_counter - PSTRACE_BUF_SIZE;
  buf_vals = kcounter + PSTRACE_BUF_SIZE - real_counter;
  total_counter = kcounter + PSTRACE_BUF_SIZE;
  spin_lock_irqsave(&ring_buf_lock, flags);
  for (k_iter = 0; k_iter < buf_vals; k_iter++)
   copy_kern_to_user(&kbuf[k_iter], &ring_buf[k_iter]);
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  user_counter = real_counter;
 } else if ((kcounter > 0) && (kcounter + PSTRACE_BUF_SIZE > total_counter)) {
  /*
   * the complex sleep that waits until
   * counter == counter + PSTRACE_BUF_SIZE
   */
  /*
   * As professor mentioned in post #521,
   * "since using wait_event() will  cause a task to block
   * in state TASK_UNINTERRUPTIBLE, which is probably
   * not quite what you want"
   * and using wait_event_interruptible would cause issues with
   * signals.. we will use add_wait_queue to set the current
   * state to TASK_INTERRUPTIBLE
   * sources:1- https://flylib.com/books/en/4.454.1.46/1/ where we followed the same steps
   * 2- https://elixir.bootlin.com/linux/v4.8/source/include/linux/wait.h#L163
   *
   */
  add_wait_queue(&get_wait, &wait);
  while ((clear != 1) && (kcounter + PSTRACE_BUF_SIZE > total_counter)) {
   prepare_to_wait(&get_wait, &wait, TASK_INTERRUPTIBLE);
   if (signal_pending(current))
    return -EINTR;
   schedule();
  }
  finish_wait(&get_wait, &wait);
  buf_vals = total_counter - kcounter;
  spin_lock_irqsave(&ring_buf_lock, flags);
  for (k_iter = 0; k_iter < buf_vals; k_iter++)
   copy_kern_to_user(&kbuf[k_iter], &ring_buf[k_iter]);
  spin_unlock_irqrestore(&ring_buf_lock, flags);
 }
 if (put_user(user_counter, counter) ||
  copy_to_user(buf, kbuf, size)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return buf_vals;
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
 int i;
 spin_lock_irq(&ring_buf_lock);
 clear = 1;
 wake_up_all(&get_wait);
 clear = 0;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  traced_processes[i] = -1;
  ring_buf[i] = empty;
 }
 ring_buf_iter = 0;
 spin_unlock_irq(&ring_buf_lock);
 return 0;
}