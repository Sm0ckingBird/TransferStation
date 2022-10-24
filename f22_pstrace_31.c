#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h> // kmalloc
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#define _debug(...)
// #define _debug(...) printk(__VA_ARGS__)
static struct pstrace ring_buf[PSTRACE_BUF_SIZE];
static unsigned long version; // for clear, default to 0
static long buf_counter_min; // default to 0
static long buf_counter; // default to 0
static pid_t pid_trace = -2; // -2 for disable
static unsigned long need_wakeup_total; // a global counter for wakeup check
static unsigned long need_wakeup_curr; // only used by pstrace_wakeup
static DEFINE_SPINLOCK(mu_pid); // for pid_trace
static DEFINE_SPINLOCK(mu_counter); // for counters, version, conditions
static DECLARE_WAIT_QUEUE_HEAD(wq_head);
// store wakeup conditions, statically allocated for now
#define CONDITION_SIZE 1000
static long condition[CONDITION_SIZE];
static int condition_len; // default to 0
int add_condition(int c)
{
 // return 1 if success, 0 if conditions full
 int i = 0, j;
 // find bisect position
 while ((i < condition_len) && (condition[i] < c))
  i++;
 // c already in condition
 if ((i < condition_len) && (condition[i] == c))
  return 1;
 // no room to add condition
 if (condition_len >= CONDITION_SIZE)
  return 0;
 // shift the large element
 j = condition_len;
 while (j > i) {
  condition[j] = condition[j - 1];
  j--;
 }
 condition[i] = c;
 condition_len++;
 return 1;
}
int pop_condition(void)
{
 /* if counter is less than all conditions, return 0, otherwise
  * return 1 and remove those smaller-or-equal elements
  */
 int delta = 1, i;
 _debug("pstrace: %d conditions, first one is %ld", condition_len,
        condition[0]);
 if ((condition_len == 0) || (buf_counter < condition[0]))
  return 0;
 while ((delta < condition_len) && (condition[delta] <= buf_counter))
  delta++;
 i = delta;
 while (i < condition_len) {
  condition[i - delta] = condition[i];
  i++;
 }
 condition_len -= delta;
 return 1;
}
void clear_condition(void)
{
 condition_len = 0;
}
void pstrace_check_wakeup(void)
{
 int need_wakeup_total_local = need_wakeup_total;
 if (need_wakeup_curr < need_wakeup_total_local) {
  // need_wakeup_curr is only used by this function
  // and it is non-decreasing, so no need to lock
  need_wakeup_curr = need_wakeup_total_local;
  _debug("pstrace: waking up tasks");
  wake_up_all(&wq_head);
  /* wake_up only works for TASK_INTERRUPTIBLE and
   * TASK_UNINTERRUPTIBLE, so there is no secondary call
   */
 }
}
void copy_entries(struct pstrace *p, long idx_start, long idx_end)
{
 int i;
 for (i = idx_start; i < idx_end; i++)
  p[i - idx_start] = ring_buf[i % PSTRACE_BUF_SIZE];
}
void display_entry(struct pstrace *p)
{
 _debug("pstrace, pid=%d, tid=%d, comm=%s, state=%ld\n", p->pid, p->tid,
        p->comm, p->state);
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 /* rcu_read_lock() is not necessary because all
  * the use cases ensures that p does not change
  */
 long idx;
 unsigned long flags_mu_pid, flags_mu_counter;
 spin_lock_irqsave(&mu_pid, flags_mu_pid);
 if (pid_trace == -1 || p->tgid == pid_trace) {
  spin_unlock_irqrestore(&mu_pid, flags_mu_pid);
  _debug("start pstrace add\n");
  spin_lock_irqsave(&mu_counter, flags_mu_counter);
  idx = buf_counter % PSTRACE_BUF_SIZE;
  get_task_comm(ring_buf[idx].comm, p);
  ring_buf[idx].state = state;
  ring_buf[idx].pid = p->tgid;
  ring_buf[idx].tid = p->pid;
  buf_counter++;
  _debug("pstrace counter=%ld", buf_counter);
  display_entry(ring_buf + idx);
  if (pop_condition())
   need_wakeup_total++;
  spin_unlock_irqrestore(&mu_counter, flags_mu_counter);
  _debug("finish pstrace add\n");
  // cannot piggyback wakeup here due to __schedule() deadlock
 } else {
  spin_unlock_irqrestore(&mu_pid, flags_mu_pid);
 }
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flags;
 _debug("start pstrace_enable\n");
 if (pid < -1) {
  _debug("pstrace_enable with invalid pid %d", pid);
  return -EINVAL;
 }
 spin_lock_irqsave(&mu_pid, flags);
 pid_trace = pid;
 spin_unlock_irqrestore(&mu_pid, flags);
 _debug("finish pstrace_enable\n");
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flags;
 _debug("start pstrace_disable\n");
 spin_lock_irqsave(&mu_pid, flags);
 pid_trace = -2;
 spin_unlock_irqrestore(&mu_pid, flags);
 _debug("finish pstrace_disable\n");
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
 DEFINE_WAIT(wq_entry);
 long idx_start, idx_end, count;
 long version_curr; // if version is newer, stop waiting
 unsigned long flags, size;
 struct pstrace *p;
 _debug("start pstrace_get\n");
 if (copy_from_user(&idx_start, counter, sizeof(long)))
  return -EFAULT;
 // _debug("[pstrace] from user idx_start=%ld\n", idx_start);
 if (idx_start < 0)
  return -EINVAL;
 size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 p = kmalloc(size, GFP_KERNEL);
 if (p == NULL)
  return -ENOMEM;
 // copy entries to temp buffer p
 spin_lock_irqsave(&mu_counter, flags);
 if (idx_start == 0) {
  // return all valid entries in buffer immediately
  idx_end = buf_counter;
  if (buf_counter - PSTRACE_BUF_SIZE < buf_counter_min) {
   idx_start = buf_counter_min;
   // _debug("[pstrace] branch 1\n");
   // _debug("[pstrace] idx_start=%ld\n", idx_start);
   // _debug("buf_counter_min=%ld\n", buf_counter_min);
  } else {
   idx_start = buf_counter - PSTRACE_BUF_SIZE;
   // _debug("[pstrace] branch 2\n");
   // _debug("idx_start=%ld\n", idx_start);
   // _debug("buf_counter=%ld\n", buf_counter);
  }
  // _debug("[pstrace] idx_start=%ld, idx_end=%ld\n", idx_start, idx_end);
 } else {
  idx_end = idx_start + PSTRACE_BUF_SIZE;
  // make sure the min bound is valid
  if (idx_start < buf_counter_min)
   idx_start = buf_counter_min;
  if (idx_end <= buf_counter) {
   /* return valid entries in buffer between counter and
    * counter+PSTRACE_BUF_SIZE, which may be < PSTRACE_BUF_SIZE
    * if some of the entries have been overwritten by more recent
    * entries outside of that range.  for example, if you called
    * with counter=100, but entries 101-200 have been overwritten
    * because current counter = 700, return 201-600.
    */
   if (idx_start < buf_counter - PSTRACE_BUF_SIZE)
    idx_start = buf_counter - PSTRACE_BUF_SIZE;
  } else {
   /* wait until counter=counter+PSTRACE_BUF_SIZE;
    * return valid entries between counter and counter+PSTRACE_BUF_SIZE
    */
   version_curr = version;
   if (!add_condition(idx_end)) {
    // too many concurrent pstrace_get, no enough space for conditions
    kfree(p);
    return -EAGAIN; // try again later
   }
   do {
    prepare_to_wait(&wq_head, &wq_entry,
      TASK_INTERRUPTIBLE);
    spin_unlock_irqrestore(&mu_counter, flags);
    schedule();
    _debug("[pstrace] waked up on %ld\n", idx_end);
    if (signal_pending(current)) {
     kfree(p);
     finish_wait(&wq_head, &wq_entry);
     _debug("pstrace_get finishes due to signal\n");
     return -EINTR;
    }
    spin_lock_irqsave(&mu_counter, flags);
   } while (buf_counter < idx_end &&
     version_curr == version);
   finish_wait(&wq_head, &wq_entry);
   // _debug("[pstrace] got out of the wait loop, counter=%ld\n", buf_counter);
   // finalize idx_start and idx_end
   // here if the getter is delayed, the actual entries may be less than 500
   // but when tracking a single process, the situation is unlikely to happen
   // see https://edstem.org/us/courses/28099/discussion/1966140
   // if (buf_counter < idx_end) // early wake up
   //     idx_end = buf_counter;
   // in case idx_end < buf_counter, it makes more sense to
   // return all available entries
   idx_end = buf_counter;
   if (idx_start < buf_counter - PSTRACE_BUF_SIZE)
    idx_start = buf_counter - PSTRACE_BUF_SIZE;
  }
 }
 // _debug("[pstrace] idx_start=%ld, idx_end=%ld\n", idx_start, idx_end);
 if (idx_start < idx_end) {
  count = idx_end - idx_start;
  copy_entries(p, idx_start, idx_end);
 } else { // no entries to copy
  count = 0;
  idx_end = buf_counter;
 }
 spin_unlock_irqrestore(&mu_counter, flags);
 _debug("[pstrace] idx_start=%ld, idx_end=%ld, count=%ld\n", idx_start,
        idx_end, count);
 // copy to user space
 if (copy_to_user(counter, &idx_end, sizeof(long)) ||
     copy_to_user(buf, p, count * sizeof(struct pstrace))) {
  kfree(p);
  return -EFAULT;
 }
 kfree(p);
 _debug("finish pstrace_get\n");
 return count;
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
 _debug("start pstrace_clear\n");
 spin_lock_irqsave(&mu_counter, flags);
 buf_counter_min = buf_counter;
 version++;
 clear_condition();
 spin_unlock_irqrestore(&mu_counter, flags);
 wake_up_all(&wq_head);
 _debug("finish pstrace_clear\n");
 return 0;
}