#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
struct pstrace_tracker {
 pid_t pid;
 long counter;
 long clear_flag;
 long counter_limit;
 struct pstrace pstrace_ring_buffer[PSTRACE_BUF_SIZE];
};
DEFINE_SPINLOCK(pstrace_lock);
DECLARE_WAIT_QUEUE_HEAD(pstrace_get_wait_queue);
struct pstrace_tracker tracker = { .pid = -2,
       .counter = -1,
       .clear_flag = 0,
       .counter_limit = -1 };
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flag;
 struct task_struct *ts;
 if (pid < 0 && pid != -1) {
  return -EINVAL;
 } else if (pid > 0) {
  rcu_read_lock();
  ts = find_task_by_vpid(pid);
  rcu_read_unlock();
  if (!ts)
   return -ESRCH;
 }
 spin_lock_irqsave(&pstrace_lock, flag);
 tracker.pid = pid;
 spin_unlock_irqrestore(&pstrace_lock, flag);
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flag;
 spin_lock_irqsave(&pstrace_lock, flag);
 tracker.pid = -2;
 spin_unlock_irqrestore(&pstrace_lock, flag);
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter)
{
 long k_counter, curr_flag, curr_limit, copy_size, sig_ret, ret;
 struct pstrace *kbuf;
 long cnt_start, cnt_end;
 int start_idx, end_idx;
 unsigned long flags;
 if (!counter || !buf)
  return -EINVAL;
 if (get_user(k_counter, counter))
  return -EFAULT;
 if (k_counter < 0)
  return -EINVAL;
 spin_lock_irqsave(&pstrace_lock, flags);
 kbuf = tracker.pstrace_ring_buffer;
 curr_limit = tracker.counter_limit;
 if (k_counter == 0) {
  cnt_start = max(curr_limit + 1,
    tracker.counter - PSTRACE_BUF_SIZE + 1);
  cnt_end = tracker.counter;
  goto copy;
 }
 if (k_counter + PSTRACE_BUF_SIZE > tracker.counter) {
  curr_flag = tracker.clear_flag;
  spin_unlock_irqrestore(&pstrace_lock, flags);
  sig_ret = wait_event_interruptible(
   pstrace_get_wait_queue,
   (curr_flag < tracker.clear_flag) ||
    (tracker.counter >=
     k_counter + PSTRACE_BUF_SIZE));
  if (sig_ret != 0)
   return -EINTR;
  spin_lock_irqsave(&pstrace_lock, flags);
 }
 cnt_end = min(tracker.counter, k_counter + PSTRACE_BUF_SIZE);
 cnt_start =
  max(max(tracker.counter - PSTRACE_BUF_SIZE + 1, k_counter + 1),
      curr_limit + 1);
copy:
 copy_size = cnt_end - cnt_start + 1;
 if (copy_size <= 0) {
  ret = put_user(max(tracker.counter, 0l), counter);
  if (ret)
   ret = -EFAULT;
  goto out;
 }
 ret = put_user(max(cnt_end, 0l), counter);
 if (ret) {
  ret = -EFAULT;
  goto out;
 }
 start_idx = (int)(cnt_start % PSTRACE_BUF_SIZE);
 end_idx = (int)(cnt_end % PSTRACE_BUF_SIZE);
 if (end_idx >= start_idx) {
  ret = copy_to_user(buf, &kbuf[start_idx],
       (end_idx - start_idx + 1) *
        sizeof(struct pstrace));
  if (ret) {
   ret = -EFAULT;
   goto out;
  }
 } else {
  ret = copy_to_user(buf, &kbuf[start_idx],
       (PSTRACE_BUF_SIZE - start_idx) *
        sizeof(struct pstrace));
  if (ret) {
   ret = -EFAULT;
   goto out;
  }
  ret = copy_to_user(buf + (PSTRACE_BUF_SIZE - start_idx),
       &kbuf[0],
       (end_idx + 1) * sizeof(struct pstrace));
  if (ret) {
   ret = -EFAULT;
   goto out;
  }
 }
 ret = copy_size;
out:
 spin_unlock_irqrestore(&pstrace_lock, flags);
 return ret;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 unsigned long flag;
 spin_lock_irqsave(&pstrace_lock, flag);
 tracker.clear_flag++;
 tracker.counter_limit = tracker.counter;
 spin_unlock_irqrestore(&pstrace_lock, flag);
 wake_up_interruptible(&pstrace_get_wait_queue);
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace *target_pstrace;
 unsigned long flags;
 spin_lock_irqsave(&pstrace_lock, flags);
 if (tracker.pid != -1 && p->tgid != tracker.pid) {
  spin_unlock_irqrestore(&pstrace_lock, flags);
  return;
 }
 target_pstrace = &tracker.pstrace_ring_buffer[++tracker.counter %
            PSTRACE_BUF_SIZE];
 memcpy(target_pstrace->comm, p->comm, TASK_COMM_LEN);
 target_pstrace->state = state;
 target_pstrace->pid = p->tgid;
 target_pstrace->tid = p->pid;
 spin_unlock_irqrestore(&pstrace_lock, flags);
}