#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/signal.h>
struct ring_buffer rb = {
 .count = 0,
 .head = 0,
 .lock = __SPIN_LOCK_UNLOCKED(rb.lock)
};
unsigned long lock_flag;
atomic_t target = ATOMIC_INIT(-2);
atomic_t clear_flag = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(rbuffer_wait);
static LIST_HEAD(event_head);
static DEFINE_SPINLOCK(wait_lock);
struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
static inline void strace_info(struct pstrace *p, pid_t pid, long state)
{
 struct task_struct *task = get_root(pid);
 strcpy(p->comm, task->comm);
 p->state = state;
 p->pid = pid;
 p->tid = task->tgid;
}
static void pstrace_add_helper(struct task_struct *task, long state)
{
 int index;
 if (state > 0x0020)
  return;
 spin_lock_irqsave(&rb.lock, lock_flag);
 index = rb.count++ % PSTRACE_BUF_SIZE;
 strace_info(&rb.buf[index], task->pid, state);
 /*printk("pstrace_add: %d %ld %ld\n", task->pid, state, rb.count);*/
 spin_unlock_irqrestore(&rb.lock, lock_flag);
}
void pstrace_add(struct task_struct *task, long state)
{
 int target_pid = atomic_read(&target);
 if (target_pid != -1 && target_pid != task->pid)
  return;
 pstrace_add_helper(task, state);
}
void pstrace_wake(void)
{
 struct task_struct *task;
 struct pstrace_event *pos, *pos_next;
 long curr_count;
 spin_lock_irqsave(&rb.lock, lock_flag);
 curr_count = rb.count;
 spin_unlock_irqrestore(&rb.lock, lock_flag);
 spin_lock_irqsave(&wait_lock, lock_flag);
 list_for_each_entry_safe(pos, pos_next, &event_head, head) {
  if (pos->condition <= curr_count) {
   task = (struct task_struct *) pos->wq.private;
   list_del(&pos->head);
   wake_up_process(task);
  }
 }
 spin_unlock_irqrestore(&wait_lock, lock_flag);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, _pid)
{
 if (_pid != -1 && get_root(_pid) == NULL)
  return -ESRCH;
 atomic_set(&target, _pid);
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 atomic_set(&target, -2);
 return 0;
}
static int copy_buf_to_user(long start, long end, struct __user pstrace * buf)
{
 size_t copy_size;
 int copy_number;
 int i;
 struct pstrace *tmp_buf;
 copy_number = (end - start) % PSTRACE_BUF_SIZE + 1;
 copy_size = sizeof(struct pstrace) * copy_number;
 tmp_buf = kmalloc(copy_size, GFP_KERNEL);
 spin_lock_irqsave(&rb.lock, lock_flag);
 for (i = 0; i < copy_number; i++)
  tmp_buf[i] = rb.buf[(start + i) % PSTRACE_BUF_SIZE];
 spin_unlock_irqrestore(&rb.lock, lock_flag);
 if (copy_to_user(buf, tmp_buf, copy_size))
  return -1;
 /* printk("Finished copy %d logs to user.\n", copy_number); */
 kfree(tmp_buf);
 return 0;
}
void pos_counter_waitqueue(long cond, int *flag)
{
 DEFINE_WAIT(wait);
 DEFINE_PSTRACE_EVENT(event, cond, wait);
 spin_lock_irqsave(&wait_lock, lock_flag);
 do {
  prepare_to_wait(&rbuffer_wait, &wait, TASK_INTERRUPTIBLE);
  list_add(&event.head, &event_head);
  if (signal_pending(current) < 0)
   pr_debug("sigpending error!\n");
  else if (signal_pending(current))
   break;
  spin_unlock_irqrestore(&wait_lock, lock_flag);
  schedule();
  spin_lock_irqsave(&wait_lock, lock_flag);
 } while (cond > rb.count && !(*flag = atomic_read(&clear_flag)));
 finish_wait(&rbuffer_wait, &wait);
 spin_unlock_irqrestore(&wait_lock, lock_flag);
}
SYSCALL_DEFINE2(pstrace_get,
  struct __user pstrace *, buf,
  long __user *, counter)
{
 long user_counter;
 long start, end;
 long curr_count, curr_head;
 long cond;
 int flag;
 spin_lock_irqsave(&rb.lock, lock_flag);
 curr_head = rb.head;
 curr_count = rb.count;
 spin_unlock_irqrestore(&rb.lock, lock_flag);
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if (copy_from_user(&user_counter, counter, sizeof(long)))
  return -EFAULT;
 if (user_counter < 0) {
  return -EINVAL;
 } else if (user_counter == 0) {
  start = curr_head;
  end = curr_count;
  if (copy_buf_to_user(start, end, buf) < 0)
   return -EFAULT;
  if (copy_to_user(counter, &curr_count, sizeof(long)))
   return -EFAULT;
 } else if (user_counter > 0) {
  if (user_counter + 2 * PSTRACE_BUF_SIZE <= curr_count) {
   if (copy_to_user(counter, &curr_count, sizeof(long)))
    return -EFAULT;
  } else if (user_counter + PSTRACE_BUF_SIZE <= curr_count) {
   start = curr_count - PSTRACE_BUF_SIZE + 1;
   end = user_counter + PSTRACE_BUF_SIZE;
   if (copy_buf_to_user(start, end, buf) < 0)
    return -EFAULT;
   if (copy_to_user(counter, &curr_count, sizeof(long)))
    return -EFAULT;
  } else {
   cond = user_counter + PSTRACE_BUF_SIZE;
   pos_counter_waitqueue(cond, &flag);
   start = user_counter + 1;
   end = user_counter + PSTRACE_BUF_SIZE;
   if (flag)
    return 0;
   if (copy_buf_to_user(start, end, buf) < 0)
    return -EFAULT;
   if (copy_to_user(counter, &end, sizeof(long)))
    return -EFAULT;
  }
 }
 return 0;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 atomic_inc(&clear_flag);
 wake_up_all(&rbuffer_wait);
 LIST_HEAD(event_head);
 atomic_dec(&clear_flag);
 spin_lock_irqsave(&rb.lock, lock_flag);
 rb.head = rb.count;
 spin_unlock_irqrestore(&rb.lock, lock_flag);
 return 0;
}