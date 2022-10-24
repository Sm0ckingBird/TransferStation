#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/pstrace.h>
#include <linux/mutex.h>
#include <linux/string.h>
struct buf_entry ring_buf[PSTRACE_BUF_SIZE];
int tail;
/* Use atomic integer operations for the global counter */
atomic64_t ring_buff_count = ATOMIC64_INIT(0);
int trace_pid = -1;
bool trace_all;
int wakeup_val = -1;
bool need_to_wake_all;
LIST_HEAD(pc_head);
DEFINE_SPINLOCK(wq_spinlock);
DEFINE_SPINLOCK(rb_spinlock);
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flags;
 spin_lock_irqsave(&rb_spinlock, flags);
 if (pid == -1) {
  trace_all = true;
  trace_pid = -1;
 } else if (pid != -1 && get_root(pid)) {
  trace_all = false;
  trace_pid = pid;
 } else {
  spin_unlock_irqrestore(&rb_spinlock, flags);
  return -ESRCH;
 }
 spin_unlock_irqrestore(&rb_spinlock, flags);
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flags;
 spin_lock_irqsave(&rb_spinlock, flags);
 trace_all = false;
 trace_pid = -2;
 spin_unlock_irqrestore(&rb_spinlock, flags);
 return 0;
}
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long rb_flags;
 unsigned long wq_flags;
 /* create new entry for ring buffer */
 struct pstrace new_pstrace;
 struct buf_entry new_buf_entry;
 int new_count;
 struct pending_counter *curr, *temp;
 if (state < 0) {
  spin_lock_irqsave(&wq_spinlock, wq_flags);
  new_count = atomic64_read(&ring_buff_count);
  list_for_each_entry_safe(curr, temp, &pc_head, counter_list) {
   if (new_count >= curr->counter_num) {
    spin_unlock_irqrestore(&wq_spinlock, wq_flags);
    wake_up_all(&curr->wq);
    spin_lock_irqsave(&wq_spinlock, wq_flags);
   }
  }
  spin_unlock_irqrestore(&wq_spinlock, wq_flags);
  return;
 }
 spin_lock_irqsave(&rb_spinlock, rb_flags);
 new_pstrace.state = state;
 new_pstrace.pid = p->tgid;
 new_pstrace.tid = p->pid;
 memcpy(new_pstrace.comm, p->comm, sizeof(p->comm));
 new_buf_entry.count = atomic64_read(&ring_buff_count);
 new_buf_entry.valid = true;
 new_buf_entry.mpstrace = new_pstrace;
 /* check if head or tail has reached the end */
 if (tail >= PSTRACE_BUF_SIZE)
  tail = 0;
 /* save item to ring buffer */
 ring_buf[tail] = new_buf_entry;
 tail += 1;
 /* Increment global counter using atomic integer operation */
 atomic64_add(1, &ring_buff_count);
 new_count = atomic64_read(&ring_buff_count);
 spin_unlock_irqrestore(&rb_spinlock, rb_flags);
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter)
{
 unsigned long wq_flags;
 unsigned long rb_flags;
 long kcounter;
 struct pstrace *kbuf;
 long current_buf_end;
 long num_copied;
 long new_counter;
 int head_copy;
 int current_count;
 int i;
 need_to_wake_all = false;
 kbuf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace),
        GFP_KERNEL);
 if (!kbuf) {
  kfree(kbuf);
  return -ENOMEM;
 }
 /* check counter access */
 if (!access_ok(counter, sizeof(long))) {
  kfree(kbuf);
  return -EFAULT;
 }
 if (copy_from_user(&kcounter, counter, sizeof(long))) {
  kfree(kbuf);
  return -EFAULT;
 }
 if (kcounter < 0) {
  kfree(kbuf);
  return -EINVAL;
 }
 if (atomic64_read(&ring_buff_count) < kcounter + PSTRACE_BUF_SIZE &&
     kcounter != 0) {
  struct pending_counter *new_wait;
  new_wait = kmalloc(sizeof(struct pending_counter), GFP_KERNEL);
  if (!new_wait) {
   kfree(new_wait);
   kfree(kbuf);
   return -ENOMEM;
  }
  init_waitqueue_head(&new_wait->wq);
  new_wait->need_to_wakeup = false;
  new_wait->counter_num = kcounter + PSTRACE_BUF_SIZE;
  INIT_LIST_HEAD(&new_wait->counter_list);
  spin_lock_irqsave(&wq_spinlock, wq_flags);
  list_add_tail(&new_wait->counter_list, &pc_head);
  spin_unlock_irqrestore(&wq_spinlock, wq_flags);
  if (wait_event_interruptible(
       new_wait->wq, ((atomic64_read(&ring_buff_count) >=
         (kcounter + PSTRACE_BUF_SIZE)) ||
        need_to_wake_all))) {
   kfree(new_wait);
   kfree(kbuf);
   return -EINTR;
  }
  spin_lock_irqsave(&wq_spinlock, wq_flags);
  list_del(&new_wait->counter_list);
  spin_unlock_irqrestore(&wq_spinlock, wq_flags);
  kfree(new_wait);
 }
 spin_lock_irqsave(&rb_spinlock, rb_flags);
 current_buf_end = atomic64_read(&ring_buff_count);
 num_copied = 0;
 new_counter = kcounter;
 head_copy = tail;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (head_copy >= PSTRACE_BUF_SIZE)
   head_copy = 0;
  current_count = ring_buf[head_copy].count;
  if (current_count > kcounter + PSTRACE_BUF_SIZE &&
      kcounter != 0)
   break;
  /* case when counter = 0 and buffer is not full */
  if (current_buf_end < PSTRACE_BUF_SIZE &&
      current_count >= current_buf_end)
   break;
  if (current_count < kcounter && kcounter != 0) {
   head_copy += 1;
   continue;
  }
  if (ring_buf[head_copy].valid) {
   new_counter = ring_buf[head_copy].count;
   kbuf[num_copied] = ring_buf[head_copy].mpstrace;
   num_copied += 1;
  }
  head_copy += 1;
 }
 spin_unlock_irqrestore(&rb_spinlock, rb_flags);
 /* can't move earlier because you don't know how large to check */
 if (!access_ok(buf, sizeof(struct pstrace) * num_copied)) {
  kfree(kbuf);
  return -EFAULT;
 }
 if (copy_to_user(counter, &new_counter, sizeof(long))) {
  kfree(kbuf);
  return -EFAULT;
 }
 if (copy_to_user(buf, kbuf, sizeof(struct pstrace) * num_copied)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return num_copied;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 int i;
 unsigned long rb_flags;
 unsigned long wq_flags;
 struct pending_counter *cursor, *temp;
 need_to_wake_all = true;
 spin_lock_irqsave(&wq_spinlock, wq_flags);
 list_for_each_entry_safe(cursor, temp, &pc_head, counter_list) {
  spin_unlock_irqrestore(&wq_spinlock, wq_flags);
  wake_up_all(&cursor->wq);
  spin_lock_irqsave(&wq_spinlock, wq_flags);
 }
 spin_unlock_irqrestore(&wq_spinlock, wq_flags);
 while (!list_empty(&pc_head))
  continue;
 spin_lock_irqsave(&rb_spinlock, rb_flags);
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  ring_buf[i].valid = false;
 spin_unlock_irqrestore(&rb_spinlock, rb_flags);
 return 0;
}