#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
struct pstrace ring_buffer[PSTRACE_BUF_SIZE];
struct pstrace buf_temp[PSTRACE_BUF_SIZE];
int head;
int tail;
long total_counter;
long prev_counter;
long user_counter = INT_MIN;
pid_t current_pid = INT_MIN;
DEFINE_SPINLOCK(lock);
unsigned long flags;
static DECLARE_WAIT_QUEUE_HEAD(wq);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 current_pid = pid;
 prev_counter = total_counter;
 // printk(KERN_INFO "test enable\n");
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 current_pid = INT_MIN;
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf,
 long __user *, counter)
{
 int cp_res;
 int index;
 int length;
 int i, j;
 DEFINE_WAIT(wait);
 if (!buf || !counter)
  return -EINVAL;
 if (copy_from_user(&user_counter, counter, sizeof(counter)))
  return -EFAULT;
 if (user_counter < 0)
  return -EINVAL;
 if (prev_counter == total_counter)
  return user_counter;
 if (user_counter <= 0) {
  spin_lock_irqsave(&lock, flags);
  cp_res = copy_to_user(buf, ring_buffer, sizeof(ring_buffer));
  spin_unlock_irqrestore(&lock, flags);
  if (cp_res)
   return -EFAULT;
  return 0;
 }
 /*
  * check if user counter plus buffer size is
  * already smaller than or equal to total_counter here
  * if so, do not wait, directly copy the buffer
  * else do the wait and use the wait queue
  * get function will be woken up in add function
  * when there are enough pstrace data
  */
 while (user_counter + (long) PSTRACE_BUF_SIZE > total_counter) {
  prepare_to_wait(&wq, &wait, TASK_INTERRUPTIBLE);
  if (signal_pending(current))
   return -EINTR;
  schedule();
 }
 finish_wait(&wq, &wait);
 /* rearrange the buffer in chronological order */
 spin_lock_irqsave(&lock, flags);
 index = user_counter % (long) PSTRACE_BUF_SIZE;
 length = PSTRACE_BUF_SIZE - index;
 // printk("index: %d\n", index);
 // printk("length: %d\n", length);
 j = 0;
 for (i = index; i < PSTRACE_BUF_SIZE; i++) {
  buf_temp[j] = ring_buffer[i];
  j++;
 }
 i = 0;
 for (; j < PSTRACE_BUF_SIZE; j++) {
  buf_temp[j] = ring_buffer[i];
  i++;
 }
 cp_res = copy_to_user(buf, buf_temp, sizeof(buf_temp));
 spin_unlock_irqrestore(&lock, flags);
 if (cp_res)
  return -EFAULT;
 return 0;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 /* wake up all sleeping get function call */
 wake_up_all(&wq);
 head = 0;
 tail = 0;
 return 0;
}
void pstrace_add(struct task_struct *p, long state)
{
 if (current_pid == INT_MIN)
  return;
 if (current_pid != -1 && current_pid != p->tgid)
  return;
 if (state == TASK_UNINTERRUPTIBLE + TASK_NOLOAD)
  state = TASK_UNINTERRUPTIBLE;
 struct pstrace pstraceItem = (struct pstrace) {
  .state = state,
  .pid = p->tgid,
  .tid = p->pid,
 };
 strcpy(pstraceItem.comm, p->comm);
 spin_lock_irqsave(&lock, flags);
 ring_buffer[head] = pstraceItem;
 total_counter++;
 // printk("total counter: %ld\n", total_counter);
 if (total_counter < PSTRACE_BUF_SIZE) {
  head = (head+1) % PSTRACE_BUF_SIZE;
 } else {
  head = (head+1) % PSTRACE_BUF_SIZE;
  tail = (tail+1) % PSTRACE_BUF_SIZE;
 }
 spin_unlock_irqrestore(&lock, flags);
}
void pstrace_wake_up(void) 
{
 /* wake up all pending get from wake queue */
 if (user_counter != INT_MIN &&
  user_counter + (long) PSTRACE_BUF_SIZE
  <= total_counter)
  wake_up_all(&wq);
 return;
}