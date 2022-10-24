#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#define PSTRACE_BUF_SIZE 500
DEFINE_SPINLOCK(pstrace_spinlock);
static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
bool clear;
// struct pstrace_event {
// long counter;
// struct pstrace buf[]
// }
struct pstrace ring_buf[PSTRACE_BUF_SIZE];
long ring_buf_counter;// number of pstrace that had been added, range: [0, inf]
long curr_count;// number of pstrace currently in ring_buf, range:[0, PSTRACE_BUF_SIZE]
pid_t traced = -2;// to check what processes are currently tracked
static inline void put_info(struct pstrace *cur_thread_info,
 struct task_struct *process, long state)
{
 get_task_comm(cur_thread_info->comm, process);
 cur_thread_info->pid = process->tgid;
 cur_thread_info->state = state;
 cur_thread_info->tid = process->pid;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 if (!p)  // task struct might be null
  return;
 // wake_up_all(&wait_queue);
 if (p->tgid == traced || traced == -1) {
  spin_lock(&pstrace_spinlock);
  // printk(KERN_INFO "add new pstrace\n");
  put_info(ring_buf + (ring_buf_counter % PSTRACE_BUF_SIZE), p, state);
  ring_buf_counter++;
  if (curr_count < PSTRACE_BUF_SIZE)
   curr_count++;
  // printk(KERN_INFO "rbCounter = %ld, currCounter = %ld\n",
  // ring_buf_counter, curr_count);
  spin_unlock(&pstrace_spinlock);
 }
 // return;
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 traced = pid;
 // printk(KERN_INFO "now tracing: %d\n", traced);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 traced = -2;
 // printk(KERN_INFO "disabled tracing\n");
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace *, buf, long *, counter)
{
 long tmp;
 long tmp2;
 long copyCount = 0;
 long userCounter;
 int i;
 if (__copy_from_user(&userCounter, counter, sizeof(long)) != 0)
  return -EFAULT;
 if (userCounter < 0)
  return -EINVAL;
 // printk(KERN_INFO "user counter = %ld\n", userCounter);
 spin_lock(&pstrace_spinlock);
/*
 if (userCounter > 0) {
  if (curr_count < PSTRACE_BUF_SIZE ||
  ring_buf_counter < userCounter + PSTRACE_BUF_SIZE) {
   spin_unlock(&pstrace_spinlock);
   wait_event_interruptible(wait_queue,
   clear == true || (curr_count == PSTRACE_BUF_SIZE &&
   ring_buf_counter >= userCounter + PSTRACE_BUF_SIZE));
   spin_lock(&pstrace_spinlock);
  }
 }
*/
 for (i = 1; i <= curr_count; i++) {
  long curr = ring_buf_counter - curr_count + i;
  // printk(KERN_INFO "copying record %ld to user space:
  // %s, %ld, %d, %d copyCount=%ld\n",
  // curr, ring_buf[i].comm, ring_buf[i].state, ring_buf[i].pid,
  // ring_buf[i].tid, copyCount);
  tmp = __copy_to_user(buf + i - 1,
   ring_buf + (curr % PSTRACE_BUF_SIZE),
   sizeof(struct pstrace));
  tmp2 = __copy_to_user(counter, &curr, sizeof(long));
  if (tmp != 0 || tmp2 != 0) {
   // printk(KERN_INFO "copying to user failed\n");
   spin_unlock(&pstrace_spinlock);
   return -EFAULT;
  }
  copyCount++;
 }
 if (userCounter == 0) {
  if (__copy_to_user(counter, &ring_buf_counter, sizeof(long)) != 0) {
   // printk(KERN_INFO "copying to user failed\n");
   spin_unlock(&pstrace_spinlock);
   return -EFAULT;
  }
 }
 spin_unlock(&pstrace_spinlock);
 return copyCount;
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get. Clear does not
 * reset the value of the buffer counter.
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 spin_lock(&pstrace_spinlock);
 clear = true;
 // wake_up_all(&wait_queue);
 curr_count = 0;  // not actually deleting records
 clear = false;
 spin_unlock(&pstrace_spinlock);
 return 0;
}