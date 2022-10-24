#include <linux/pstrace.h>
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
#include <linux/signal.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500
DEFINE_SPINLOCK(mrs_lock);
DECLARE_WAIT_QUEUE_HEAD(wqhead);
/*Add locks later */
struct ring_buffer {
 int head;
 long last_count;
 unsigned long counter;
 struct pstrace buffer[PSTRACE_BUF_SIZE];
};
struct ring_buffer globalRingBuffer = {.head = 0, .last_count = 0, .counter = 0};
atomic_t trackedprocess = ATOMIC_INIT(-2);
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long flags;
 struct pstrace toBeAdded;
 if (trackedprocess.counter == -1 || trackedprocess.counter == (int) task_pid_nr(p)) {
  /* only log if tracing for this pid has been enabled */
  spin_lock_irqsave(&mrs_lock, flags);
  toBeAdded = (struct pstrace)
   {.state = state, .pid = p->tgid, .tid = task_pid_nr(p)};
  /* tid might be thread group leader or something */
  strncpy(toBeAdded.comm, p->comm, 16);
  globalRingBuffer.buffer[globalRingBuffer.counter % PSTRACE_BUF_SIZE] = toBeAdded;
  globalRingBuffer.counter++;
 spin_unlock_irqrestore(&mrs_lock, flags);
 wake_up_interruptible(&wqhead);
 }
};
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 *
 * Interface: long pstrace_enable(pid_t pid);
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t __user, pid) {
 unsigned long flags;
 if (find_task_by_vpid(pid) == NULL && pid != -1)
  return -ESRCH;
 atomic_set(&trackedprocess, pid);
 spin_lock_irqsave(&mrs_lock, flags);
 globalRingBuffer.last_count = globalRingBuffer.counter;
 spin_unlock_irqrestore(&mrs_lock, flags);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 *
 * Interface: long pstrace_disable();
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 atomic_set(&trackedprocess, -2);
 /* no pid will be -2 so nothing will be tracked by pstrace_add */
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
 *
 * Interface: long pstrace_get(struct pstrace *buf, long *counter);
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user*, counter)
{
 long counter_copy;
 unsigned long flags;
 struct pstrace *intermediateBuffer;
 struct pstrace temp_pstrace;
 int ret_val;
 int i, j;
 long lower, upper;
 int cpyval, starting_index;
 ret_val = 0;
 intermediateBuffer = kmalloc_array(PSTRACE_BUF_SIZE,  sizeof(struct pstrace), GFP_KERNEL);
 if (copy_from_user(&counter_copy, counter, sizeof(long)))
  return -EFAULT;
 if (counter_copy < 0)
  return -EINVAL;
 j = 0; //increment for the buffer we're going to copy over.
 if (!counter_copy) { //counter copy equal to 0
  cpyval = copy_to_user(counter, &globalRingBuffer.counter, sizeof(long));
  if (cpyval != 0)
   return -EFAULT;
  spin_lock_irqsave(&mrs_lock, flags);
  if (globalRingBuffer.counter - counter_copy > 500) {
   starting_index = globalRingBuffer.counter % PSTRACE_BUF_SIZE;
   for (i = 0; i < 500; i++) {
    temp_pstrace =
     globalRingBuffer.buffer[(starting_index + i)
     % PSTRACE_BUF_SIZE];
    if (temp_pstrace.pid != -2)
     intermediateBuffer[j++] = temp_pstrace;
   }
   cpyval = copy_to_user(buf, intermediateBuffer, j * sizeof(struct pstrace));
   if (cpyval != 0)
    return -EFAULT;
   ret_val = j;
  } else {
   for (i = 0; i < globalRingBuffer.counter; i++) {
    temp_pstrace = globalRingBuffer.buffer[i];
    if (temp_pstrace.pid != -2)
     intermediateBuffer[j++] = temp_pstrace;
   }
   cpyval = copy_to_user(buf, intermediateBuffer, j * sizeof(struct pstrace));
   if (cpyval != 0)
    return -EFAULT;
   ret_val = j;
  }
  spin_unlock_irqrestore(&mrs_lock, flags);
 } else if (counter_copy + PSTRACE_BUF_SIZE <= globalRingBuffer.counter) {
  cpyval = copy_to_user(counter, &globalRingBuffer.counter, sizeof(long));
  spin_lock_irqsave(&mrs_lock, flags);
  lower = counter_copy + PSTRACE_BUF_SIZE;
  upper = globalRingBuffer.counter - PSTRACE_BUF_SIZE;
  if (lower <= upper) {
   kfree(intermediateBuffer);
   spin_unlock_irqrestore(&mrs_lock, flags);
   return 0;
  }
  i = (upper + 1) % 500;
  for (; i < PSTRACE_BUF_SIZE; i++) {
   temp_pstrace = globalRingBuffer.buffer[i];
   if (temp_pstrace.pid != -2)
    intermediateBuffer[j++] = temp_pstrace;
  }
  for (i = 0; i <= lower % 500; i++) {
   temp_pstrace = globalRingBuffer.buffer[i];
   if (temp_pstrace.pid != -2)
    intermediateBuffer[j++] = temp_pstrace;
  }
  cpyval = copy_to_user(buf, intermediateBuffer, j * sizeof(struct pstrace));
  if (cpyval != 0)
   return -EFAULT;
  ret_val = j;
  spin_unlock_irqrestore(&mrs_lock, flags);
 } else {
  wait_event_interruptible(wqhead,
    globalRingBuffer.counter >= counter_copy + PSTRACE_BUF_SIZE);
  spin_lock_irqsave(&mrs_lock, flags);
  if (globalRingBuffer.counter < counter_copy + PSTRACE_BUF_SIZE) {
   /* when interruptible sleep woken by a pstrace_clear call
    * as if we called pstrace_get(0)
    */
  } else {
   upper = counter_copy + PSTRACE_BUF_SIZE;
   lower = counter_copy;
   cpyval = copy_to_user(counter, &upper, sizeof(long));
   if (cpyval)
    return -EFAULT;
   for (i = 0; i < 500; i++) {
    temp_pstrace =
     globalRingBuffer.buffer[lower + i % PSTRACE_BUF_SIZE];
    intermediateBuffer[i] = temp_pstrace;
   }
   cpyval = copy_to_user(buf, intermediateBuffer,
     PSTRACE_BUF_SIZE * sizeof(struct pstrace));
   if (cpyval) {
    /* need to change this to returning an error rather than a printk */
    return -EFAULT;
   }
  spin_unlock_irqrestore(&mrs_lock, flags);
  }
 }
 kfree(intermediateBuffer);
 return ret_val;
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 *
 * Interface: long pstrace_clear();
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 int i, floor_max;
 unsigned long flags;
 spin_lock_irqsave(&mrs_lock, flags);
 /* if counter is less than 500 means we havent filled buffer
  * use the global counter to iterate properly otherwise clear all
  */
 floor_max = (globalRingBuffer.counter < 500)
  ? globalRingBuffer.counter : 500;
 for (i = 0; i < floor_max; i++)
  globalRingBuffer.buffer[i].pid = -2;
 spin_unlock_irqrestore(&mrs_lock, flags);
 return 0;
}