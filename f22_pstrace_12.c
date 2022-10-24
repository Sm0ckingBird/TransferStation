// SPDX-License-Identifier: GPL-2.0
#include "sched/sched.h"
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
#include <linux/pstrace.h>
#define TRUE 1
#define FALSE 0
static long buf_counter;
static long num_process_states; // This is a surprise tool that will help us later for pstrace_clear
static long num_entries_to_clear;
static long num_waiting_entries;
static struct pstrace ringbuf[PSTRACE_BUF_SIZE];
static int tracked_process;
static int pstrace_enabled;
//static DEFINE_SPINLOCK(pstrace_lock);
static DECLARE_WAIT_QUEUE_HEAD(pstrace_wait);
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
 struct task_struct *root;
 pstrace_enabled = TRUE;
 rcu_read_lock();
 //get_root throwing error on -1
 if (pid == -1) {
  tracked_process = pid;
  buf_counter = 0;
  rcu_read_unlock();
  return 0;
 }
 root = get_root(pid);
 if (root == NULL) {
  rcu_read_unlock();
  return -ESRCH;
 }
 tracked_process = pid;
 // Reset the counter, effectively clearing the buffer
 buf_counter = 0;
 rcu_read_unlock();
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 // We want to disable if the program was signal interrupted
 pstrace_enabled = FALSE;
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 int add_index;
 struct pstrace new_addition;
 unsigned long flags; // save state of interrupts to restore later
 if (!pstrace_enabled)
  return;
 if (state == PSTRACE_WAKEUP_FLAG && buf_counter > 499) {
  wake_up_interruptible(&pstrace_wait);
  return;
 }
 if (!p || (tracked_process != -1 && p->pid != tracked_process))
  return;
 // Do some state filtering
 if (state == TASK_STOPPED)
  state = __TASK_STOPPED;
 if (state == TASK_KILLABLE || state == TASK_IDLE)
  return;
 // Note: tgid is thread group id and is the actual pid
 // pid is process id and is the thread id
 new_addition.tid = p->pid;
 new_addition.pid = p->tgid;
 new_addition.state = state;
 memcpy(new_addition.comm, p->comm, sizeof(p->comm));
 spin_lock_irqsave(&pstrace_wait.lock, flags);
 // rq is the task run queue for CPUs
 add_index = buf_counter % PSTRACE_BUF_SIZE;
 ringbuf[add_index] = new_addition;
 buf_counter++;
 num_process_states++;
 spin_unlock_irqrestore(&pstrace_wait.lock, flags);
 // Wake up causes a deadlock
 // We call pstrace_add in __schedule which holds onto the rq->lock => pstrace_wait->lock
 // but wake_up obtains the locks pstrace_wait->lock => p->pi_lock => rq->lock
 // If we can't change wake_up, then how do we resolve this deadlock?
 if (state == TASK_RUNNING || state == TASK_RUNNABLE || buf_counter < 490)
  return;
 wake_up_interruptible(&pstrace_wait);
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
 long kcounter;
 size_t size;
 long next;
 int i;
 int amount_to_copy;
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 if (kcounter < 0)
  return -EINVAL;
 // TOOD: Make sure buffer is large enough
 // Do we need to allocate kbuf or can we copy directly from the ringbuf?
 // TODO: lock the ring buffer and counter when copying out
 // TODO: Add support for waking up early from interrupt or pstrace_clear
 //if (wait_event_interruptible(pstrace_wait, buf_counter + PSTRACE_BUF_SIZE >= kcounter)) {
 // Using a dummy wait_event for testing
 // TODO: Modify CV to obtain locks atomically when waking up
 //spin_lock_irqsave(&pstrace_lock, flags);
 // Use a custom wakeup function to 1. obtain locks, 2. easily check cond before waking up
 // wait queue again
 //if (num_entries_to_clear > 0) {
 //        // wait
 //}
 // remember to decrement num_entries_to_clear if it's greater than 0
 spin_lock(&pstrace_wait.lock);
 if (kcounter + 999 >= buf_counter) {
  if (wait_event_interruptible_locked(pstrace_wait, buf_counter >= kcounter + 500 && num_process_states >= 500) < 0)
   return -EINTR;
  amount_to_copy = kcounter - buf_counter + 1000;
  if (amount_to_copy > 500)
   amount_to_copy = buf_counter - kcounter;
  next = buf_counter;
  // TODO: Copy from the correct index to be sequential in the ring buffer
  size = amount_to_copy * sizeof(struct pstrace);
  for (i = buf_counter - amount_to_copy; i < buf_counter; i++) {
   int offset = i - (buf_counter - amount_to_copy);
   if (copy_to_user(buf + offset, &(ringbuf[i % 500]), sizeof(struct pstrace)))
    return -EFAULT;
  }
 }
 spin_unlock(&pstrace_wait.lock);
 if (put_user(next, counter))
  return -EFAULT;
 return 0;
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
 num_entries_to_clear = num_waiting_entries;
 // stop new entries from entering
 //while (num_entries_to_clear > 0) {
 //        wake_up_all_interruptible(&pstrace_wait);
 //        //num_entries_to_clear--;
 //}
 // wake up all
 // new lock, new CV
 // Wake up all pstrace_get entries
 // Don't allow other callers to wait
 // Clear buffer entries
 // We don't need to actually clear the data, we just update our counter variables
 num_process_states = 0;
 return 0;
}