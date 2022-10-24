// SPDX-License-Identifier: GPL-2.0
#include <linux/errno.h>  /* Error codes */
#include <linux/kernel.h>
#include <linux/signal.h>  /* kill() */
#include <linux/spinlock.h>  /* spinlock stuff */
#include <linux/string.h>
#include <linux/syscalls.h>  /* strlen() */
#include <linux/types.h>  /* kill() */
#include "../include/linux/pstrace.h"
/*
 * TODO: Delete all unnecessary prink statements
 * TODO: Remove all comments that start with //
 * TODO: Run checkpatch on this file
 * TODO CHECK that trace lock is applied to every use of
 * trace_pid and make sure grb_counter_when_cleared has proper locking
 */
/* Global Ring Buffer Variables */
static struct pstrace grb[PSTRACE_BUF_SIZE]; /* Global array to store traced entries */
/* Global counter of items that HAVE BEEN copied into buffer since boot!*/
static long grb_counter;
static int grb_counter_when_cleared;
static DEFINE_SPINLOCK(grb_and_counter_lock);
/* Set by pstrace clear to alter the wake up behavior of pstrace get */
//static atomic_t clearing_buffer = ATOMIC_INIT(0);
/*
 * Global variable to show what pid is currently being traced.
 * -1 means trace all processes.
 * -2 means tracing disabled. (DEFAULT)
 */
static pid_t trace_pid = -2;
static DEFINE_SPINLOCK(tracing_lock);
/* Stuff for use with pstrace_get */
//static DECLARE_WAIT_QUEUE_HEAD(pstrace_get_wait_queue);
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
 struct task_struct *target_process;
 /* Check if process with @pid exists */
 target_process = get_root(pid);
 if (target_process == NULL)
  return -ESRCH;
 /* By setting trace_pid != -2, we enable tracing */
 spin_lock(&tracing_lock);
 trace_pid = pid;
 spin_unlock(&tracing_lock);
 pr_info("pstrace_enable: trace_pid = %d\n", trace_pid);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 /* By setting trace_pid = -2, we disable tracing */
 spin_lock(&tracing_lock);
 trace_pid = -2;
 spin_unlock(&tracing_lock);
 pr_info("pstrace_disable: trace_pid = %d\n", trace_pid);
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 int i;  /* Loop indexer */
 int len; /* task_struct->comm length */
 int next_writable_index;
 pid_t my_pid;
 pid_t my_tgid;
 char my_name[16];
 //ADD RCU READ LOCK TO GRAB DATA OFF THE TASK STRUCT
 /* Check if tracing disabled */
 spin_lock(&tracing_lock);
 if (trace_pid == -2) {
  spin_unlock(&tracing_lock);
  //pr_info("pstrace_add: tracing disabled!\n");
  return;
 }
 //crit section
 rcu_read_lock();
 my_pid = p->pid;
 my_tgid = p->tgid;
 i = 0;
 len = strlen(p->comm);
 while (i < 16 && i < len) {
  my_name[i] = p->comm[i];
  ++i;
 }
 my_name[i] = '\0';
 rcu_read_unlock();
 //end crit section
 /* Check if we're tracing this process */
 if (trace_pid == -1 || trace_pid == my_tgid) {
  pr_info("pstrace_ad: trace_pid = %d, state = %ld\n", trace_pid, state);
  //Crit Section start
  spin_lock(&grb_and_counter_lock);
  next_writable_index = (grb_counter)%PSTRACE_BUF_SIZE;
  strcpy(grb[next_writable_index].comm, my_name);
  grb[next_writable_index].state = state;
  grb[next_writable_index].pid = my_tgid;
  grb[next_writable_index].tid = my_pid;
  ++grb_counter;
  spin_unlock(&grb_and_counter_lock);
  //Crit section end
  /* We must call this every time grb_counter is incremented */
  //wake_up_all(&pstrace_get_wait_queue);
 }
 spin_unlock(&tracing_lock); //is it ok to hold this spin lock over the wake_up call?
}
/*
 * WARNING: Locks the GRB. Designed to be passed to wait function as a condition
 */
int safely_check_grb_counter_against(long user_counter)
{
 spin_lock(&grb_and_counter_lock);
 if ((grb_counter - user_counter) >= PSTRACE_BUF_SIZE) {
  spin_unlock(&grb_and_counter_lock);
  return 1;
 } else {
  spin_unlock(&grb_and_counter_lock);
  return 0;
 }
}
/*
 * WARNING: Must be called with grb variables lock held
 */
int grb_counter_to_index(long my_counter)
{
 if (my_counter <= grb_counter_when_cleared)
  return -1;
 if (my_counter <= (grb_counter - PSTRACE_BUF_SIZE))
  return -1;
 if (my_counter > grb_counter)
  return -1;
 if (my_counter < 1)
  return -1;
 return (my_counter - 1) % PSTRACE_BUF_SIZE;
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
 long kern_counter; /* Used in every case */
 int grb_ind;   /* Used in more than one case */
 int copied_items; /* Used in more than one case */
 int count_to_bufsz; /* Used in more than one case */
 /* Grab counter from user space */
 if (get_user(kern_counter, counter))
  return -EFAULT;
 pr_info("pstrace_get: trace_pid = %d\n", trace_pid);
 pr_info("pstrace_get: kern_counter = %ld\n", kern_counter);
 //start_of_pstrace_get_logic_before_any_locks_are_grabbed:
 spin_lock(&grb_and_counter_lock);
 if (kern_counter < 0) {
  if (put_user(grb_counter, counter)) {
   spin_unlock(&grb_and_counter_lock);
   return -EFAULT;
  }
  spin_unlock(&grb_and_counter_lock);
  return -EINVAL;
 } else if (kern_counter == 0) { /*Dump entire buffer*/
  pr_info("pstrace_get: Case 2\n");
  count_to_bufsz = 0;
  copied_items = 0;
  while (count_to_bufsz < PSTRACE_BUF_SIZE) {
   grb_ind = grb_counter_to_index(grb_counter - PSTRACE_BUF_SIZE
     + 1 + count_to_bufsz);
   if (grb_ind >= 0) {
    if (copy_to_user(buf+copied_items,
       grb+grb_ind, sizeof(struct pstrace))) {
     spin_unlock(&grb_and_counter_lock);
     return -EFAULT;
    }
    ++copied_items;
   }
   ++count_to_bufsz;
  }
  if (put_user(grb_counter, counter)) {
   spin_unlock(&grb_and_counter_lock);
   return -EFAULT;
  }
  spin_unlock(&grb_and_counter_lock);
  return copied_items;
 } else if (kern_counter + PSTRACE_BUF_SIZE <= grb_counter) {
  pr_info("pstrace_get: Case 3\n");
  if (kern_counter + 2*PSTRACE_BUF_SIZE <= grb_counter) {
   if (put_user(grb_counter, counter)) {
    spin_unlock(&grb_and_counter_lock);
    return -EFAULT;
   }
   spin_unlock(&grb_and_counter_lock);
   return 0;
  }
  count_to_bufsz = 0;
  copied_items = 0;
  while (count_to_bufsz < PSTRACE_BUF_SIZE) {
   grb_ind = grb_counter_to_index(kern_counter + 1 + count_to_bufsz);
   if (grb_ind >= 0) {
    if (copy_to_user(buf+copied_items,
       grb+grb_ind, sizeof(struct pstrace))) {
     spin_unlock(&grb_and_counter_lock);
     return -EFAULT;
    }
    ++copied_items;
   }
   ++count_to_bufsz;
  }
  if (put_user(grb_counter, counter)) {
   spin_unlock(&grb_and_counter_lock);
   return -EFAULT;
  }
  spin_unlock(&grb_and_counter_lock);
  return copied_items;
 }
 else {
  spin_unlock(&grb_and_counter_lock);
  return -1;
/*
 *  spin_unlock(&grb_and_counter_lock);
 *  wait_event_interruptible(pstrace_get_wait_queue,
 *  safely_check_grb_counter_against(kern_counter));
 *  //&& !atomic_read(&clearing_buffer)
 *  goto start_of_pstrace_get_logic_before_any_locks_are_grabbed;
 */
 }
 spin_unlock(&grb_and_counter_lock);
 /*
  * Case 4: counter > 0 and counter+PSTRACE_BUF_SIZE > grb_counter
  * Handle: Handle this after other conditions are working
  */
 /* Sleep until wakeup_flag is set by pstrace_add*/
 //wait_event_interruptible(wq, condition);
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
 //TODO Add wakeup all func so peeps can get their records before we delete
 int i; /* Loop indexer */
 int grb_index;
 /* Acquire lock to modify ringbuffer */
 spin_lock(&grb_and_counter_lock);
 //atomic_set(&clearing_buffer, 1);
 //wake_up_all(&pstrace_get_wait_queue);
 grb_counter_when_cleared = grb_counter;
 pr_info("pstrace_clear: trace_pid = %d\n", trace_pid);
 /* Zero out the buffer */
 for (grb_index = 0; grb_index < PSTRACE_BUF_SIZE; ++grb_index) {
  for (i = 0; i < 16; ++i)
   grb[grb_index].comm[i] = '\0';
  grb[grb_index].state = 0;
  grb[grb_index].pid = 0;
  grb[grb_index].tid = 0;
 }
 /* Unlock */
 spin_unlock(&grb_and_counter_lock);
 return 0;
}