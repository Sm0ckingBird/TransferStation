// SPDX-License-Identifier: MIT
#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/kern_levels.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/sched/task.h>
#include <linux/list.h>
#include <linux/minheap_custom.h>
/* redefine global vars made extern in pstrace.h */
int pid_to_trace = TRACE_DISABLED;
struct pstrace pstrace_rbuf[PSTRACE_BUF_SIZE];
int rbuf_head;
int rbuf_tail;
int rbuf_count; /* num of records accessible in rbuf right now */
int counter_to_check;
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
DEFINE_SPINLOCK(rbuf_lock); /* Lock should be global */
DECLARE_WAIT_QUEUE_HEAD(wq);
long total_trace_count; /* total num records ever recorded */
/* HW3 PART 1 */
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *p;
 if (pid == -1) {
  pid_to_trace = -1;
  return 0;
 }
 p = find_task_by_vpid(pid);
 if (!p) {
  pr_info("PSTRACE: ESRCH, pid %d not found.\n", pid);
  return -ESRCH;
 }
 pid_to_trace = task_tgid_nr(p);
 pr_info("PSTRACE: set pid_to_trace to: %d\n", pid_to_trace);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 pid_to_trace = TRACE_DISABLED;
 pr_info("PSTRACE: reset pid_to_trace to: %d\n", pid_to_trace);
 return 0;
}
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace *rbuf_p;
 unsigned long flags;
 struct wait_queue_entry *wq_entry;
 struct heap_entry *cur_heap_entry;
 pr_info("PSTRACE: begin __pstrace_add__, locking...\n");
 spin_lock_irqsave(&rbuf_lock, flags);
 /* locate the head for data write */
 rbuf_p = pstrace_rbuf + rbuf_head;
 pr_info("PSTRACE: using (head, tail) of (%d, %d)\n", rbuf_head,
  rbuf_tail);
 /* check if we will be overwriting the tail */
 if (rbuf_count == PSTRACE_BUF_SIZE) {
  rbuf_tail++;
  rbuf_count--;
 }
 /* write data to head */
 rbuf_p->pid = task_tgid_nr(p);
 rbuf_p->tid = task_pid_nr(p);
 rbuf_p->state = state;
 get_task_comm(rbuf_p->comm, p);
 pr_info("PSTRACE: wrote data to rbuf (head: %d): pid: %d, tid: %d, state: %ld, comm: %s\n",
  rbuf_head, rbuf_p->pid, rbuf_p->tid, rbuf_p->state,
  rbuf_p->comm);
 /* update rbuf_count, head, tail */
 rbuf_count++;
 total_trace_count++;
 pr_info("PSTRACE: updated rbuf_count and total_trace_count to:"
   "%d, %ld\n", rbuf_count, total_trace_count);
 if (++rbuf_head == PSTRACE_BUF_SIZE) {
  pr_info("PSTRACE: reset rbuf_head to 0 from: %d\n", rbuf_head);
  rbuf_head = 0;
 }
 if (rbuf_tail == PSTRACE_BUF_SIZE) {
  pr_info("PSTRACE: reset rbuf_tail to 0 from: %d\n", rbuf_tail);
  rbuf_tail = 0;
 }
 pr_info("PSTRACE: __pstrace_add__ complete, unlocking...\n");
 spin_unlock_irqrestore(&rbuf_lock, flags);
 if (heap_count > 0) {
  pr_info("Checking lowest count %ld, total: %ld\n",
   heap[0]->counter, total_trace_count);
  if (heap[0]->counter == total_trace_count) {
   cur_heap_entry = heap_pop_min();
   pr_info("lowest heap_entry->counter: %ld, total_trace_count: %ld",
    cur_heap_entry->counter, total_trace_count);
   wq_entry = cur_heap_entry->wq_entry;
   /* the 'func' is the custom_remove_function,
    * which will take it off the waitqueue
    * it's basically the same as the
    * autoremove_wake_function
    */
   wq_entry->func(wq_entry, TASK_NORMAL, 0, NULL);
   kfree(cur_heap_entry);
  }
 }
}
void check_pstrace_add(struct task_struct *p, long state, char *message)
{
 if (pid_to_trace == -1 || pid_to_trace == task_tgid_nr(p)) {
  pr_info("%s (tgid: %d)\n", message, task_tgid_nr(p));
  pstrace_add(p, state);
 }
}
/* HW3 PART 2 */
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
int calculate_nums_to_copy(long *counter, int *num_to_copy, int *num_to_copy2,
      int *set_counter_to_global_counter,
      int woken_up_by_clear)
{
 int end;
 int start;
 pr_info("Calc nums to copy, counter: %ld, global counter: %ld\n",
  *counter, total_trace_count);
 if (*counter == 0) {
  // if tail > head, copy to end of buf, else
  // copy from head til tail
  *num_to_copy = (rbuf_tail >= rbuf_head) ?
          (PSTRACE_BUF_SIZE - rbuf_tail) :
          (rbuf_head - rbuf_tail);
  // if tail <= head, copy from beginning of buf to the tail
  *num_to_copy2 = (rbuf_tail <= rbuf_head) ? rbuf_tail : 0;
 }
 // no valid entries in buffer (they're all too old), don't copy anything
 else if (total_trace_count - *counter >= 2 * PSTRACE_BUF_SIZE) {
  // *counter = 0;
  *num_to_copy = 0;
  *num_to_copy2 = 0;
 }
 // Some entries are valid, so copy only some, see case 3 of ed post
 else if (*counter + PSTRACE_BUF_SIZE <= total_trace_count) {
  end = (*counter + PSTRACE_BUF_SIZE -
         (total_trace_count - PSTRACE_BUF_SIZE) + rbuf_tail) %
        PSTRACE_BUF_SIZE;
  *num_to_copy = (rbuf_tail > end) ?
          PSTRACE_BUF_SIZE - rbuf_tail :
          end - rbuf_tail;
  *num_to_copy2 = (rbuf_tail > end) ? end : 0;
  *set_counter_to_global_counter = 0;
 }
 // when pstrace_get is woken up by a clear, just fill buffer
 // with all numbers within indices [counter, total_trace_count]
 else if (*counter <= total_trace_count && woken_up_by_clear) {
  end = ((*counter + rbuf_tail) +
         (total_trace_count - *counter)) %
        PSTRACE_BUF_SIZE;
  start = (*counter + rbuf_tail) % PSTRACE_BUF_SIZE;
  *num_to_copy =
   (start > end) ? PSTRACE_BUF_SIZE - start : end - start;
  *num_to_copy2 = (start > end) ? end : 0;
 } else {
  return -1;
 }
 pr_info("num_to_copy: %d, num_to_copy2: %d\n", *num_to_copy,
  *num_to_copy2);
 return 1;
}
int copy_rbuf_to_user(struct pstrace *buf, long *counter)
{
 // int start = rbuf_tail;
 int num_to_copy = 0; // num to copy from tail to end of buf
 int num_to_copy2 = 0; // num to copy from start of buf to end
 int set_counter_to_global_counter = 1;
 int signal_was_sent = 0;
 int woken_up_by_clear = 0;
 int ret;
 /* Define the wq_entry with a custom wake function
  * that I wrote in kernel/sched/wait.c#L412
  */
 DEFINE_WAIT_FUNC(wq_entry, custom_wake_function);
 unsigned long flags;
 pr_info("Inputted Counter: %ld, total_trace_count: %ld\n", *counter,
  total_trace_count);
 // return all entries in chronological orders
 // ret < 0 means we must block
 ret = calculate_nums_to_copy(counter, &num_to_copy, &num_to_copy2,
         &set_counter_to_global_counter,
         woken_up_by_clear);
 if (ret < 0) {
  // Asyncronous getting
  pr_info("Blocking pstrace_get until condition is true...\n");
  counter_to_check = *counter + PSTRACE_BUF_SIZE;
  do {
   pr_info("Preparing to wait, counter: %ld, total_trace_count: %ld\n",
    *counter, total_trace_count);
   prepare_to_wait_custom(&wq, &wq_entry,
            TASK_INTERRUPTIBLE,
            *counter + PSTRACE_BUF_SIZE);
   // prepare_to_wait(&wq, &wq_entry, TASK_INTERRUPTIBLE);
   if (signal_pending_state(current->state, current)) {
    signal_was_sent = 1;
    break;
   }
   spin_unlock_irqrestore(&rbuf_lock, flags);
   schedule();
   pr_info("After schedule, wq_entry.flags: %d\n",
    wq_entry.flags);
   // If pstrace_clear is called,
   // WQ_FLAG_PSTRACE_CLEAR
   // on each pstrace_get task will be set
   if ((wq_entry.flags & WQ_FLAG_PSTRACE_CLEAR) ==
       WQ_FLAG_PSTRACE_CLEAR) {
    woken_up_by_clear = 1;
    break;
   }
   spin_lock_irqsave(&rbuf_lock, flags);
  } while (*counter + PSTRACE_BUF_SIZE > total_trace_count);
  pr_info("Finished waiting!! counter: %ld, total_trace_count: %ld\n",
   *counter, total_trace_count);
  finish_wait_custom(&wq, &wq_entry);
  // finish_wait(&wq, &wq_entry);
  if (signal_was_sent) {
   num_to_copy = 0;
   num_to_copy2 = 0;
  } else {
   // process has woken up due to the condition being true.
   // Calculate what it should copy
   calculate_nums_to_copy(counter, &num_to_copy,
            &num_to_copy2,
            &set_counter_to_global_counter,
            woken_up_by_clear);
  }
 }
 num_to_copy = MIN(num_to_copy, rbuf_count);
 // This should be uncessary, because if rbuf_count < 500,
 // num_to_copy2 will be 0
 num_to_copy2 = MIN(num_to_copy2, rbuf_count);
 // DEBUG
 if (!(num_to_copy + num_to_copy2 <= PSTRACE_BUF_SIZE))
  pr_info("total num to copy more tham 500!\n");
 if (!(rbuf_tail + num_to_copy <= PSTRACE_BUF_SIZE))
  pr_info("tail + num to copy exceeds 500!\n");
 pr_info("PSTRACE: Copying %d, (head, tail) is (%d, %d)", num_to_copy,
  rbuf_head, rbuf_tail);
 pr_info("PSTRACE: Copying %d, (head, tail) is (%d, %d)", num_to_copy2,
  rbuf_head, rbuf_tail);
 if (copy_to_user(buf, pstrace_rbuf + rbuf_tail,
    num_to_copy * sizeof(struct pstrace)) ||
     copy_to_user(buf + num_to_copy, pstrace_rbuf,
    num_to_copy2 * sizeof(struct pstrace)))
  return -EFAULT;
 if (set_counter_to_global_counter)
  *counter = total_trace_count;
 else
  *counter =
   *counter +
   PSTRACE_BUF_SIZE; // case where global counter = 1000
   //  and pstrace_get(100)
 if (signal_was_sent)
  return -EINTR;
 return num_to_copy + num_to_copy2;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter_ptr)
{
 unsigned long flags;
 int return_val = -EINVAL;
 long counter;
 if (get_user(counter, counter_ptr))
  return -EFAULT;
 pr_info("PSTRACE: Calling pstrace_get\n");
 spin_lock_irqsave(&rbuf_lock, flags);
 return_val = copy_rbuf_to_user(buf, &counter);
 pr_info("Returned from copy_rbuf_to_user %d\n", return_val);
 if (put_user(counter, counter_ptr))
  return_val = -EFAULT;
 spin_unlock_irqrestore(&rbuf_lock, flags);
 return return_val;
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 */
SYSCALL_DEFINE1(pstrace_clear, int, pid)
{
 unsigned long flags;
 pr_info("PSTRACE: Calling pstrace_clear\n");
 /* Wake up before the rbuf_head,tail,count is reset*/
 wake_up_all_clear(&wq);
 clear_heap();
 /* sleep so that woken processes have time to be woken up
  * and be copied over
  * before resetting the buffer to 0
  */
 msleep(200);
 spin_lock_irqsave(&rbuf_lock, flags);
 rbuf_head = 0;
 rbuf_tail = 0;
 rbuf_count = 0;
 spin_unlock_irqrestore(&rbuf_lock, flags);
 return 0;
}