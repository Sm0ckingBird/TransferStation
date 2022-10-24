#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/wait.h>
struct pstrace ring_buf[PSTRACE_BUF_SIZE];
unsigned long flags;
 /* used for locking the ring_buf, ring_buf_len, and traced_pid */
DEFINE_SPINLOCK(ring_buf_lock);
int ring_buf_len;  /* index of latest entry in the ring buffer */
long ring_buf_count; /* number of records added ever */
int ring_buf_valid_count; /* number of records added since last clear */
/* used for conditionally stopping waiting when we clear the buffer */
atomic_t clear_count;
pid_t traced_pid = -2; /* the pid we are tracing, or -1 for all processes,
   * or -2 for tracing disabled
   */
DECLARE_WAIT_QUEUE_HEAD(wq_head);
bool is_wakeup_required;
long linux_counter;
int orig_clear_count;
struct mutex pstrace_mutex; /* used for locking ring_buf and sleep */
pid_t syscall443_pid = -10;
long local_counter;
void insert_pstrace_entry(struct task_struct *p, long state)
{
 /* Add the ring buffer entry at index ring_buf_len.
  * Assumption: we have a lock on the ring buffer.
  */
 strcpy(ring_buf[ring_buf_len].comm, p->comm);
 ring_buf[ring_buf_len].state = state;
 ring_buf[ring_buf_len].pid = p->tgid;
 ring_buf[ring_buf_len].tid = p->pid;
 ring_buf_count++;
 // wake_up?
 ring_buf_valid_count++;
 ring_buf_len++;
 local_counter++;
 if (ring_buf_len == PSTRACE_BUF_SIZE)
  ring_buf_len = 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 /* Add to the ring buffer. We need to add the state updates of all those
  * traced processes.
  */
 if (traced_pid == -2)
  return;
 if ((traced_pid != -1) && (traced_pid != p->tgid))
  return;
 if (!p)
  return;
 if ((p->pid < 0) || (p->tgid < 0))
  return;
 if (state == TASK_STOPPED)
  state = __TASK_STOPPED;
 /* only track states that we care about */
 if (state != TASK_RUNNING &&
     state != TASK_RUNNABLE &&
     state != TASK_INTERRUPTIBLE &&
     state != TASK_UNINTERRUPTIBLE &&
     state != __TASK_STOPPED &&
     state != EXIT_ZOMBIE &&
     state != EXIT_DEAD)
  return;
 spin_lock_irqsave(&ring_buf_lock, flags);
 /* is tracing enabled? */
 if (traced_pid == -2) {
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  return;
 }
 /* are we tracing this process? */
 if ((traced_pid != -1) && (traced_pid != p->tgid)) {
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  return;
 }
 insert_pstrace_entry(p, state);
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 if (is_wakeup_required &&
     ((ring_buf_count >= linux_counter + PSTRACE_BUF_SIZE))) {
  wake_up_interruptible(&wq_head);
 }
}
void pstrace_add_wakeup(struct task_struct *p, long state)
{
 /* Add to the ring buffer. We need to add the state updates of all those
  * traced processes.
  */
 if (traced_pid == -2)
  return;
 if ((traced_pid != -1) && (traced_pid != p->tgid))
  return;
 if (!p)
  return;
 if (syscall443_pid == p->pid)
  return;
 else if (traced_pid == -1)
  return;
 else
  return pstrace_add(p, state);
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *task = NULL;
 /* validate that we are given a valid pid */
 if (pid < -1)
  return -ESRCH;
 else if (pid == 0)
  task = &init_task;
 else if (pid > 0)
  task = find_task_by_vpid(pid);
 if (pid != -1 && task == NULL)
  return -ESRCH;
 spin_lock_irqsave(&ring_buf_lock, flags);
 traced_pid = pid;
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 spin_lock_irqsave(&ring_buf_lock, flags);
 traced_pid = -2;
 spin_unlock_irqrestore(&ring_buf_lock, flags);
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf,
  long __user *, counter)
{
 int num_to_copy;
 long records_copied = 0;
 int cleared = 0;
 int index;
 int i;
 int wait_status = -ERESTARTSYS;
 /*To store the start (valid values) index counter*/
 int start_index_counter = 0;
 /*To store the end (valid values) index counter*/
 int end_index_counter = 0;
 /*Looping element*/
 int temp_index_counter = 0;
 /*To store the start (valid values) index in ringbuf*/
 int start_valid_index = 0;
 /*To store the end (valid values) index in ringbuf*/
 int end_valid_index = 0;
 long copy_counter = 0;
 if (!buf || !counter)
  return -EINVAL;
 /* copy *nr from user space into max_entries */
 if (copy_from_user(&linux_counter, counter, sizeof(long)))
  return -EFAULT;
 if (linux_counter < 0)
  return -EINVAL;
 else if (linux_counter == 0) {
  spin_lock_irqsave(&ring_buf_lock, flags);
  num_to_copy = (ring_buf_valid_count < PSTRACE_BUF_SIZE ?
          ring_buf_valid_count : PSTRACE_BUF_SIZE);
  if (num_to_copy == 0) {
   spin_unlock_irqrestore(&ring_buf_lock, flags);
   return 0;
  }
  /*Valid values - these will only increase. there is no "%"
   * Not using it anywhere in counter = 0
   */
  start_index_counter = (local_counter-num_to_copy + 1);
  end_index_counter = (local_counter);
  /*Need % as these are valid indices stored*/
  end_valid_index = (ring_buf_len + PSTRACE_BUF_SIZE - 1) %
    PSTRACE_BUF_SIZE;
  start_valid_index = (ring_buf_len + PSTRACE_BUF_SIZE -
         num_to_copy) % PSTRACE_BUF_SIZE;
  for (i = 0; i < num_to_copy && i < ring_buf_valid_count; i++) {
   if (i == 0)
    index = start_valid_index;
   else
    index = (index + 1) % PSTRACE_BUF_SIZE;
   if (copy_to_user(buf[i].comm,
      ring_buf[index].comm,
      16*sizeof(char)) ||
       copy_to_user(&(buf[i].state),
      &(ring_buf[index].state),
      sizeof(long)) ||
       copy_to_user(&(buf[i].pid),
      &(ring_buf[index].pid),
      sizeof(pid_t)) ||
       copy_to_user(&(buf[i].tid),
      &(ring_buf[index].tid),
      sizeof(pid_t))) {
    spin_unlock_irqrestore(&ring_buf_lock, flags);
    return -EFAULT;
   }
   records_copied++;
   if (index == end_valid_index)
    break;
  }
  copy_counter = local_counter;
  if (copy_to_user(counter, &copy_counter, sizeof(long))) {
   spin_unlock_irqrestore(&ring_buf_lock, flags);
   return -EFAULT;
  }
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  return records_copied;
 } else if (linux_counter > 0) {
  orig_clear_count = clear_count.counter;
  if (ring_buf_count < linux_counter + PSTRACE_BUF_SIZE) {
   syscall443_pid = task_pid_nr(current);
   if (syscall443_pid < 0)
    return -EFAULT;
   is_wakeup_required = true;
   wait_status = wait_event_interruptible(wq_head,
       (ring_buf_count >= linux_counter +
        PSTRACE_BUF_SIZE) ||
       (orig_clear_count != clear_count.counter));
   if (wait_status !=  0) {
    syscall443_pid = -10;
    return wait_status;
   }
   if (orig_clear_count != clear_count.counter)
    cleared = 1;
  }
  is_wakeup_required = false;
  records_copied = 0;
  syscall443_pid = -10;
  spin_lock_irqsave(&ring_buf_lock, flags);
  num_to_copy = (ring_buf_valid_count < PSTRACE_BUF_SIZE ?
          ring_buf_valid_count : PSTRACE_BUF_SIZE);
  if (num_to_copy == 0) {
   spin_unlock_irqrestore(&ring_buf_lock, flags);
   return 0;
  }
  /*Valid values - these will only increase. there is no "%" */
  start_index_counter = (local_counter-num_to_copy + 1);
  end_index_counter = (local_counter);
  if ((start_index_counter > linux_counter + PSTRACE_BUF_SIZE) ||
   (end_index_counter <= linux_counter)) {
   spin_unlock_irqrestore(&ring_buf_lock, flags);
   return 0;
  }
  /*Need % as these are valid indices stored*/
  end_valid_index = (ring_buf_len + PSTRACE_BUF_SIZE - 1) %
    PSTRACE_BUF_SIZE;
  start_valid_index = (ring_buf_len + PSTRACE_BUF_SIZE -
         num_to_copy) % PSTRACE_BUF_SIZE;
  for (i = 0; i < PSTRACE_BUF_SIZE &&
        (cleared == 0 || i < ring_buf_valid_count); i++) {
   if (i == 0) {
    index = start_valid_index;
    temp_index_counter = start_index_counter;
   } else {
    index = (index + 1) % PSTRACE_BUF_SIZE;
    temp_index_counter++;
   }
   if (temp_index_counter <= linux_counter)
    continue;
   if (temp_index_counter > linux_counter +
       PSTRACE_BUF_SIZE)
    break;
   if (copy_to_user(buf[i].comm,
      ring_buf[index].comm,
      16*sizeof(char)) ||
       copy_to_user(&(buf[i].state),
      &(ring_buf[index].state),
      sizeof(long)) ||
       copy_to_user(&(buf[i].pid),
      &(ring_buf[index].pid),
      sizeof(pid_t)) ||
       copy_to_user(&(buf[i].tid),
      &(ring_buf[index].tid),
      sizeof(pid_t))) {
    spin_unlock_irqrestore(&ring_buf_lock, flags);
    return -EFAULT;
   }
   records_copied++;
   if (index == end_valid_index)
    break;
  }
  copy_counter = linux_counter + records_copied;
  if (copy_to_user(counter, &copy_counter, sizeof(long))) {
   spin_unlock_irqrestore(&ring_buf_lock, flags);
   return -EFAULT;
  }
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  return records_copied;
 }
 return records_copied;
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
 atomic_inc(&clear_count);
 spin_lock_irqsave(&ring_buf_lock, flags);
 ring_buf_valid_count = 0;
 ring_buf_len = 0;
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 if (is_wakeup_required && (orig_clear_count != clear_count.counter))
  wake_up_interruptible(&wq_head);
 return 0;
}