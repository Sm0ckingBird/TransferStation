#include <linux/pstrace.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
int flag = -1;
int should_get_return = 0;
int track_all = -1;
long buf_counter = 0;
int buf_occupied = 0;
static DEFINE_SPINLOCK(lock_spin);
struct pstrace_record ring_buf[PSTRACE_BUF_SIZE];
struct pstrace_pid pid_list[PSTRACE_BUF_SIZE];
/*
 * Description: To check whether the program is first time run
 *        set all states to 0 if it is.
 */
void init_pid_list(int flag)
{
 int i = 0;
 if (flag == -1) {
  for (i = 0; i < PSTRACE_BUF_SIZE; ++i)
   pid_list[i].state = 0;
 }
}
/*
 * Description : To determine whether a process should be traced
 * Return       : 0 no, 1 yes
 */
int should_track(pid_t pid)
{
 int i = 0;
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i)
  if (pid_list[i].pid == pid && pid_list[i].state == 1)
   return 1;
 return 0;
}
/*
 * Param - p                  : target process task_struct
 * Param - should_get_return  : check whether wake_up should be called
 * Param - track_all          : check whether input pid is -1
 */
void pstrace_add(struct task_struct *p)
{
 unsigned long flags = 0;
       /*
 * Avoid wake_up to call pstrace_add() function
 */
 if (should_get_return == 1)
  return;
       /*
 * 1. Check whether the pid is in the pid_list or the input pid is -1
 * 2. Add the information of the process to the ring buffer in order
 * 3. Set the occupied state of that buffer place to 1 (occupied)
 * 4. Add buffer counter
 * 5. Set should_get_returnAvoid the wake_up function
 */
 spin_lock_irqsave(&lock_spin, flags);
 if (track_all == 1 || should_track(p->pid) == 1) {
  if (p->state == TASK_DEAD)
   ring_buf[buf_counter % PSTRACE_BUF_SIZE].trace.state =
    p->exit_state;
  else
   ring_buf[buf_counter % PSTRACE_BUF_SIZE].trace.state =
    p->state;
  ring_buf[buf_counter % PSTRACE_BUF_SIZE].trace.pid = p->pid;
  ring_buf[buf_counter % PSTRACE_BUF_SIZE].occupied = 1;
  get_task_comm(
   ring_buf[buf_counter % PSTRACE_BUF_SIZE].trace.comm, p);
  buf_counter++;
  should_get_return = 1;
  wake_up(&buffer_increment_wait);
  should_get_return = 0;
 }
 spin_unlock_irqrestore(&lock_spin, flags);
}
/*
 * Param - flag     : check whether the program is first time run
 * Param - pid_list : an struct to save the target pid
 *      : 1). pid
 *      : 2). state: 1 (should trace), 0 (don't trace)
 * Return           : 0 on success, -1 on failure
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 int i = 0;
 spin_lock(&lock_spin);
 init_pid_list(flag);
 flag = 1;
       /*
 * Case: all processes should be traced
 */
 if (pid == -1) {
  track_all = 1;
  spin_unlock(&lock_spin);
  return 0;
 }
       /*
 * Check whether the pid has been added
 */
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i) {
  if (pid_list[i].pid == pid && pid_list[i].state == 1) {
   spin_unlock(&lock_spin);
   return 0;
  }
 }
       /*
 * If not added, add the pid to the pid_list
 */
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i) {
  if (pid_list[i].state == 0) {
   pid_list[i].state = 1;
   pid_list[i].pid = pid;
   spin_unlock(&lock_spin);
   return 0;
  }
 }
 spin_unlock(&lock_spin);
 return 0;
}
/*
 * Return   : 0 on success, -1 on failure
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 int i = 0;
 spin_lock(&lock_spin);
       /*
 * Set all the state of processes to 0 (don't trace)
 */
 if (pid == -1) {
  track_all = 0;
  for (i = 0; i < PSTRACE_BUF_SIZE; ++i)
   pid_list[i].state = 0;
  spin_unlock(&lock_spin);
  return 0;
 }
       /*
 * disable specific by setting the state.
 */
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i) {
  if (pid_list[i].pid == pid && pid_list[i].state == 1) {
   pid_list[i].state = 0;
   spin_unlock(&lock_spin);
   return 0;
  }
 }
 spin_unlock(&lock_spin);
 return 0;
}
/*
 * Param - tmp      : temporary task_struct to pass data
 * Param - ring_buf : a struct to save the target process's info
 *      : 1). occupied 1 will be printed, 0 seen as empty
 *      : 2). pid
 *      : 3). state
 * Param - lower    : lower limit of ring buffer
 * Param - upper    : upper limit of targeted range
 * Return           : 0 on success, -1 on failure
 */
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter)
{
 long cnt = 0;
 long i = 0, j = 0;
 struct pstrace *tmp;
 long lower, upper;
 if (!buf || !counter)
  return -EINVAL;
 if (copy_from_user(&cnt, counter, sizeof(long)))
  return -EFAULT;
 tmp = kmalloc((500) * sizeof(struct pstrace), GFP_KERNEL);
 if (tmp == NULL)
  return -ENOMEM;
 spin_lock(&lock_spin);
 lower = buf_counter - PSTRACE_BUF_SIZE;
 upper = cnt + PSTRACE_BUF_SIZE;
       /*
 * The process does not need to sleep in this case and should
 * output the all the elements in the ring buffer.
 * When pid is -1, pass all the data from ring buffer to user-space.
 * Otherwise, pass the data of process with given pid.
 */
 if (cnt <= 0) {
  if (pid == -1) {
   for (i = 0, j = 0; i < PSTRACE_BUF_SIZE; ++i) {
    if (ring_buf[i % PSTRACE_BUF_SIZE].occupied ==
        1) {
     tmp[j] = ring_buf[i % PSTRACE_BUF_SIZE]
        .trace;
     j++;
    }
   }
  } else {
   for (i = 0, j = 0; i < PSTRACE_BUF_SIZE; ++i) {
    if (ring_buf[i % PSTRACE_BUF_SIZE].occupied ==
         1 &&
        ring_buf[i % PSTRACE_BUF_SIZE].trace.pid ==
         pid) {
     tmp[j] = ring_buf[i % PSTRACE_BUF_SIZE]
        .trace;
     j++;
    }
   }
  }
  spin_unlock(&lock_spin);
  if (copy_to_user(buf, tmp,
     PSTRACE_BUF_SIZE * sizeof(struct pstrace))) {
   kfree(tmp);
   return -EFAULT;
  }
  kfree(tmp);
  if (copy_to_user(counter, &buf_counter, sizeof(long)))
   return -EFAULT;
  return j;
 }
       /*
 * The process does not need to sleep in this case and should
 * output the all the elements in the ring buffer.
 * When pid is -1, pass all the data from ring buffer to user-space.
 * Otherwise, pass the data of process with given pid.
 */
 if (upper < lower) {
        /*
  * The ring buffer does not have the elements requested
  * because of the update operation.
  */
  spin_unlock(&lock_spin);
  kfree(tmp);
  if (copy_to_user(counter, &buf_counter, sizeof(long)))
   return -EFAULT;
  return 0;
 } else if (upper <= buf_counter) {
        /*
  * Part of ring buffer meets the requirement in the range
  * (buf_counter-500, counter+500)
  */
  if (pid == -1) {
   for (i = buf_counter - PSTRACE_BUF_SIZE, j = 0;
        i < upper; ++i) {
    if (ring_buf[i % PSTRACE_BUF_SIZE].occupied ==
        1) {
     tmp[j] = ring_buf[i % PSTRACE_BUF_SIZE]
        .trace;
     j++;
    }
   }
  } else {
   for (i = buf_counter - PSTRACE_BUF_SIZE, j = 0;
        i < upper; ++i) {
    if (ring_buf[i % PSTRACE_BUF_SIZE].trace.pid ==
         pid &&
        ring_buf[i % PSTRACE_BUF_SIZE].occupied ==
         1) {
     tmp[j] = ring_buf[i % PSTRACE_BUF_SIZE]
        .trace;
     j++;
    }
   }
  }
 } else {
        /*
  * The upper limit of ring buffer index is less than counter.
  * THe process has to sleep and wait until the buffer counter
  * reach the counter+500.
  */
  DECLARE_WAITQUEUE(wait, current);
  add_wait_queue(&buffer_increment_wait, &wait);
        /*
  * The process sleep in the wait queue and waked up by
  * pstrace_add() function, it will check whether the condition
  * is required after waking up. If not, it will sleep again.
  */
  while (buf_counter < upper) {
   set_current_state(TASK_INTERRUPTIBLE);
   spin_unlock(&lock_spin);
   schedule();
   spin_lock(&lock_spin);
  }
  remove_wait_queue(&buffer_increment_wait, &wait);
        /*
  * Pass the information of enabled process to user space.
  */
  if (pid == -1) {
   for (i = buf_counter - PSTRACE_BUF_SIZE, j = 0;
        i < buf_counter; ++i) {
    if (ring_buf[i % PSTRACE_BUF_SIZE].occupied ==
        1) {
     tmp[j] = ring_buf[i % PSTRACE_BUF_SIZE]
        .trace;
     j++;
    }
   }
  } else {
   for (i = buf_counter - PSTRACE_BUF_SIZE, j = 0;
        i < buf_counter; ++i) {
    if (ring_buf[i % PSTRACE_BUF_SIZE].trace.pid ==
         pid &&
        ring_buf[i % PSTRACE_BUF_SIZE].occupied ==
         1) {
     tmp[j] = ring_buf[i % PSTRACE_BUF_SIZE]
        .trace;
     j++;
    }
   }
  }
 }
 spin_unlock(&lock_spin);
 if (copy_to_user(buf, tmp, PSTRACE_BUF_SIZE * sizeof(struct pstrace))) {
  kfree(tmp);
  return -EFAULT;
 }
 if (tmp != NULL)
  kfree(tmp);
 if (copy_to_user(counter, &buf_counter, sizeof(long)))
  return -EFAULT;
 return j;
}
/*
 * Description   : Change the occupied state to clear the ring buff
 * Return        : 0 on success, -1 on failure
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i = 0;
 spin_unlock(&lock_spin);
       /*
 * Clear all the elements in ring buffer
 */
 if (pid == -1) {
  for (i = 0; i < PSTRACE_BUF_SIZE; ++i)
   ring_buf[i].occupied = 0;
  return 0;
 }
       /*
 * Clear the specific elements according to pid
 */
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i)
  if (ring_buf[i].trace.pid == pid && ring_buf[i].occupied == 1)
   ring_buf[i].occupied = 0;
 spin_unlock(&lock_spin);
 return 0;
}