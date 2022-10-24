#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/pstrace.h>
#include <linux/delay.h>
/*
 * PID Tracking
 *
 * enabled_pids - all the enabled pids
 * disabled_pids - all the disabled pid
 * track_all - flag to indicate if all pids are being tracked
 * rw_track_pid_lock - lock to control access to these
 *   tracking variables
 */
static struct pid_tracker enabled_pids = {{-1}, 0};
static struct pid_tracker disabled_pids = {{-1}, 0};
static bool track_all;
static DEFINE_RWLOCK(rw_track_pid_lock);
/*
 * PS TRACE BUFFER
 *
 * BUFFER_COUNTER - Contains number of writes to the buffer
 *                  Duals as a pointer for buffer by modulo size
 *                  By modulo it points to next writable location
 * pstrace_buffer - The buffer for pstrace
 * get_process_buffer - A buffer to hold the buffers for each get
 *                      No need of ptr here, as we will only
 *   check for null spots
 * rw_pstrace_lock - lock to control access to these pstrace variables
 */
static long BUFFER_COUNTER;
static struct circbuff pstrace_buffer = {{NULL}, 0, 0, PSTRACE_BUF_SIZE, 0};
static struct get_buffer *get_process_buffer[GET_PROCESS_BUF_SIZE] = {NULL};
static DEFINE_RWLOCK(rw_pstrace_lock);
/* Wait Queue */
static DECLARE_WAIT_QUEUE_HEAD(wq_pstrace_get);
/* pid tracking functions */
static void clear_all_pids(struct pid_tracker *pt)
{
 while (pt->ptr != 0) {
  pt->ptr -= 1;
  pt->pids[pt->ptr] = -1;
 }
}
static int get_pid_idx(struct pid_tracker *pt, pid_t pid)
{
 int i = pt->ptr;
 int idx = -1;
 while (i > 0) {
  i -= 1;
  if (pt->pids[i] == pid) {
   idx = i;
   break;
  }
 }
 return idx;
}
static int get_null_idx_get_process(void)
{
 int i = 0;
 for (; i < GET_PROCESS_BUF_SIZE; i++) {
  if (get_process_buffer[i] == NULL)
   return i;
 }
 return -1;
}
static int remove_pid(struct pid_tracker *pt, pid_t pid)
{
 int i = 0, idx = -1;
 if (pt->ptr == 0) {
  pr_err("PSTRACE [%d]: Error for pid: %d, buffer empty.",
   current->pid, pid);
  return -ENOMEM;
 }
 idx = get_pid_idx(pt, pid);
 if (idx != -1) {
  i = idx;
  while ((i+1) < pt->ptr) {
   pt->pids[i] = pt->pids[i+1];
   i += 1;
  }
  pt->ptr -= 1;
  pt->pids[pt->ptr] = -1;
 }
 return idx;
}
static int add_pid(struct pid_tracker *pt, pid_t pid)
{
 int ret = 0, idx = (-1);
 if (pt->ptr == PSTRACE_BUF_SIZE) {
  pr_err("PSTRACE [%d]: Error for pid: %d, buffer full.",
   current->pid, pid);
  return -ENOMEM;
 }
 idx = get_pid_idx(pt, pid);
 if (idx != -1) {
  pr_err("PSTRACE [%d]: Value %d already present",
   current->pid, pid);
  ret = -EINVAL;
 } else {
  pt->pids[pt->ptr] = pid;
  pt->ptr += 1;
 }
 return ret;
}
/* get the task_struct for given pid - NULL if invalid pid*/
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
/* circ buffer functions */
static void cb_push(struct pstrace *p)
{
 if (pstrace_buffer.count >= PSTRACE_BUF_SIZE) {
  /* overwriting first entry */
  if (pstrace_buffer.buffer[pstrace_buffer.head] != NULL)
   kfree(pstrace_buffer.buffer[pstrace_buffer.head]);
  pstrace_buffer.tail = (pstrace_buffer.tail + 1) %
     pstrace_buffer.length;
 }
 pstrace_buffer.buffer[pstrace_buffer.head] = p;
 if (pstrace_buffer.count < PSTRACE_BUF_SIZE)
  (pstrace_buffer.count)++;
 pstrace_buffer.head = (pstrace_buffer.head + 1) % pstrace_buffer.length;
}
/* If pid == -1, clear all */
static int cb_clear_by_pid(pid_t pid_to_clear)
{
 static struct pstrace *new_buffer[PSTRACE_BUF_SIZE] = {NULL};
 int new_count = 0;
 int cleared_count;
 int i;
 if (pstrace_buffer.count == 0) {
  pr_err("PSTRACE [%d]: Clearing by pid in empty circular buffer",
   current->pid);
  return 0;
 }
 for (i = pstrace_buffer.tail;
  i < pstrace_buffer.head;
  i = (i+1) % pstrace_buffer.length) {
  if (pstrace_buffer.buffer[i] != NULL) {
   if ((pstrace_buffer.buffer[i])->pid != pid_to_clear ||
    pid_to_clear != -1)
    new_buffer[new_count++] =
     pstrace_buffer.buffer[i];
   kfree(pstrace_buffer.buffer[i]);
  }
 }
 for (i = 0; i < new_count; i++)
  pstrace_buffer.buffer[i] = new_buffer[i];
 cleared_count = pstrace_buffer.head - pstrace_buffer.tail - new_count;
 pstrace_buffer.tail = 0;
 pstrace_buffer.head = new_count;
 pstrace_buffer.count = new_count;
 return cleared_count;
}
/* If pid == -1, copy all; pass count_to_copy == -1 to copy all */
static int cb_copy_by_pid(pid_t pid_to_copy,
   struct pstrace *kbufptr,
   int count_to_copy)
{
 int copied_count = 0;
 int i;
 if (pstrace_buffer.count == 0) {
  pr_err("PSTRACE [%d]: coping by pid in empty circular buffer",
   current->pid);
  return 0;
 }
 for (i = pstrace_buffer.tail;
  i != ((pstrace_buffer.head - 1 + pstrace_buffer.length) %
   pstrace_buffer.length);
  i = (i+1) % pstrace_buffer.length) {
  if (count_to_copy != -1 && copied_count >= count_to_copy)
   break;
  if (pstrace_buffer.buffer[i] != NULL) {
   if (pstrace_buffer.buffer[i]->pid == pid_to_copy ||
    pid_to_copy == -1)
    kbufptr[copied_count++] =
     *(pstrace_buffer.buffer[i]);
  }
 }
 /* for last entry, previous loop body 1 more time */
 if (pstrace_buffer.buffer[i] != NULL &&
  (count_to_copy == -1 ||
  copied_count < count_to_copy)) {
  if (pstrace_buffer.buffer[i]->pid == pid_to_copy ||
   pid_to_copy == -1) {
   kbufptr[copied_count++] = *(pstrace_buffer.buffer[i]);
  }
 }
 return copied_count;
}
static void copy_to_pstrace(struct task_struct *p, struct pstrace *ps)
{
 ps->pid = task_pid_vnr(p);
 get_task_comm(ps->comm, p);
 ps->state = p->state;
 if (p->exit_state != 0)
  ps->state = p->exit_state;
}
static bool pid_enabled(pid_t pid)
{
 int didx = -1, eidx = -1;
 bool enabled = false;
 if (track_all == true) {
  didx = get_pid_idx(&disabled_pids, pid);
  if (didx == -1)
   enabled = true;
 } else {
  // Verify using both in case of inconsistency
  didx = get_pid_idx(&disabled_pids, pid);
  eidx = get_pid_idx(&enabled_pids, pid);
  if (didx == -1 && eidx != -1)
   enabled = true;
 }
 return enabled;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 struct pstrace *ps;
 unsigned long flags;
 bool is_enabled = false;
 int i = 0;
 if (p == NULL)
  return;
 read_lock(&rw_track_pid_lock);
 is_enabled = pid_enabled(p->pid);
 read_unlock(&rw_track_pid_lock);
 if (!is_enabled)
  return;
 // create the pstrace object
 ps = kmalloc(sizeof(struct pstrace), GFP_KERNEL);
 if (ps == NULL)
  return;
 copy_to_pstrace(p, ps);
 write_lock_irqsave(&rw_pstrace_lock, flags);
 BUFFER_COUNTER += 1;
 cb_push(ps);
 for (i = 0; i < GET_PROCESS_BUF_SIZE; i++) {
  if (get_process_buffer[i] != NULL) {
   struct get_buffer *gb = get_process_buffer[i];
   if (gb->ptr == PSTRACE_BUF_SIZE) {
    gb->should_exit = true;
   } else if (gb->should_exit != true) {
    pid_t tracking_pid = gb->tracking_pid;
    if (tracking_pid == -1 ||
     tracking_pid == p->pid) {
     struct pstrace lps;
     copy_to_pstrace(p, &lps);
     gb->buffer[gb->ptr] = lps;
     gb->ptr += 1;
     if (gb->ptr == PSTRACE_BUF_SIZE)
      gb->should_exit = true;
    }
   }
  }
 }
 wake_up_all(&wq_pstrace_get);
 write_unlock_irqrestore(&rw_pstrace_lock, flags);
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid) {
 int ret = 0;
 struct task_struct *ts;
 pr_info("PSTRACE [%d]:  pstrace_enable called with pid: %d",
  current->pid, pid);
 write_lock(&rw_track_pid_lock);
 if (pid == -1) {
  track_all = true;
  clear_all_pids(&disabled_pids);
  clear_all_pids(&enabled_pids);
 } else if (!track_all) {
  ts = get_root(pid);
  if (ts == NULL) {
   pr_err("PSTRACE [%d]: Invalid pid provided: %d",
    current->pid, pid);
   ret = -EINVAL;
  } else {
   remove_pid(&disabled_pids, pid);
   ret = add_pid(&enabled_pids, pid);
  }
 }
 write_unlock(&rw_track_pid_lock);
 return ret;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid) {
 int eidx = -1, didx = -1, ret = 0;
 pr_info("PSTRACE [%d]:  pstrace_disable called with pid: %d",
  current->pid, pid);
 write_lock(&rw_track_pid_lock);
 if (pid == -1) {
  track_all = false;
  clear_all_pids(&disabled_pids);
  clear_all_pids(&enabled_pids);
 } else {
  eidx = remove_pid(&enabled_pids, pid);
  didx = get_pid_idx(&disabled_pids, pid);
  if (eidx == -1 && didx == -1)
   ret = -EINVAL;
  else if (eidx == -1 && didx != -1) {
   pr_err("PSTRACE [%d]: This pid %d is already disabled",
    current->pid, pid);
   ret = -EINVAL;
  } else {
   ret = add_pid(&disabled_pids, pid);
  }
 }
 write_unlock(&rw_track_pid_lock);
 return ret;
}
int init_user_vars_for_get(struct pstrace *buf, long *counter, long *krc)
{
 long val;
 if (access_ok(counter, sizeof(long)) == 0) {
  pr_err("PSTRACE [%d]:  cannot access counter", current->pid);
  return -EINVAL;
 }
 if (__copy_from_user(krc, counter, sizeof(long)) != 0) {
  pr_err("PTRACE: unable to copy the counter");
  return -EINVAL;
 }
 val = *krc;
 if (access_ok(buf, val*sizeof(struct pstrace)) == 0) {
  pr_err("PSTRACE [%d]:  cannot access buffer", current->pid);
  return -EINVAL;
 }
 return 0;
}
/*
 * Syscall No. 438
 *
 * Copy the pstrace ring buffer info @buf.
 * If @pid == -1, copy all records; otherwise, only copy records of @pid.
 * If @counter > 0, the caller process will wait until a full buffer can
 * be returned after record @counter (i.e. return record @counter + 1 to
 * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
 *
 * Returns the number of records copied.
 */
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter) {
 long krc = 0;
 unsigned long flags = 0;
 struct get_buffer gb;
 int ret = 0, cret = 0;
 int idx, num_copy;
 bool do_not_unlock = false;
 ret = init_user_vars_for_get(buf, counter, &krc);
 if (ret != 0)
  return ret;
 write_lock_irqsave(&rw_pstrace_lock, flags);
 idx = get_null_idx_get_process();
 if (idx == -1) {
  pr_err("PSTRACE [%d]: No mem for another get call.",
   current->pid);
  ret = -ENOMEM;
 } else {
  gb.get_process_pid = current->pid;
  gb.tracking_pid = pid;
  gb.ptr = 0;
  gb.should_exit = false;
  get_process_buffer[idx] = &gb;
 }
 write_unlock_irqrestore(&rw_pstrace_lock, flags);
 if (ret != 0)
  return ret;
 read_lock(&rw_pstrace_lock);
 if (krc == 0) {
  num_copy = cb_copy_by_pid(pid, gb.buffer, -1);
  gb.ptr += num_copy;
  pr_info("PSTRACE [%d]: GET - copied all as counter = 0",
  current->pid);
 } else if ((krc >= BUFFER_COUNTER) ||
  (krc + PSTRACE_BUF_SIZE <= BUFFER_COUNTER)) {
  ret = -EINVAL;
 } else {
  num_copy = (BUFFER_COUNTER - krc);
  num_copy = cb_copy_by_pid(pid, gb.buffer, num_copy);
  gb.ptr += num_copy;
  if (num_copy == PSTRACE_BUF_SIZE)
   gb.should_exit = true;
  do {
   if (gb.should_exit)
    break;
   read_unlock(&rw_pstrace_lock);
   do_not_unlock = true;
   ret = wait_event_interruptible(wq_pstrace_get,
      gb.should_exit == true);
   if (ret != 0)
    break;
   read_lock(&rw_pstrace_lock);
   do_not_unlock = false;
  } while (1);
 }
 cret = __copy_to_user(buf, &gb.buffer, sizeof(gb.buffer));
 if (cret != 0) {
  pr_err("PSTRACE [%d]: GET - copy to user buffer failed.",
   current->pid);
  cret = -EFAULT;
 }
 cret = __copy_to_user(counter, &BUFFER_COUNTER, sizeof(long));
 if (cret != 0) {
  pr_err("PSTRACE [%d]:  copy to user counter failed.",
   current->pid);
  cret = -EFAULT;
 }
 // since we are exiting, we can remove our spot
 // from get_process_buffer. it is ok to not use
 // write_lock as no one else is accessing the current
 // spot from this point on.
 get_process_buffer[idx] = NULL;
 if (!do_not_unlock)
  read_unlock(&rw_pstrace_lock);
 if (ret == 0 && cret == 0)
  return gb.ptr;
 else if (ret == 0)
  return cret;
 return ret;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid) {
 int ret = 0, i = 0;
 unsigned long flags;
 pr_info("PSTRACE [%d]:  pstrace_clear called", current->pid);
 write_lock_irqsave(&rw_pstrace_lock, flags);
 for (i = 0; i < GET_PROCESS_BUF_SIZE; i++) {
  if (get_process_buffer[i] != NULL) {
   struct get_buffer *gb = get_process_buffer[i];
   if (gb->ptr == PSTRACE_BUF_SIZE) {
    gb->should_exit = true;
   } else {
    pid_t tracking_pid = gb->tracking_pid;
    if (pid == -1 || tracking_pid == pid)
     gb->should_exit = true;
   }
  }
 }
 cb_clear_by_pid(pid);
 write_unlock_irqrestore(&rw_pstrace_lock, flags);
 wake_up_all(&wq_pstrace_get);
 return ret;
}