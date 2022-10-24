#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/sched/task.h> /* tasklist */
#include <linux/list.h>       /* list_head stuff */
#include <linux/slab.h>       /* kmalloc, kfree */
#include <linux/kernel.h>     /* printk levels */
#define INVALID_PID -10000
DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static LIST_HEAD(target_counters);
bool tracing_all;
int num_tracing;
static atomic_t counter_buffer = ATOMIC_INIT(0);
struct pstrace pstrace_buffer[PSTRACE_BUF_SIZE];
struct pid_list traced_pids;
/* to_be_woken_get: is set to pid of get syscall which clear wants to kill */
static pid_t to_be_woken_get = INVALID_PID;
struct pstrace final_buf_k[PSTRACE_BUF_SIZE];
int snapshot_counter_value;
int num_deleted;
static DEFINE_SPINLOCK(pstracebuf_lock);
static DEFINE_SPINLOCK(finalbuf_lock);
static DEFINE_SPINLOCK(num_deleted_lock);
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
void fill_pstrace_buffer(struct task_struct *process, int is_exit_flag)
{
 struct pstrace *tracer;
 int buffer_index = ((atomic_read(&counter_buffer)
   -num_deleted) % PSTRACE_BUF_SIZE);
 tracer = pstrace_buffer + buffer_index;
 tracer->pid = task_pid_vnr(process);
 if (is_exit_flag == 1)
  tracer->state = process->exit_state;
 else
  tracer->state = process->state;
 get_task_comm(tracer->comm, process);
 atomic_inc(&counter_buffer);
}
/* Checks if current pid is being traced. */
bool pid_traced(pid_t pid)
{
 struct pid_list *iter;
 if (tracing_all)
  return true;
 if (num_tracing == 0 || list_empty(&(traced_pids.llist)))
  return false;
 list_for_each_entry(iter, &(traced_pids.llist), llist) {
  if (iter->pid == pid)
   return true;
 }
 return false;
}
/* Stops tracing the pid */
void pid_stop_trace(pid_t pid)
{
 struct pid_list *iter;
 list_for_each_entry(iter, &(traced_pids.llist), llist) {
  if (iter->pid == pid) {
   list_del(&(iter->llist));
   num_tracing -= 1;
   break;
  }
 }
}
/* METHOD FOR DEBUGGING PURPOSES */
void debug_print(struct task_struct *tsk, int exit_flag)
{
 if (exit_flag == 0)
  pr_info("NORMAL: %s: pid %d and state %ld and exit state %d\n",
   tsk->comm, tsk->pid, tsk->state, tsk->exit_state);
 else
  pr_info("EXIT: %s: pid %d and state %ld and exit state %d\n",
   tsk->comm, tsk->pid, tsk->state, tsk->exit_state);
}
void debug_pid_list(void)
{
 struct pid_list *iter;
 if (num_tracing == 0 || list_empty(&(traced_pids.llist)))
  pr_info("list empty\n");
 if (tracing_all)
  pr_info("tracing all\n");
 list_for_each_entry(iter, &(traced_pids.llist), llist) {
  pr_info("tracing pid%d\n", iter->pid);
 }
}
/*
 * Syscall No. 436
 * * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *process;
 struct pid_list *new_pid;
 unsigned long flags;
 pr_info("ENABLE: got pid %d", (int) pid);
 spin_lock_irqsave(&pstracebuf_lock, flags);
 pr_info("locked pstrace lock.\n");
 if (pid < 0) {
  tracing_all = true;
 } else {
  if (num_tracing == 0) {
   // TODO: will leak memory
   INIT_LIST_HEAD(&traced_pids.llist);
  } else if (num_tracing >= PSTRACE_BUF_SIZE) {
   spin_unlock_irqrestore(&pstracebuf_lock, flags);
   return -ENOMEM;
  } else if (pid_traced(pid)) {
   spin_unlock_irqrestore(&pstracebuf_lock, flags);
   return 0;
  }
  read_lock(&tasklist_lock);
  process = get_root(pid);
  read_unlock(&tasklist_lock);
  if (process == NULL) {
   spin_unlock_irqrestore(&pstracebuf_lock, flags);
   return -ESRCH;
  }
  new_pid = kmalloc(sizeof(struct pid_list), GFP_KERNEL);
  if (new_pid == NULL) {
   spin_unlock_irqrestore(&pstracebuf_lock, flags);
   return -ENOMEM;
  }
  new_pid->pid = pid;
  list_add(&(new_pid->llist), &(traced_pids.llist));
  num_tracing += 1;
  pr_info("Tracing process with pid %d", (int) pid);
 }
 spin_unlock_irqrestore(&pstracebuf_lock, flags);
 pr_info("released pstrace lock.\n");
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 unsigned long flags;
 pr_info("DISABLE: got pid %d", (int) pid);
 spin_lock_irqsave(&pstracebuf_lock, flags);
 if (pid < 0) {
  tracing_all = false;
  num_tracing = 0;
 } else if (!pid_traced(pid)) {
  pr_info("Pid %d not tracked.\n", (int) pid);
 } else {
  pid_stop_trace(pid);
  pr_info("Stopped tracking pid %d\n", (int) pid);
 }
 spin_unlock_irqrestore(&pstracebuf_lock, flags);
 return 0;
}
long get_list_min(void)
{
 struct counter_list *iter;
 long minm = INT_MAX;
 list_for_each_entry(iter, &(target_counters), llist) {
  if (iter->target_counter < minm)
   minm = iter->target_counter;
 }
 return minm;
}
//write different check and wake for clear
bool check_and_wakeup(int value)
{
 unsigned long flags;
 long minTarget = -1;
 //return if wait queue is empty
 if (!wq_has_sleeper(&wait_queue))
  return true;
 minTarget = get_list_min();
 if (value == minTarget) {
  spin_lock_irqsave(&finalbuf_lock, flags);
  memcpy(final_buf_k, pstrace_buffer,
    PSTRACE_BUF_SIZE*sizeof(struct pstrace));
  spin_unlock_irqrestore(&finalbuf_lock, flags);
  spin_unlock_irqrestore(&pstracebuf_lock, flags);
  snapshot_counter_value = atomic_read(&counter_buffer);
  wake_up_interruptible(&wait_queue);
  return false;
 }
 return true;
}
bool is_pid_sleeping(pid_t pid)
{
 struct pid_list *iter;
 if (tracing_all)
  return true;
 if (list_empty(&(target_counters)))
  return false;
 list_for_each_entry(iter, &(target_counters), llist) {
  if (iter->pid == pid)
   return true;
 }
 return false;
}
void check_and_wakeup_for_clear(void)
{
 unsigned long flags;
 spin_lock_irqsave(&pstracebuf_lock, flags);
 spin_lock_irqsave(&finalbuf_lock, flags);
 memcpy(final_buf_k, pstrace_buffer,
    PSTRACE_BUF_SIZE*sizeof(struct pstrace));
 spin_unlock_irqrestore(&finalbuf_lock, flags);
 spin_unlock_irqrestore(&pstracebuf_lock, flags);
 snapshot_counter_value = atomic_read(&counter_buffer);
 pr_info("By the authority of pstrace_clear, waking up everybody.\n");
 wake_up_interruptible(&wait_queue);
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, int is_exit_flag)
{
 unsigned long flags;
 bool shouldUnlock = true;
 pid_t pid = p->pid;
 if (pid_traced(pid)) {
  spin_lock_irqsave(&pstracebuf_lock, flags);
  fill_pstrace_buffer(p, is_exit_flag);
  shouldUnlock = check_and_wakeup(atomic_read(&counter_buffer));
  if (shouldUnlock)
   spin_unlock_irqrestore(&pstracebuf_lock, flags);
 }
}
bool should_wake_up(pid_t pid)
{
 if (to_be_woken_get == -1)
  return true;
 else
  return to_be_woken_get == pid;
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid,
  struct pstrace __user *, buf,
    long __user *, counter)
{
 struct pstrace *buf_k;
 unsigned long flags;
 pid_t pid_k = pid;
 long counter_k;
 long num_elements_copied = 0;
 int start;
 int end;
 int j = 0;
 bool requiredSleeping = false;
 int local_copy_counter_buffer = 0;
 int target_val_for_counter = 0;
 /* All that happens is finding the max value. */
 struct counter_list *new_woken_listnode;
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if ((copy_from_user(&counter_k, counter, sizeof(long))) != 0)
  return -EFAULT;
 buf_k = kmalloc_array(PSTRACE_BUF_SIZE,
    sizeof(struct pstrace), GFP_KERNEL);
 if (!buf_k)
  return -ENOMEM;
 target_val_for_counter = counter_k + PSTRACE_BUF_SIZE;
 snapshot_counter_value = atomic_read(&counter_buffer);
 while (1) {
  if (atomic_read(&counter_buffer) >=
    target_val_for_counter
    || should_wake_up(pid)) {
   pr_info("Target val: %d, pid: %d",
    target_val_for_counter, pid);
   break;
  }
  new_woken_listnode = kmalloc(sizeof
    (struct counter_list), GFP_KERNEL);
  if (new_woken_listnode == NULL)
   return -ENOMEM;
  new_woken_listnode->traced_pid = pid;
  new_woken_listnode->target_counter = target_val_for_counter;
  list_add(&(new_woken_listnode->llist), &(target_counters));
  requiredSleeping = true;
  pr_info("SLEEPING:pstrace_get\n");
  wait_event_interruptible(wait_queue,
   ((atomic_read(&counter_buffer) >=
   target_val_for_counter) ||
   (should_wake_up(pid))));
 }
 pr_info("AWAKE:pstrace_get\n");
 if (requiredSleeping) {
  local_copy_counter_buffer = snapshot_counter_value;
  list_del(&(new_woken_listnode->llist));
 } else {
  local_copy_counter_buffer = atomic_read(&counter_buffer);
  spin_lock_irqsave(&pstracebuf_lock, flags);
  spin_lock_irqsave(&finalbuf_lock, flags);
  memcpy(final_buf_k, pstrace_buffer,
    PSTRACE_BUF_SIZE * sizeof(struct pstrace));
  spin_unlock_irqrestore(&finalbuf_lock, flags);
  spin_unlock_irqrestore(&pstracebuf_lock, flags);
 }
 start = local_copy_counter_buffer-PSTRACE_BUF_SIZE;
 end = local_copy_counter_buffer;
 if (start < counter_k)
  start = counter_k;
 if (end > target_val_for_counter)
  end = target_val_for_counter;
 pr_info("start is :%d, end is:%d\n", start, end);
 spin_lock_irqsave(&finalbuf_lock, flags);
 while (start < end) {
  int index = start % PSTRACE_BUF_SIZE;
  if ((final_buf_k[index].pid == pid_k) || (pid_k == -1)) {
   struct pstrace *curr = &(final_buf_k[index]);
   struct pstrace *dest = &(buf_k[j]);
   if (final_buf_k[index].pid == INVALID_PID) {
    start++;
    continue;
   }
   dest->pid = curr->pid;
   dest->state = curr->state;
   strncpy(dest->comm, curr->comm, sizeof(curr->comm));
   pr_info("%s,%d,%ld\n", dest->comm,
    dest->pid, dest->state);
   j++;
  }
  start++;
 }
 num_elements_copied = j;
 spin_unlock_irqrestore(&finalbuf_lock, flags);
 pr_info("counter passed was :%ld, counter_buffer is:%d\n",
   counter_k, local_copy_counter_buffer);
 if ((copy_to_user(buf, buf_k, sizeof(struct pstrace)
   * PSTRACE_BUF_SIZE)) != 0) {
  kfree(buf_k);
  return -EFAULT;
 }
 kfree(buf_k);
 pr_info("Number of elements copied were :%ld\n", num_elements_copied);
 if (copy_to_user(counter, &num_elements_copied,
   sizeof(num_elements_copied)))
  return -EFAULT;
 pr_info("EXITING:pstrace_get\n");
 return 0;
}
/*
 * Given a pid
 */
void update_ring_buffer(pid_t pid_to_delete)
{
 int i;
 int last_non_match;
 last_non_match = 0;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (pstrace_buffer[i].pid != pid_to_delete)
   pstrace_buffer[last_non_match++] = pstrace_buffer[i];
  else {
   spin_lock(&num_deleted_lock);
   num_deleted++;
   spin_unlock(&num_deleted_lock);
  }
 }
 for (i = last_non_match; i < PSTRACE_BUF_SIZE; i++)
  pstrace_buffer[i].pid = INVALID_PID;
}
bool target_pid_sleeping(pid_t pid)
{
 struct counter_list *iter;
 if (list_empty(&target_counters))
  return false;
 if (pid == -1)
  return true;
 list_for_each_entry(iter, &target_counters, llist) {
  if (iter->traced_pid == pid)
   return true;
 }
 return false;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 *
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 unsigned long flags;
 to_be_woken_get = pid;
 check_and_wakeup_for_clear();
 //now final_buf has the latest snapshot of pstrace_buf
 if (pid == -1) {
  spin_lock(&num_deleted_lock);
  num_deleted = atomic_read(&counter_buffer);
  spin_unlock(&num_deleted_lock);
 } else {
  spin_lock_irqsave(&pstracebuf_lock, flags);
  update_ring_buffer(pid);
  spin_unlock_irqrestore(&pstracebuf_lock, flags);
 }
 return 0;
}