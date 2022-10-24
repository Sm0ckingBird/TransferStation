/*
 * linux/kernel/pstrace.c
 *
 * Implements the pstrace_enable, pstrace_disable and
 * pstrace_get system calls as part of W4118 OS A3
 */
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/atomic-fallback.h>
#include <linux/slab.h>
#include <linux/pstrace.h>
#include <linux/wait.h>
#include <linux/rwlock.h>
#define PSTRACE_BUF_SIZE 500    /* size of the ring buffer */
#define ALL 1
#define NOT_ALL 0
DEFINE_RWLOCK(pstrace_buf_lock);   /* lock for ring buffer */
DEFINE_RWLOCK(traced_p_lock);      /* lock for list of traced processes */
DEFINE_RWLOCK(waiting_list_lock);  /* lock for waiting list */
DEFINE_RWLOCK(recursive_lock);
/* ring buffer */
struct pstrace pstrace_buf[PSTRACE_BUF_SIZE];
/* list head for list of disabled (when TRACING = ALL) OR */
/* traced processes (when TRACING = NOT_ALL) */
static LIST_HEAD(traced_p_list);
/* list head for waiting records */
static LIST_HEAD(waiting_list);
/* are we tracing all processes 0 (some) or 1 (all) */
int TRACING = NOT_ALL;
/* persistent count of number of records added to buffer */
atomic_t record_count = ATOMIC_INIT(0);
/* wait queue to for taks to wait on until requested records are found */
DECLARE_WAIT_QUEUE_HEAD(wait_queue);
/**
 * Returns a task struct for a task specified by pid.
 */
static struct task_struct *get_task_by_pid(pid_t pid)
{
 struct task_struct *t;
 if (pid == 0)
  return &init_task;
 rcu_read_lock();
 t = find_task_by_vpid(pid);
 rcu_read_unlock();
 return t;
}
/**
 * Dumps the list of traced pids from the traced_p_list
 * and sets the value of tracing global variable.
 * Lock is acquired before making changes.
 */
void dump_traced_pid_list_and_set_tracing(int trace_all)
{
 struct traced_process *p;
 struct traced_process *next;
 write_lock(&traced_p_lock);
 if (trace_all != TRACING) {
  list_for_each_entry_safe(p, next, &traced_p_list, list) {
   list_del(&p->list);
   kfree(p);
  }
  TRACING = trace_all;
 }
 write_unlock(&traced_p_lock);
}
/**
 * Are we currently trying to trace the process identified
 * by this pid? Returns 1 if process should be traced,
 * 0 otherwise. Note that both the traced_p_list and tracing
 * locks should be acquired before using this function.
 */
int currently_tracing(pid_t pid)
{
 struct traced_process *p;
 int in_traced_list = 0;
 list_for_each_entry(p, &traced_p_list, list) {
  if (p->pid == pid) {
   in_traced_list = 1;
   break;
  }
 }
 /* if tracing everything, traced_list is a disabled list */
 /* if tracing only some things, traced_list is an enabled list */
 if (!in_traced_list && TRACING == ALL)
  return 1;
 else if (in_traced_list && TRACING == ALL)
  return 0;
 else if (in_traced_list)
  return 1;
 else
  return 0;
}
/**
 * Enables pstrace tracing for user-specified pid
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct traced_process *new_traced_process;
 /* trace all pids condition */
 if (pid == -1) {
  dump_traced_pid_list_and_set_tracing(ALL);
  return 0;
 }
 /* does the pid actually exist? */
 if (pid < -1 || get_task_by_pid(pid) == NULL)
  return -ESRCH;
 new_traced_process = kmalloc(sizeof(struct traced_process),
   GFP_KERNEL);
 if (new_traced_process == NULL)
  return -ENOMEM;
 /* are we already tracing this pid? if so, we shouldn't re-add it */
 /* we also don't need to add it if we are already tracing everything */
 write_lock(&traced_p_lock);
 if (currently_tracing(pid)) {
  kfree(new_traced_process);
 } else {
  new_traced_process->pid = pid;
  list_add(&new_traced_process->list, &traced_p_list);
 }
 write_unlock(&traced_p_lock);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 struct traced_process *p;
 struct traced_process *next;
 struct traced_process *new_disabled_process;
 /* Disable tracing for any currently traced pids */
 if (pid == -1) {
  dump_traced_pid_list_and_set_tracing(NOT_ALL);
  return 0;
 }
 new_disabled_process = kmalloc(sizeof(struct traced_process),
   GFP_KERNEL);
 if (new_disabled_process == NULL)
  return -ENOMEM;
 write_lock(&traced_p_lock);
 if (TRACING == ALL) {
  new_disabled_process->pid = pid;
  list_add(&new_disabled_process->list, &traced_p_list);
 } else {
  /* we will not need this memory anymore, just deleting here */
  kfree(new_disabled_process);
  /* remove the pid from list of enabled pids */
  list_for_each_entry_safe(p, next, &traced_p_list, list) {
   if (p->pid == pid) {
    list_del(&p->list);
    kfree(p);
    break;
   }
  }
 }
 write_unlock(&traced_p_lock);
 return 0;
}
/**
 * Helper function for determining what records should or should not
 * go into the kernel buffer. If the pid of the record doesn't match,
 * the record has been cleared (and we don't want cleared records) or
 * if the pid is beyond the full buffer condition, then don't add it.
 * When full_buf_condition is set to -1, it indicates that there is no
 * limit on record id to return; otherwise, we only want to include
 * records up to a certain record id.
 */
int include_record(struct pstrace *record, int pid, int full_buf_condition,
  int include_cleared)
{
 if (pid != -1 && record->pid != pid)
  return 0;
 else if (!include_cleared && record->cleared)
  return 0;
 else if (full_buf_condition != -1 && full_buf_condition < record->id)
  return 0;
 return 1;
}
/**
 * Populates the kernel pstrace result buffer with the relevant
 * contents from the pstrace ring buffer (i.e., only results relevant
 * to the specified pid or all records if pid = -1). Note that this
 * function requires use of a read-lock on the pstrace_buf_lock. Records
 * are copied to the kernel buffer in order.
 *
 * Returns the number of records moved into the kernel buffer.
 */
int populate_kernel_pstrace_buf(struct pstrace kresult_buf[], int pid,
  int full_buf_condition, int include_cleared)
{
 int idx_oldest_record;
 int highest_idx;
 int i = 0;
 int j = 0; /* represents the number of records copied */
 int n_records;
 /* Get the current record count; since we have a read lock on the */
 /* pstrace buffer when this method is called, we know there can't be */
 /* writes to it and consequently record_count also not incremented */
 n_records = atomic_read(&record_count);
 /* We have no records; the counter of last record is 0*/
 if (n_records == 0)
  return 0;
 if (n_records < PSTRACE_BUF_SIZE) {
  idx_oldest_record = 0;
  highest_idx = n_records - 1;
 } else {
  idx_oldest_record = n_records % PSTRACE_BUF_SIZE;
  highest_idx = PSTRACE_BUF_SIZE - 1;
 }
 /* add the records to the kernel buffer, starting from oldest */
 for (i = idx_oldest_record; i <= highest_idx; i++) {
  if (include_record(&pstrace_buf[i], pid, full_buf_condition,
     include_cleared)) {
   memcpy(&kresult_buf[j], &pstrace_buf[i],
     sizeof(struct pstrace));
   j++;
  }
 }
 for (i = 0; i < idx_oldest_record; i++) {
  if (include_record(&pstrace_buf[i], pid, full_buf_condition,
     include_cleared)) {
   memcpy(&kresult_buf[j], &pstrace_buf[i],
     sizeof(struct pstrace));
   j++;
  }
 }
 return j;
}
/**
 * Creates a new waiter, an task that is waiting
 * on a list for a specific task.
 */
struct waiter *create_new_waiter(pid_t pid)
{
 struct waiter *new_waiter;
 new_waiter = kmalloc(sizeof(struct waiter), GFP_KERNEL);
 if (!new_waiter)
  return NULL;
 new_waiter->pid = task_pid_nr(current);
 new_waiter->waiting_on = pid;
 new_waiter->dequeue_flag = 0;
 return new_waiter;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  int __user *, counter)
{
 int counter_v;
 int last_counter_v;
 int full_buf_condition = 0;
 int n_records_added = 0;
 struct pstrace *kresult_buf;
 struct waiter *waiter = NULL;
 int ret = 0;
 int include_cleared = 0;
 struct wait_queue_entry entry;
 if (pid < -1 || (pid != -1 && !currently_tracing(pid)))
  return -ESRCH;
 if (copy_from_user(&counter_v, counter, sizeof(int)))
  return -EFAULT;
 /* create a buffer to hold intermediate results */
 kresult_buf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace),
   GFP_KERNEL);
 if (!kresult_buf)
  return -ENOMEM;
 full_buf_condition = counter_v > 0 ? counter_v + PSTRACE_BUF_SIZE : -1;
 last_counter_v = atomic_read(&record_count);
 /* scenario where record count has gone beyond counter specified */
 if (counter_v > 0 && full_buf_condition <
   last_counter_v - PSTRACE_BUF_SIZE) {
  if (copy_to_user(counter, &last_counter_v, sizeof(int)))
   ret = -EFAULT;
  goto cleanup;
 }
 /* wait scenario, buffer isn't ready */
 if (counter_v > 0 && full_buf_condition > last_counter_v) {
  waiter = create_new_waiter(pid);
  if (!waiter) {
   ret = -ENOMEM;
   goto cleanup;
  }
  /* add new entry in our list_waiting list */
  write_lock(&waiting_list_lock);
  list_add(&waiter->list, &waiting_list);
  write_unlock(&waiting_list_lock);
  /* wait until either (1) the full_buf_condition is met */
  /* (2) pstrace_clear was called on a pid of interest */
  init_wait_entry(&entry, 0);
  add_wait_queue(&wait_queue, &entry);
  read_lock(&waiting_list_lock);
  while (atomic_read(&record_count) < full_buf_condition &&
    waiter->dequeue_flag == 0) {
   prepare_to_wait(&wait_queue, &entry,
     TASK_INTERRUPTIBLE);
   read_unlock(&waiting_list_lock);
   schedule();
   read_lock(&waiting_list_lock);
  }
  finish_wait(&wait_queue, &entry);
  include_cleared = waiter->dequeue_flag;
  read_unlock(&waiting_list_lock);
 }
 /* immediately grab read lock to get all necessary records */
 read_lock(&pstrace_buf_lock);
 /* get record count again, it may have incremented, and fill buffer */
 last_counter_v = atomic_read(&record_count);
 n_records_added = populate_kernel_pstrace_buf(kresult_buf, pid,
   full_buf_condition, include_cleared);
 read_unlock(&pstrace_buf_lock);
 if (copy_to_user(buf, kresult_buf,
    sizeof(struct pstrace) * n_records_added)) {
  ret = -EFAULT;
  goto cleanup;
 }
 if (copy_to_user(counter, &last_counter_v, sizeof(int))) {
  ret = -EFAULT;
  goto cleanup;
 }
cleanup:
 kfree(kresult_buf);
 /* delete from waiting list, if waiting was required */
 if (waiter) {
  write_lock(&waiting_list_lock);
  list_del(&waiter->list);
  kfree(waiter);
  write_unlock(&waiting_list_lock);
 }
 return ret;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i;
 int max_idx;
 struct waiter *w;
 if (pid < -1)
  return -ESRCH;
 /* Update the list_waiting */
 /* if pid = -1, then set all flags in list waiting to 1 (true) */
 /* if pid is specified, switch on flags only items waiting on pid */
 write_lock(&waiting_list_lock);
 list_for_each_entry(w, &waiting_list, list) {
  if (w->waiting_on == pid || pid == -1)
   w->dequeue_flag = 1;
 }
 write_unlock(&waiting_list_lock);
 /* soft clear all records by setting their cleared field to yes */
 write_lock(&pstrace_buf_lock);
 if (atomic_read(&record_count) < PSTRACE_BUF_SIZE)
  max_idx = atomic_read(&record_count);
 else
  max_idx = PSTRACE_BUF_SIZE;
 for (i = 0; i < max_idx; i++) {
  if (pid == -1 || pstrace_buf[i].pid == pid)
   pstrace_buf[i].cleared = 1;
 }
 write_unlock(&pstrace_buf_lock);
 /* for some reason this actually never wakes anything up */
 wake_up(&wait_queue);
 return 0;
}
/**
 * Does the task have a state that we are currently
 * trying to trace? Returns 0 if no, 1 if yes.
 */
int traced_state_change(struct task_struct *p)
{
 if (((p->state & TASK_INTERRUPTIBLE) != 0)  ||
     ((p->state & TASK_UNINTERRUPTIBLE) != 0) ||
     p->state == TASK_RUNNING ||
     task_is_stopped(p))  /* __TASK_STOPPED case */
  return 1;
 /* TASK_DEAD and EXIT ZOMBIE produce duplicate records */
 else if ((p->state != TASK_DEAD && p->exit_state == EXIT_ZOMBIE) ||
   (p->exit_state == EXIT_DEAD))
  return 1;
 return 0;
}
/**
 * Add state changes to the pstrace_buf for a given task.
 * Only tasks that are being traced will have their state
 * changes added to the buffer (either the task is on the list
 * of tasks being traced OR all tasks are currently being traced).
 */
void pstrace_add(struct task_struct *p)
{
 struct pstrace new_trace;
 int new_idx;
 int tracing_pid = 1;
 unsigned long flags;
 int recursive = 0;
 struct waiter *w;
 /* do we even need to trace this task's state changes? */
 local_irq_save(flags);
 read_lock(&traced_p_lock);
 tracing_pid = currently_tracing(task_pid_nr(p));
 read_unlock(&traced_p_lock);
 if (!tracing_pid || !traced_state_change(p)) {
  local_irq_restore(flags);
  return;
 }
 /* convert task struct information into the pstrace struct */
 rcu_read_lock();
 write_lock(&pstrace_buf_lock);
 new_trace.pid = task_pid_nr(p);
 new_trace.state = p->state;
 new_trace.exit_state = p->exit_state ? p->exit_state : 0;
 new_trace.cleared = 0;
 new_trace.id = atomic_read(&record_count) + 1;
 get_task_comm(new_trace.comm, p);
 /* add the new trace to the pstrace_buf and increment records seen */
 new_idx = atomic_read(&record_count) % PSTRACE_BUF_SIZE;
 memcpy(&pstrace_buf[new_idx], &new_trace, sizeof(new_trace));
 atomic_inc(&record_count); /* only place count is incremented*/
 write_unlock(&pstrace_buf_lock);
 /* determine if we are in a recursive case */
 read_lock(&waiting_list_lock);
 list_for_each_entry(w, &waiting_list, list) {
  if (w->pid == task_pid_nr(p)) {
   recursive = 1;
   break;
  }
 }
 read_unlock(&waiting_list_lock);
 rcu_read_unlock();
 /* don't call wake_up if in recursive case */
 if (!recursive)
  wake_up(&wait_queue);
 local_irq_restore(flags);
}