#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/preempt.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/atomic.h>
/* Guards all global data structures */
static DEFINE_SPINLOCK(pstrace_lock);
/* Process tracing state */
DECLARE_HASHTABLE(enabled, 9); /* need pstrace_lock */
DECLARE_HASHTABLE(disabled, 9); /* need pstrace_lock */
bool trace_all_processes; /* need pstrace_lock */
/* Ring buf state */
struct pstrace *ring_buf; /* need pstrace_lock */
long ring_buffer_count; /* need pstrace_lock */
LIST_HEAD(get_waiters);
bool initialized; /* need pstrace_lock */
DECLARE_WAIT_QUEUE_HEAD(pstrace_evt);
/*
 * get_waiter represents a blocked get call.
 * get blocks when the buffer is not full.
 *
 * pid - the pid this get call cares about. may be -1, which represents all pids
 * lower - the lower bound (inclusive) of
 * the range of events that still need to be copied
 * upper - the upper bound (exclusive) of
 * the range of events that still need to be copied
 * n - the number of events that have already been copied to buf
 * buf - buffer of relevant pstrace events
 * get_waiters_list - list_head so get_waiters can be iterated over
 */
struct get_waiter {
 pid_t pid;
 long lower;
 long upper;
 int n;
 struct list_head get_waiters_list;
 struct pstrace buf[PSTRACE_BUF_SIZE];
};
struct hpid {
 int pid;
 struct hlist_node node;
};
static inline int is_process(struct task_struct *tsk)
{
 if (task_pid_vnr(tsk) == task_tgid_vnr(tsk))
  return 1;
 else
  return 0;
}
static inline bool is_process_enabled(int pid)
{
 struct hpid *cur;
 hash_for_each_possible(enabled, cur, node, pid) {
  if (cur->pid == pid)
   return true;
 }
 return false;
}
static inline bool is_process_disabled(int pid)
{
 struct hpid *cur;
 hash_for_each_possible(disabled, cur, node, pid) {
  if (cur->pid == pid)
   return true;
 }
 return false;
}
static inline void add_to_enabled(int pid)
{
 struct hpid *new_process;
 new_process = kmalloc(sizeof(struct hpid), GFP_KERNEL);
 new_process->pid = pid;
 hash_add(enabled, &new_process->node, pid);
}
static inline void add_to_disabled(int pid)
{
 struct hpid *new_process;
 new_process = kmalloc(sizeof(struct hpid), GFP_KERNEL);
 new_process->pid = pid;
 hash_add(disabled, &new_process->node, pid);
}
static inline void remove_from_enabled(int pid)
{
 struct hpid *cur;
 struct hlist_node *tmp;
 hash_for_each_possible_safe(enabled, cur, tmp, node, pid) {
  if (cur->pid == pid) {
   hash_del(&cur->node);
   kfree(cur);
  }
 }
}
static inline void remove_from_disabled(int pid)
{
 struct hpid *cur;
 struct hlist_node *tmp;
 hash_for_each_possible_safe(disabled, cur, tmp, node, pid) {
  if (cur->pid == pid) {
   hash_del(&cur->node);
   kfree(cur);
  }
 }
}
int maybe_initialize(void)
{
 unsigned long lock_flags;
 spin_lock_irqsave(&pstrace_lock, lock_flags);
 if (initialized) {
  spin_unlock_irqrestore(&pstrace_lock, lock_flags);
  return 0;
 }
 hash_init(enabled);
 hash_init(disabled);
 ring_buf = kmalloc(
   sizeof(struct pstrace) * PSTRACE_BUF_SIZE,
   GFP_KERNEL);
 if (!ring_buf) {
  spin_unlock_irqrestore(&pstrace_lock, lock_flags);
  return -ENOMEM;
 }
 initialized = true;
 spin_unlock_irqrestore(&pstrace_lock, lock_flags);
 return 0;
}
bool is_process_traced(pid_t pid)
{
 if (trace_all_processes)
  return !is_process_disabled(pid);
 else
  return is_process_enabled(pid);
}
void add_helper(struct pstrace *p)
{
 struct list_head *tmp;
 struct get_waiter *gw;
 ring_buf[ring_buffer_count % PSTRACE_BUF_SIZE] = *p;
 list_for_each(tmp, &get_waiters) {
  gw = list_entry(tmp, struct get_waiter, get_waiters_list);
  /* check if this get_waiter cares about the data I will write */
  if (gw->lower <= ring_buffer_count
   && ring_buffer_count < gw->upper) {
   if (gw->pid == -1 || gw->pid == p->pid) {
    gw->buf[gw->n] = ring_buf[ring_buffer_count
       % PSTRACE_BUF_SIZE];
    gw->n++;
   }
   gw->lower = ring_buffer_count + 1;
  }
 }
 ring_buffer_count++;
}
/*
 * Copycomm
 * Used to copy comm from temp storage to ring buffer.
 */
void copycomm(char *srccomm, char *destcomm)
{
 int i;
 if (srccomm)
  for (i = 0; i < 16; i++)
   destcomm[i] = srccomm[i];
}
void pstrace_trace(struct pstrace *entry)
{
 struct pstrace *new_entry;
 /* this is a weird thing to do...rethink this */
 new_entry = &ring_buf[ring_buffer_count % PSTRACE_BUF_SIZE];
 new_entry->pid = entry->pid;
 new_entry->state = entry->state;
 copycomm(entry->comm, new_entry->comm);
 add_helper(new_entry);
}
void pstrace_add(struct task_struct *p)
{
 unsigned long flags;
 long ppid;
 unsigned long lock_flags;
 struct pstrace entry;
 local_irq_save(flags);
 preempt_disable();
 local_irq_disable();
 entry.pid = p->pid;
 if (p->exit_state == 0) {
  if (p->state == 0
   || p->state & TASK_INTERRUPTIBLE
   || p->state & TASK_UNINTERRUPTIBLE
   || p->state & TASK_STOPPED)
   entry.state = p->state;
  else if (p->state == TASK_WAKING)
   entry.state = 0;
  else {
   local_irq_restore(flags);
   preempt_enable();
   return;
  }
 } else
  entry.state = p->exit_state;
 get_task_comm(entry.comm, p);
 spin_lock_irqsave(&pstrace_lock, lock_flags);
 if (!initialized) {
  spin_unlock_irqrestore(&pstrace_lock, lock_flags);
  return;
 }
 if (p->pid == p->tgid) {
  ppid = entry.pid;
  if (is_process_traced(ppid))
   pstrace_trace(&entry);
 }
 spin_unlock_irqrestore(&pstrace_lock, lock_flags);
 preempt_enable();
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct hpid *cur;
 struct hlist_node *tmp;
 struct task_struct *tsk = NULL;
 unsigned int bkt;
 unsigned long lock_flags;
 maybe_initialize();
 read_lock(&tasklist_lock);
 spin_lock_irqsave(&pstrace_lock, lock_flags);
 if (pid == -1) {
  hash_for_each_safe(disabled, bkt, tmp, cur, node) {
   hash_del(&cur->node);
   kfree(cur);
  }
  trace_all_processes = true;
 } else {
  tsk = find_task_by_vpid(pid);
  if (!tsk) {
   spin_unlock_irqrestore(&pstrace_lock, lock_flags);
   read_unlock(&tasklist_lock);
   return -EINVAL;
  }
  if (!is_process(tsk))
   pid = task_tgid_vnr(tsk);
  if (!is_process_enabled(pid)) {
   if (is_process_disabled(pid))
    remove_from_disabled(pid);
   add_to_enabled(pid);
  }
 }
 spin_unlock_irqrestore(&pstrace_lock, lock_flags);
 read_unlock(&tasklist_lock);
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 struct hpid *cur;
 struct hlist_node *tmp;
 struct task_struct *tsk = NULL;
 unsigned int bkt;
 unsigned long lock_flags;
 maybe_initialize();
 read_lock(&tasklist_lock);
 spin_lock_irqsave(&pstrace_lock, lock_flags);
 if (pid == -1) {
  hash_for_each_safe(enabled, bkt, tmp, cur, node) {
   hash_del(&cur->node);
   kfree(cur);
  }
  trace_all_processes = false;
 } else {
  tsk = find_task_by_vpid(pid);
  if (!tsk) {
   spin_unlock_irqrestore(&pstrace_lock, lock_flags);
   read_unlock(&tasklist_lock);
   return -EINVAL;
  }
  if (!is_process(tsk))
   pid = task_tgid_vnr(tsk);
  if (!is_process_disabled(pid)) {
   if (is_process_enabled(pid))
    remove_from_enabled(pid);
   add_to_disabled(pid);
  }
 }
 spin_unlock_irqrestore(&pstrace_lock, lock_flags);
 read_unlock(&tasklist_lock);
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid,
 struct pstrace __user *, buf,
 long __user *, counter)
{
 int i, idx, n;
 long cnt, lower, upper;
 unsigned long lock_flags;
 struct get_waiter *waiter;
 if (copy_from_user(&cnt, counter, sizeof(long)))
  return -EFAULT;
 waiter = kmalloc(sizeof(struct get_waiter), GFP_KERNEL);
 if (!waiter)
  return -ENOMEM;
 maybe_initialize();
 spin_lock_irqsave(&pstrace_lock, lock_flags);
 /* initialize get_waiter */
 waiter->pid = pid;
 if (cnt <= 0) {
  waiter->lower = ring_buffer_count - PSTRACE_BUF_SIZE;
  waiter->upper = ring_buffer_count;
 } else {
  waiter->lower = cnt;
  waiter->upper = cnt + PSTRACE_BUF_SIZE;
  if (cnt + PSTRACE_BUF_SIZE < ring_buffer_count) {
   waiter->lower = ring_buffer_count;
   waiter->upper = ring_buffer_count;
  }
 }
 waiter->n = 0;
 lower = waiter->lower < ring_buffer_count - PSTRACE_BUF_SIZE
  ? ring_buffer_count - PSTRACE_BUF_SIZE
  : waiter->lower;
 if (lower < 0)
  lower = 0;
 upper = ring_buffer_count < waiter->upper
  ? ring_buffer_count
  : waiter->upper;
 /* iterate over ring_buf and copy relevant fields to ret */
 for (i = lower; i < upper; i++) {
  idx = i % PSTRACE_BUF_SIZE;
  if (ring_buf[idx].pid != -1
   && (pid == -1 || ring_buf[idx].pid == pid)) {
   waiter->buf[waiter->n] = ring_buf[idx];
   waiter->n++;
  }
 }
 waiter->lower = waiter->lower > upper ? waiter->lower : upper;
 /*
  * If we are still waiting on events, sleep until the buffer is full.
  */
 if (waiter->lower < waiter->upper) {
  list_add(&waiter->get_waiters_list, &get_waiters);
  for (;;) {
   /* wait for max 1s */
   wait_event_lock_irq_timeout(pstrace_evt,
     waiter->lower >= waiter->upper,
     pstrace_lock, HZ);
   if (waiter->lower == waiter->upper)
    break;
  }
  /*
   * Now we should have all the info needed ready in get_waiter
   */
  list_del(&waiter->get_waiters_list);
 }
 spin_unlock_irqrestore(&pstrace_lock, lock_flags);
 if (copy_to_user(buf, waiter->buf,
  sizeof(struct pstrace) * waiter->n)) {
  kfree(waiter);
  return -EFAULT;
 }
 if (copy_to_user(counter, &waiter->upper, sizeof(long))) {
  kfree(waiter);
  return -EFAULT;
 }
 n = waiter->n;
 kfree(waiter);
 return n;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the given pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i;
 unsigned long lock_flags;
 struct list_head *tmp;
 struct get_waiter *gw;
 if (pid < -1)
  return -EINVAL;
 maybe_initialize();
 spin_lock_irqsave(&pstrace_lock, lock_flags);
 /* modify get_waiters so they will
  * return immediately when they next wake up
  * then iterate over get_waiters and
  * copy in data that they are waiting for.
  */
 list_for_each(tmp, &get_waiters) {
  gw = list_entry(tmp, struct get_waiter, get_waiters_list);
  if (pid == -1 || gw->pid == -1 || pid == gw->pid) {
   gw->lower = ring_buffer_count;
   gw->upper = ring_buffer_count;
  }
 }
 /* actually do the clear */
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  if (pid == -1 || ring_buf[i].pid == pid)
   ring_buf[i].pid = -1;
 spin_unlock_irqrestore(&pstrace_lock, lock_flags);
 /* wake up all get_waiters */
 wake_up_all(&pstrace_evt);
 return 0;
}