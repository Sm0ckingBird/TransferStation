// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h> /* pid_t */
#include <linux/pstrace.h>
#include <linux/syscalls.h> /* SYSCALL_DEFINE */
#include <linux/semaphore.h> /* semaphore */
#include <linux/string.h> /* strncpy, memcpy */
#include <linux/spinlock.h> /* spin_lock */
#include <linux/errno.h> /* error codes */
#include <linux/sched.h> /* task_struct */
#include <linux/sched/task.h> /* init_task */
#include <linux/rcupdate.h> /* rcu_read_lock */
#include <linux/sched.h>  /* state numbers */
#include <linux/uaccess.h> /* copy to and from user */
/*
 * IMPORTANT: if two locks need to be acquired together,
 * acquire ringbuf_lock before goals_lock.
 */
/* The ring buffer. */
static struct pstrace_buf ringbuf;
/* ringbuf should only be accessed via the following functions. */
void pstrace_add(struct task_struct *p, long state);
static long pstrace_reset(int reset_counter);
static long pstrace_get_imm(struct pstrace *buf, long *counter);
static long pstrace_get_goal(struct pstrace *buf, long *counter);
/*
 * All accesses to ringbuf need to consult the spinlock.
 * We're not defining it inside struct pstrace_buf to avoid
 * the need of dynamic initialization.
 */
static DEFINE_SPINLOCK(ringbuf_lock);
/*
 * Flags for storing interrupt states prior to entering ringbuf_lock.
 * Set by spin_lock_irqsave and restored by spin_unlock_irqrestore.
 */
static unsigned long ringbuf_lock_irq_flags;
/* List of pending pstrace_get goals. */
static struct pstrace_goal goal_head = {
 .goal = 0,
 .list = LIST_HEAD_INIT(goal_head.list)
};
/* All accesses to the list of goals should consult the spinlock. */
static DEFINE_SPINLOCK(goals_lock);
/*
 * The lock needed to access @add_flag and @add_pid
 */
static DEFINE_SPINLOCK(enable_disable_lock);
/*
 * Global variables needed in order to have pstrace_add work
 * @add_flag is 0 by default since pstrace_add is DISABLED by default
 * @add_pid controls what pid we are paying attention to (-1 if all)
 */
static int add_flag;
static pid_t add_pid;
/*
 * Checks to make sure that we have a valid pid
 *
 * A valid pid is either a pid of an existing process or -1
 * to denote any process.
 *
 * Believe you need to grab the rcu_read_lock in order to check the pid is valid
 *
 * Returns 1 if the pid is valid and 0 otherwise
 */
static int check_pid(pid_t pid)
{
 struct task_struct *tsk;
 rcu_read_lock();
 tsk = pid == 0 ? &init_task : find_task_by_vpid(pid);
 rcu_read_unlock();
 return pid == -1 || tsk != NULL;
}
/*
 * Should be called with ringbuf_lock held.
 * Copies entries indexed between [begin, end) from ringbuf to buf.
 * buf should be a kernel buffer of the correct size,
 * no checking is performed here.
 * When begin == end, the entire ringbuf is copied.
 */
static void pstrace_copy_entries(struct pstrace *buf, long begin, long end)
{
 struct pstrace *dest = buf;
 long i = begin;
 struct pstrace *src;
 do {
  src = &(ringbuf.buf[i].val);
  strncpy(dest->comm, src->comm, 16);
  dest->state = src->state;
  dest->pid = src->pid;
  dest->tid = src->tid;
  ++dest;
  i = (i + 1) % PSTRACE_BUF_SIZE;
 } while (i != end);
}
/*
 * System call to enable pstrace_add.
 *
 * Checks that pid is valid and if so, atomically sets add_flag and add_pid
 *
 * I do not think we need the __user modifier because we are not writing to @pid
 *
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t __user, pid)
{
 int pid_valid;
 pr_info("Performing pid check");
 pid_valid = check_pid(pid);
 if (!pid_valid)
  return -ESRCH;
 pr_info("Pid %d was valid", pid);
 pr_info("Attempting to acquire spin lock in order to enable trace");
 spin_lock(&enable_disable_lock);
 add_flag = 1;
 add_pid = pid;
 spin_unlock(&enable_disable_lock);
 pr_info("Enabled trace successfully");
 return 0;
}
/*
 * Atomically resets the flags
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 pr_info("Attempting to acquire spin lock in order to disable tracing");
 spin_lock(&enable_disable_lock);
 add_flag = 0;
 add_pid = 0;
 spin_unlock(&enable_disable_lock);
 pr_info("Successfully disabled tracing");
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 struct pstrace *kbuf;
 long kcounter;
 long ret = 0;
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 if (kcounter < 0)
  return -EINVAL;
 kbuf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (kbuf == NULL)
  return -ENOMEM;
 if (kcounter == 0)
  ret = pstrace_get_imm(kbuf, &kcounter);
 else if (kcounter > 0)
  ret = pstrace_get_goal(kbuf, &kcounter);
 if (ret < 0)
  goto free_exit;
 if (put_user(kcounter, counter)) {
  ret = -EFAULT;
  goto free_exit;
 }
 if (copy_to_user(buf, kbuf, sizeof(struct pstrace) * ret)) {
  ret = -EFAULT;
  goto free_exit;
 }
free_exit:
 kfree(kbuf);
 return ret;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 struct pstrace_goal *entry;
 wait_queue_head_t **wq;
 long list_size = 0;
 long i = 0;
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 spin_lock_irq(&goals_lock);
 list_for_each_entry(entry, &(goal_head.list), list)
  ++list_size;
 /* RISK: Calling kmalloc holding lock! */
 wq = kmalloc_array(list_size, sizeof(wait_queue_head_t *), GFP_KERNEL);
 if (wq == NULL) {
  spin_unlock_irq(&goals_lock);
  spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
  return -ENOMEM;
 }
 list_for_each_entry(entry, &(goal_head.list), list) {
  *(wq + i) = &(entry->wq);
  entry->size = ringbuf.size;
  entry->counter = ringbuf.counter;
  if (ringbuf.size == PSTRACE_BUF_SIZE)
   pstrace_copy_entries(&(entry->result[0]), ringbuf.next,
          ringbuf.next);
  else if (ringbuf.size > 0)
   pstrace_copy_entries(&(entry->result[0]), 0, ringbuf.next);
  entry->valid = 1;
  ++i;
 }
 ringbuf.size = 0;
 ringbuf.next = 0;
 spin_unlock_irq(&goals_lock);
 spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 for (i = 0; i < list_size; ++i)
  wake_up_all(*(wq + i));
 kfree(wq);
 return 0;
}
/* Acquires RCU lock before reading task_struct. */
static void get_pstrace_from_task(struct pstrace *p, struct task_struct *tsk)
{
 rcu_read_lock();
 get_task_comm(p->comm, tsk);
 p->pid = task_tgid_vnr(tsk);
 p->tid = task_pid_vnr(tsk);
 rcu_read_unlock();
}
static wait_queue_head_t *reach_goal(long goal)
{
 struct pstrace_goal *entry;
 wait_queue_head_t *wq;
 spin_lock_irq(&goals_lock);
 list_for_each_entry(entry, &(goal_head.list), list) {
  if (entry->goal == goal)
   break;
 }
 if (entry->goal != goal) {
  wq = NULL;
  goto unlock_out;
 }
 wq = &(entry->wq);
 entry->size = ringbuf.size;
 entry->counter = ringbuf.counter;
 if (ringbuf.size == PSTRACE_BUF_SIZE)
  pstrace_copy_entries(&(entry->result[0]), ringbuf.next,
         ringbuf.next);
 else
  pstrace_copy_entries(&(entry->result[0]), 0, ringbuf.next);
 entry->valid = 1;
unlock_out:
 spin_unlock_irq(&goals_lock);
 return wq;
}
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace *entry;
 wait_queue_head_t *wq;
 /* Only execute if add_flag set and pid is tracked */
 if (!add_flag)
  return;
 if (p == NULL) {
  pr_info("pstrace: NULL task transitioned to %ld\n", state);
  return;
 }
 if ((add_pid != p->pid) && (add_pid != -1))
  return;
 if ((state == TASK_RUNNABLE) || (state == TASK_RUNNING) ||
     (state == TASK_INTERRUPTIBLE) || (state == TASK_UNINTERRUPTIBLE) ||
     (state == __TASK_STOPPED) || (state == TASK_DEAD)) {
  /* Unsupported for now */
  pr_info("dummy pstrace add: %d, %ld\n", p->pid, state);
  return;
 }
 pr_info("pstrace add: %d, %ld, counter: %ld\n",
  p->pid, state, ringbuf.counter + 1);
 /* acquire lock */
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 /* get a pointer to the next entry in ringbuf */
 entry = &(ringbuf.buf[ringbuf.next].val);
 /* fill the pstrace entry */
 get_pstrace_from_task(entry, p);
 entry->state = state;
 /* update counter for the current entry */
 ringbuf.buf[ringbuf.next].counter = ringbuf.counter + 1;
 ++ringbuf.counter;
 ringbuf.next = (ringbuf.next + 1) % PSTRACE_BUF_SIZE;
 /* don't increase size if ringbuf is full */
 if (ringbuf.size < PSTRACE_BUF_SIZE)
  ++ringbuf.size;
 /* check for pstrace_get waiters */
 wq = reach_goal(ringbuf.counter);
 /* release lock */
 spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 if (wq)
  wake_up_all(wq);
}
/*
 * Resets the ringbuf counter when @reset_counter is non-zero.
 */
static long pstrace_reset(int reset_counter)
{
 /* acquire lock */
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 ringbuf.size = 0;
 ringbuf.next = 0;
 if (reset_counter)
  ringbuf.counter = 0;
 /* release lock */
 spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 return 0;
}
/*
 * The (*counter = 0) implementation of pstrace_get:
 *
 * Copies the entire ring buffer immediately and returns
 * number of entries copied.
 * 
 * buf should be a kernel buffer of the correct size,
 * no checking is performed here.
 * 
 * counter should also be a kernel space pointer.
 */
static long pstrace_get_imm(struct pstrace *buf, long *counter)
{
 long entries_copied;
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 if (ringbuf.size < PSTRACE_BUF_SIZE)
  pstrace_copy_entries(buf, 0, ringbuf.next);
 else
  pstrace_copy_entries(buf, ringbuf.next, ringbuf.next);
 entries_copied = ringbuf.size;
 *counter = ringbuf.counter;
 spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 return entries_copied;
}
/*
 * Adds a goal to the list if it doesn't already exist.
 * Then puts itself to wait until the goal is reached.
 *
 * Returns 0 on success.
 * May fail if kmalloc fails or interrupted during wait.
 * Returns -ENOMEM and -EINTR respectively.
 */
static long add_goal_and_wait(long goal, struct pstrace_goal **entry)
{
 long ret = 0;
 spin_lock_irq(&goals_lock);
 pr_info("checking goals for %ld\n", goal);
 /* check if someone is already waiting on this goal */
 list_for_each_entry((*entry), &(goal_head.list), list) {
  if ((*entry)->goal == goal)
   break;
 }
 /* add the goal to list if it doesn't exist */
 if ((*entry)->goal != goal) {
  pr_info("adding goal %ld\n", goal);
  /* RISK: Calling kmalloc holding lock! */
  *entry = kmalloc(sizeof(struct pstrace_goal), GFP_KERNEL);
  if (*entry == NULL) {
   ret = -ENOMEM;
   goto out;
  }
     (*entry)->goal = goal;
  (*entry)->valid = 0;
  (*entry)->reference = 0;
  init_waitqueue_head(&((*entry)->wq));
  list_add_tail(&((*entry)->list), &(goal_head.list));
 }
 pr_info("goal %ld in list\n", goal);
 ++((*entry)->reference);
 ret = wait_event_interruptible_lock_irq((*entry)->wq, (*entry)->valid,
      goals_lock);
 if (ret == -ERESTARTSYS)
  ret = -EINTR;
 pr_info("finished waiting: %ld\n", ret);
out:
 spin_unlock_irq(&goals_lock);
 return ret;
}
/*
 * After the goal has been reached, copies the result and counter from
 * the goal entry. Also deletes entry if no more references.
 */
static long fetch_goal(struct pstrace *buf, long *counter,
         struct pstrace_goal *entry)
{
 long entries_copied;
 spin_lock_irq(&goals_lock);
 entries_copied = entry->size;
 *counter = entry->counter;
 memcpy(buf, &(entry->result[0]),
        entries_copied * sizeof(struct pstrace));
 --(entry->reference);
 if (entry->reference == 0) {
  /* 
   * Wait queue should be empty because everyone must have left
   * the queue before they could decrease the reference counter.
   */
  list_del(&(entry->list));
  kfree(entry);
 }
 spin_unlock_irq(&goals_lock);
 return entries_copied;
}
static long mod_buf_size(long val)
{
 while (val < 0)
  val += PSTRACE_BUF_SIZE;
 return val % PSTRACE_BUF_SIZE;
}
/*
 * Acquire ringbuf_lock before entering this function.
 *
 * In this case, ringbuf.counter > goal > PSTRACE_BUF_SIZE.
 * But it's possible that ringbuf.size < PSTRACE_BUF_SIZE.
 */
static long pstrace_get_goal_imm(struct pstrace *buf, long *counter)
{
 /* the last entry we want to return */
 long goal = *counter + PSTRACE_BUF_SIZE;
 /* smallest counter value in ringbuf */
 long first_counter = ringbuf.counter - ringbuf.size + 1;
 /* we'll copy indices [begin, end) from ringbuf */
 long begin, end;
 if (ringbuf.size == 0 || goal < first_counter) {
  *counter = ringbuf.counter;
  return 0;
 }
 /* now we're sure that first_counter <= goal < ringbuf.counter */
 end = mod_buf_size(ringbuf.next - (ringbuf.counter - goal));
 begin = mod_buf_size(ringbuf.next - ringbuf.size);
 pstrace_copy_entries(buf, begin, end);
 *counter = ringbuf.buf[mod_buf_size(end - 1)].counter;
 return mod_buf_size(end - begin);
}
/*
 * The (*counter > 0) implementation of pstrace_get:
 *
 * Doesn't return until the ringbuf counter reaches a certain goal.
 * 
 * If the ringbuf counter reached the goal at this precise moment,
 * the function immediately copies from the current ringbuf and returns.
 * Otherwise, it adds an entry to the list of goals and waits for the
 * event to happen in the future.
 * 
 * buf should be a kernel buffer of the correct size,
 * no checking is performed here.
 * 
 * counter should also be a kernel space pointer.
 */
static long pstrace_get_goal(struct pstrace *buf, long *counter)
{
 long ret;
 /* the last entry we want to return */
 long goal = *counter + PSTRACE_BUF_SIZE;
 struct pstrace_goal *entry;
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 if (goal < ringbuf.counter) {
  pr_info("pstrace_get_goal case 1\n");
  ret = pstrace_get_goal_imm(buf, counter);
  spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 } else if (goal == ringbuf.counter) {
  pr_info("pstrace_get_goal case 2\n");
  if (ringbuf.size < PSTRACE_BUF_SIZE)
   pstrace_copy_entries(buf, 0, ringbuf.next);
  else
   pstrace_copy_entries(buf, ringbuf.next, ringbuf.next);
  *counter = goal;
  ret = ringbuf.size;
  spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 } else {
  pr_info("pstrace_get_goal case 3\n");
  /* the wait case */
  spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
  ret = add_goal_and_wait(goal, &entry);
  pr_info("returned from add_goal_and_wait: %ld\n", ret);
  pr_info("entry: %p, wq: %p\n", entry, &(entry->wq));
  if (ret)
   return ret;
  ret = fetch_goal(buf, counter, entry);
  pr_info("returned from fetch_goal: %ld\n", ret);
 }
 return ret;
}
/*********************************************************************/
/* Code below for debugging purposes only, remove before submission. */
/*********************************************************************/
#define PSTRACE_DEBUG_ADD 0
#define PSTRACE_DEBUG_PRINT 1
#define PSTRACE_DEBUG_RESET 2
#define PSTRACE_DEBUG_LOCK 3
#define PSTRACE_DEBUG_UNLOCK 4
#define PSTRACE_DEBUG_GET 5
/* locates a task by find_task_by_vpid and adds to ringbuf */
static long pstrace_debug_add(int pid, long state)
{
 struct task_struct *tsk;
 if (pid < 0)
  return -EINVAL;
 if (pid == 0)
  tsk = &init_task;
 else
  tsk = find_task_by_vpid(pid);
 if (tsk == NULL)
  return -ESRCH;
 pstrace_add(tsk, state);
 return 0;
}
static long pstrace_debug_print(void)
{
 long begin, delta, i;
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 if (!ringbuf.size) {
  pr_info("ringbuf empty\n");
  spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
  return 0;
 }
 pr_info("size:%ld, next:%ld\n", ringbuf.size, ringbuf.next);
 if (ringbuf.size < PSTRACE_BUF_SIZE)
  begin = 0;
 else
  begin = ringbuf.next;
 for (delta = 0; delta < ringbuf.size; ++delta) {
  i = (begin + delta) % PSTRACE_BUF_SIZE;
  pr_info("%ld,%ld: %s,%ld,%d,%d\n", i, ringbuf.buf[i].counter,
         ringbuf.buf[i].val.comm,
         ringbuf.buf[i].val.state,
         ringbuf.buf[i].val.pid,
         ringbuf.buf[i].val.tid);
 }
 spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 return 0;
}
static long pstrace_debug_lock(void)
{
 spin_lock_irqsave(&ringbuf_lock, ringbuf_lock_irq_flags);
 return 0;
}
static long pstrace_debug_unlock(void)
{
 spin_unlock_irqrestore(&ringbuf_lock, ringbuf_lock_irq_flags);
 return 0;
}
static long pstrace_debug_get_imm(void)
{
 long counter = 0;
 long entries_copied;
 long i;
 struct pstrace *cur;
 struct pstrace *buf = kmalloc_array(PSTRACE_BUF_SIZE,
         sizeof(struct pstrace),
         GFP_KERNEL);
 entries_copied = pstrace_get_imm(buf, &counter);
 pr_info("entries copied: %ld, counter: %ld\n", entries_copied, counter);
 for (i = 0; i < entries_copied; ++i) {
  cur = buf + i;
  pr_info("%ld: %s,%ld,%d,%d\n", i, cur->comm, cur->state,
        cur->pid, cur->tid);
 }
 kfree(buf);
 return entries_copied;
}
static long pstrace_debug_get(int counter)
{
 if (counter == 0)
  return pstrace_debug_get_imm();
 return 0;
}
SYSCALL_DEFINE3(pstrace_debug, int, op, int, iarg1, int, iarg2)
{
 switch (op) {
 case PSTRACE_DEBUG_ADD:
  return pstrace_debug_add(iarg1, iarg2);
 case PSTRACE_DEBUG_PRINT:
  return pstrace_debug_print();
 case PSTRACE_DEBUG_RESET:
  return pstrace_reset(iarg1);
 case PSTRACE_DEBUG_LOCK:
  return pstrace_debug_lock();
 case PSTRACE_DEBUG_UNLOCK:
  return pstrace_debug_unlock();
 case PSTRACE_DEBUG_GET:
  return pstrace_debug_get(iarg1);
 default:
  return -EINVAL;
 }
}