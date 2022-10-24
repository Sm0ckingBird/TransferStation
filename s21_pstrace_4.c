// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/types.h> /* pid_t */
#include <linux/pstrace.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
#define DISABLED_TREE 0
#define TRACED_TREE 1
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
/*
 * LOCKS
 */
static DEFINE_RWLOCK(pbuf_rwlock); /* rw lock for buffer and pcounter*/
static DEFINE_RWLOCK(tp_rwlock); /* protects the rbtrees/counter */
/* Lock protecting sleepers list. The seqlock is used so that any processes
 * waiting to complete pstrace_get (writers) are favored over the process that
 * woke them up (the reader)
 */
static DEFINE_SEQLOCK(sleepers_lock);
/*
 * GLOBAL VARIABLES
 */
static struct pstrace pstrace_buf[PSTRACE_BUF_SIZE]; /* buffer for tracing */
static atomic64_t pcounter = ATOMIC64_INIT(0); /* count # of processes in buf */
static struct rb_root traced_pids = RB_ROOT; /* tracks which pids are traced */
static struct rb_root disabled_pids = RB_ROOT; /* tracks currently disabled */
static atomic_t tcounter = ATOMIC_INIT(0); /* counter for traced pids */
static atomic_t trace_all = ATOMIC_INIT(0); /* trace all PIDs */
static LIST_HEAD(sleepers_list); /* processes waiting for buffer to fill */
/* Return the pid_trace object if a pid is currently being traced. Otherwise
 * return NULL
 */
static struct pid_trace *find_pid_trace(pid_t pid, int tree);
/* Inserts the pid_trace into the global tracing rbtree. Returns 0 if inserted
 * successully, returns -1 if not (already in tree).
 */
static int insert_pid_trace(struct pid_trace *p, int tree);
/*
 * sys_pstrace_enable
 * Enables tracing for @pid. If -1 is given, enable tracing for all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 short found = 0;
 struct pid_trace *trace_p;
 struct pid_trace *disable_p = NULL;
 struct task_struct *task;
 if (pid < -1)
  return -EINVAL;
 if (pid == -1) {
  struct pid_trace *curr;
  struct pid_trace *next;
  /* Clear the disabled tree */
  write_lock(&tp_rwlock);
  atomic_set(&trace_all, 1);
  rbtree_postorder_for_each_entry_safe(
   curr, next, &disabled_pids, rb_node) {
   pr_notice("Erasing PID=%d in disable tree", curr->pid);
   rb_erase(&curr->rb_node, &disabled_pids);
   kfree(curr);
  }
  write_unlock(&tp_rwlock);
  pr_notice("Tracing all processes.\n");
  return 0;
 }
 /* Only trace a PID if that task already exists */
 read_lock(&tasklist_lock);
 for_each_process(task) {
  if (task_tgid_vnr(task) == pid) {
   found = 1;
   break;
  }
 }
 read_unlock(&tasklist_lock);
 if (!found) {
  pr_notice("Process %d doesn't exist. Cannot trace.\n", pid);
  return -EINVAL;
 }
 /* allocate the node container */
 trace_p = kmalloc(sizeof(struct pid_trace), GFP_KERNEL);
 if (!trace_p)
  return -ENOMEM;
 trace_p->pid = pid;
 /* INSERT: the PID into the traced_pids tree */
 write_lock(&tp_rwlock);
 pr_notice("Currently tracing %d processes.", atomic_read(&tcounter));
 if (atomic_read(&tcounter) >= PSTRACE_BUF_SIZE) {
  write_unlock(&tp_rwlock);
  pr_warn("Already tracing max num of processes\n");
  kfree(trace_p);
  return -EINVAL;
 }
 /* Decrement outside of insert_pid_trace because insert is used for
  * disable as well.
  */
 if (insert_pid_trace(trace_p, TRACED_TREE) != -1) {
  pr_warn("PID=%d is not in the traced tree!", pid);
  atomic_inc(&tcounter);
 }
 pr_notice("pstrace_enable success on PID=%d", pid);
 /* REMOVE: the PID from the disabled_pids tree */
 disable_p = find_pid_trace(pid, DISABLED_TREE);
 if (disable_p) {
  pr_notice("Found PID=%d in disabled tree. Deleting...\n", pid);
  rb_erase(&disable_p->rb_node, &disabled_pids);
  write_unlock(&tp_rwlock);
  kfree(disable_p);
  return 0;
 }
 pr_notice("Didn't find PID=%d in disabled tree.\n", pid);
 write_unlock(&tp_rwlock);
 return 0;
}
/*
 * sys_pstrace_disable
 * Disables tracing for @pid. If -1 is given, stop tracing for all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 struct pid_trace *trace_p = NULL;
 struct pid_trace *disable_p;
 if (pid < -1)
  return -EINVAL;
 if (pid == -1) {
  struct pid_trace *curr;
  struct pid_trace *next;
  write_lock(&tp_rwlock);
  atomic_set(&trace_all, 0);
  atomic_set(&tcounter, 0);
  /* Clear the traced tree of all its traced PIDs */
  rbtree_postorder_for_each_entry_safe(
   curr, next, &traced_pids, rb_node) {
   pr_notice("Erasing PID=%d from traced tree", curr->pid);
   rb_erase(&curr->rb_node, &traced_pids);
   kfree(curr);
  }
  pr_notice("Now tracing %d processes", atomic_read(&tcounter));
  write_unlock(&tp_rwlock);
  pr_notice("Disabled tracing on all processes.\n");
  return 0;
 }
 /* allocate the node container */
 disable_p = kmalloc(sizeof(struct pid_trace), GFP_KERNEL);
 if (!disable_p)
  return -ENOMEM;
 disable_p->pid = pid;
 /* INSERT: the PID into the disabled_pids tree */
 write_lock(&tp_rwlock);
 pr_notice("Currently tracing %d processes.", atomic_read(&tcounter));
 if (insert_pid_trace(disable_p, DISABLED_TREE) == -1)
  pr_warn("PID=%d is already in the disabled tree!", pid);
 pr_notice("pstrace_disable success on PID=%d", pid);
 /* REMOVE: the PID from the traced_pids tree */
 trace_p = find_pid_trace(pid, TRACED_TREE);
 if (trace_p) {
  pr_notice("Found PID=%d in enabled tree. Deleting...\n", pid);
  atomic_dec(&tcounter);
  rb_erase(&trace_p->rb_node, &traced_pids);
  write_unlock(&tp_rwlock);
  kfree(trace_p);
  return 0;
 }
 pr_notice("Didn't find PID=%d in enabled tree.\n", pid);
 write_unlock(&tp_rwlock);
 return 0;
}
/*
 * sys_pstrace_get
 * Copy the pstrace ring buffer info @buf.
 * If @pid == -1, copy all records; otherwise, only copy records of @pid.
 * If @counter > 0, the caller process will wait until a full buffer can
 * be returned after record @counter (i.e. return record @counter + 1 to
 * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
 *
 * Returns the number of records copied.
 */
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter)
{
 long kcounter, save_counter, i, j;
 int ret = 0;
 int new_sleeper = 1;
 struct list_head *p;
 struct sleeper *this, *tmp = NULL;
 wait_queue_head_t *q; /* the queue we will sleep on if we sleep */
 struct pstrace *kbuf;
 DEFINE_WAIT(wait);
 if (pid < -1 || copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
 /* Immediately copy whole buffer back to userspace */
 if (kcounter <= 0)
  kcounter = -1; /* -1 because for loop takes kcounter - 1 */
 /* We want to allocate the memory before we grab the rwlock on buf*/
 kbuf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace),
        GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
 this = kmalloc(sizeof(struct sleeper), GFP_KERNEL);
 if (!this) {
  kfree(kbuf);
  return -ENOMEM;
 }
 read_lock(&pbuf_rwlock); /* for accessing the buffer */
 /* only sleep if the buffer hasn't reached kcounter + PSTRACE_BUF_SIZE
  * yet. Body of the if statement is the sleeping path.
  */
 if (kcounter > 0 && kcounter + PSTRACE_BUF_SIZE >
  atomic64_read(&pcounter)) {
  /* First find the wait_queue associated with our sleeper. The
   * sleeper structs are linked according to the counter they are
   * waiting for. The first sleeper is the one with the smallest
   * counter value. Then, if there isn't one already, we have to
   * insert an entry for waiting for our counter.
   */
  write_seqlock(&sleepers_lock);
  this->counter = kcounter + PSTRACE_BUF_SIZE;
  this->pid = pid;
  INIT_LIST_HEAD(&this->sleepers);
  /* Here we have to use list_for_each because, if the list is
   * empty, then list_for_each_entry will try to get list_entry of
   * the sleepers_list list_head which is not within any
   * structure. Also we want tmp to be NULL if the list is empty,
   * but list_for_each_entry will initialize it before it checks
   * the condition.
   */
  list_for_each(p, &sleepers_list) {
   tmp = list_entry(p, struct sleeper, sleepers);
   if (tmp->counter >= this->counter)
    break;
  }
  /* Now temp points to the node which has an equal counter as us
   * and so we should just add ourself to it, or we are the first
   * ones with this counter and we should create a new waitqueue
   */
  /* counter this process is waiting for */
  if (tmp == NULL) { /* the list is empty, need new node */
   pr_notice("Initiated the waitqueue list for counter = %ld\n"
     , kcounter + PSTRACE_BUF_SIZE);
   init_waitqueue_head(&this->q);
   q = &this->q;
   list_add(&this->sleepers, &sleepers_list);
   pr_notice("Finished initialization\n");
  } else if (tmp->counter != this->counter) { /* need new node */
   pr_notice("Added self (counter = %ld) right before counter %ld\n",
     this->counter, tmp->counter);
   init_waitqueue_head(&this->q);
   q = &this->q;
   if (tmp->counter > this->counter)
    list_add_tail(&this->sleepers, &tmp->sleepers);
   else /* we have the largest counter value */
    list_add(&this->sleepers, &tmp->sleepers);
  } else { /* found a similar waitqueue, no new node needed */
   pr_notice("Found another entry for counter %ld\n",
    kcounter);
   q = &tmp->q;
   new_sleeper = 0; /* Didn't add this to list */
  }
  /* Now that we've figured out the queue we should add ourselves
   * to, go on the queue and sleep until the counter reaches the
   * value we want
   */
  pr_notice("Preparing to queue self\n");
  add_wait_queue(q, &wait);
  set_current_state(TASK_INTERRUPTIBLE);
  pr_notice("Added self to queue: %p\n", q);
  /* Unlock because of schedule */
  write_sequnlock(&sleepers_lock);
  read_unlock(&pbuf_rwlock);
  pr_notice("Going to sleep\n");
  schedule();
  if (signal_pending(current)) { /* clean up and exit */
   if (new_sleeper) {
    write_seqlock(&sleepers_lock);
    list_del(&this->sleepers);
    write_sequnlock(&sleepers_lock);
   }
   /* Both write and seqlock unlocked, so free */
   kfree(this);
   kfree(kbuf);
   return -EINVAL;
  }
  read_lock(&pbuf_rwlock);
  /* we will need this to remove our entry afterwards */
  write_seqlock(&sleepers_lock);
  finish_wait(q, &wait);
  pr_notice("Woken up!!\n");
  /* By now we have the counter has reached the value we want or
   * we have been prematurely woken up by a pstrace_clear call
   * we should remove ourselves from the sleepers list and free
   * the node if we are the one who created it
   */
  if (new_sleeper)
   list_del(&this->sleepers);
  write_sequnlock(&sleepers_lock);
  /* By now the buffer has reached the size we want so we can fall
   * through to the copying code and return
   */
 }
 pr_notice("Searching for %d. Copying for counter %ld\n from process %d",
   pid, kcounter, task_tgid_vnr(current));
 /* i iterates the pstrace_buf, j iterates the user-space buf */
 for (i = MAX(atomic64_read(&pcounter) - 501, kcounter + 1), j = 0;
     i <= MIN(atomic64_read(&pcounter) - 1, kcounter + PSTRACE_BUF_SIZE);
     i++) {
  struct pstrace cur = pstrace_buf[i % PSTRACE_BUF_SIZE];
  /* Continue if we're not looking for this PID...*/
  if (pid != -1 && cur.pid != pid)
   continue;
  /* ...OR if the PID is already cleared by pstrace_clear */
  if (cur.pid == -1)
   continue;
  kbuf[j++] = cur;
 }
 save_counter = atomic64_read(&pcounter);
 read_unlock(&pbuf_rwlock);
 /* copy the buffer and counter at time of read to user_space */
 if (copy_to_user(buf, kbuf, j * sizeof(struct pstrace)))
  ret = -EFAULT;
 if (!ret && copy_to_user(counter, &save_counter, sizeof(long)))
  ret = -EFAULT;
 pr_notice("Wrote %ld entries from pid %d\n", j, task_tgid_vnr(current));
 kfree(this);
 kfree(kbuf);
 if (ret)
  return ret;
 else
  return j;
}
/*
 * sys_pstrace_clear
 * Clear the pstrace buffer.
 * If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.
 * Cleared records should never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i; /* iterator for the pbuf when clearing entries */
 unsigned long seq;
 int waiter_exists = 0;
 /* Wake up the pstrace_get processes that are still waiting */
 do {
  do {
   struct sleeper *tmp = NULL;
   struct list_head *t;
   waiter_exists = 0;
   /* Grab the seq lock */
   seq = read_seqbegin(&sleepers_lock);
   /* Just take the next sleeper on the list */
   list_for_each(t, &sleepers_list) {
    tmp = list_entry(t, struct sleeper, sleepers);
    break;
   }
   /* Wake up the next process sleeping */
   if (tmp && (pid == -1 || tmp->pid == pid)) {
    waiter_exists = 1;
    pr_err("Waking pstrace_get for counter=%ld",
    tmp->counter);
    wake_up(&tmp->q);
   }
  /* Release the seq lock */
  } while (read_seqretry(&sleepers_lock, seq));
 } while (waiter_exists);
 /* Clear all intended entries in the pbuf */
 write_lock(&pbuf_rwlock);
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  /* -1 means that an entry has been cleared */
  if (pid == -1 || pstrace_buf[i].pid == pid)
   pstrace_buf[i].pid = -1;
 write_unlock(&pbuf_rwlock);
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 struct pstrace tmp;
 struct pid_trace *traced;
 struct pid_trace *disabled;
 long counter;
 unsigned long seq;
 int waiter_exists = 0;
 if (unlikely(!p))
  return;
 /* Make sure that this process has been pstrace_enabled (and NOT
  * pstrace_disabled)
  */
 read_lock(&tp_rwlock);
 /* If nothing is being traced, return immediately */
 if (!atomic_read(&tcounter) && !atomic_read(&trace_all)) {
  read_unlock(&tp_rwlock);
  return;
 }
 traced = find_pid_trace(p->pid, TRACED_TREE);
 disabled = find_pid_trace(p->pid, DISABLED_TREE);
 /* Condition to contiue:
  * (trace_all OR individually traced) AND NOT disabled
  */
 if (!(atomic_read(&trace_all) || traced) || disabled) {
  read_unlock(&tp_rwlock);
  return;
 }
 read_unlock(&tp_rwlock);
 rcu_read_lock();
 /* Prepare the struct pstrace */
 tmp.pid = task_tgid_vnr(p);
 get_task_comm(tmp.comm, p);
 /* EXIT_DEAD and EXIT_ZOMBIE */
 if (p->exit_state)
  tmp.state = p->exit_state;
 /* __TASK_STOPPED */
 else if (task_is_stopped(p))
  tmp.state = __TASK_STOPPED;
 /* TASK_UNINTERRUPTIBLE */
 else if ((p->state & TASK_UNINTERRUPTIBLE))
  tmp.state = TASK_UNINTERRUPTIBLE;
 /* TASK_INTERRUPTIBLE */
 else if ((p->state & TASK_INTERRUPTIBLE))
  tmp.state = TASK_INTERRUPTIBLE;
 /* TASK_RUNNING */
 else if (p->state == TASK_RUNNING)
  tmp.state = TASK_RUNNING;
 else {
  rcu_read_unlock();
  return;
 }
 rcu_read_unlock();
 /* save to buffer */
 write_lock(&pbuf_rwlock);
 counter = atomic64_read(&pcounter);
 pstrace_buf[counter % PSTRACE_BUF_SIZE] = tmp;
 atomic64_inc(&pcounter);    /* Counter always points to next empty */
 write_unlock(&pbuf_rwlock);
 pr_err("%s wrote %d to buffer!\n", __func__, tmp.pid);
 /* Now wake up any processes that are waiting for the buffer to reach
  * this specific counter value
  */
 do {
  do {
   struct sleeper *tmp = NULL;
   struct list_head *t;
   waiter_exists = 0;
   /* Grab the seq lock */
   seq = read_seqbegin(&sleepers_lock);
   /* We use list_for_each for the same reason as in
    * pstrace_get above
    */
   list_for_each(t, &sleepers_list) {
    tmp = list_entry(t, struct sleeper, sleepers);
    if (tmp->counter == counter)
     break;
   }
   /* wake up all the processes waiting for the counter
    * to reach this amount
    */
   if (tmp && tmp->counter == counter) {
    waiter_exists = 1;
    pr_err("Waking processes waiting for counter to reach: %ld",
    counter);
    wake_up(&tmp->q);
   }
  /* Release the seq lock */
  } while (read_seqretry(&sleepers_lock, seq));
 } while (waiter_exists);
 pr_notice("Logged: {pid: %d, comm: %s, state: %ld, counter: %ld}\n",
  tmp.pid, tmp.comm, tmp.state, counter);
}
/* Helper function that finds an entry of a pid in the tracing rbtree */
static struct pid_trace *find_pid_trace(pid_t pid, int tree)
{
 struct pid_trace *p;
 struct rb_node *node;
 if (tree)
  node = traced_pids.rb_node;
 else
  node = disabled_pids.rb_node;
 while (node) {
  p = container_of(node, struct pid_trace, rb_node);
  if (p->pid < pid)
   node = node->rb_left;
  else if (p->pid > pid)
   node = node->rb_right;
  else
   return p;
 }
 return NULL;
}
/* Inserts struct pid_trace into the global rbtree. Returns 0 if successfully
 * inserted, retunrs -1 if not (already in tree).
 */
int insert_pid_trace(struct pid_trace *p, int tree)
{
 struct rb_node **new;
 struct rb_node *parent = NULL;
 if (tree)
  new = &traced_pids.rb_node;
 else
  new = &disabled_pids.rb_node;
 while (*new) {
  pid_t tmp = container_of(*new, struct pid_trace, rb_node)->pid;
  parent = *new;
  if (p->pid < tmp)
   new = &((*new)->rb_right);
  else if (p->pid > tmp)
   new = &((*new)->rb_left);
  else {
   pr_notice("Aleady tracking pid: %d\n", p->pid);
   return -1;
  }
 }
 /* add the new node and rebalance the tree */
 rb_link_node(&p->rb_node, parent, new);
 if (tree)
  rb_insert_color(&p->rb_node, &traced_pids);
 else
  rb_insert_color(&p->rb_node, &disabled_pids);
 pr_notice("Added pid trace: %d\n", p->pid);
 return 0;
}