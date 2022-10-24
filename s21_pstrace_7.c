/*
 * W4118 OS homework 3,
 * Diyue Gu(dg3198), Yunkai Tang(yt2696), Hengjiu kang(hk3120)
 */
#include <asm-generic/barrier.h>
#include <linux/circ_buf.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/pstrace.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
/* #define DEBUG_OUTPUT */
#ifdef DEBUG_OUTPUT
#define DEBUG_PRINTK(f_, ...) \
 printk((f_), ##__VA_ARGS__)
#else
#define DEBUG_PRINTK(f_, ...) do { } while (0)
#endif
enum tracing_mode_enum {
 TRACING_DISABLED,
 TRACING_ALL,
 TRACING_SELECTIVE,
};
enum pstrace_wake_reason_enum {
 PSTRACE_WAKE_NO,
 PSTRACE_WAKE_NORMAL,
 PSTRACE_WAKE_DUMP,
};
struct pstrace_tree_node {
 struct rb_node node;
 char comm[16];
 pid_t pid;  /* The pid of the process */
 long state;  /* The state of the process */
 bool valid;
 wait_queue_head_t qeurer;
 enum pstrace_wake_reason_enum wake_reason;
};
/* global data structure (using circular buffer) to trace the processes */
static atomic_long_t awaiting_querers;
static DEFINE_SPINLOCK(pstrace_lock);
static struct pstrace_tree_node *pstrace_buf;
static long pstrace_head;
static enum pstrace_wake_reason_enum pstrace_wake_reason = PSTRACE_WAKE_NORMAL;
static DEFINE_SPINLOCK(tracing_list_lock);
static enum tracing_mode_enum tracing_mode = TRACING_DISABLED;
static struct rb_root tracing_rbtree = RB_ROOT;
static DECLARE_WAIT_QUEUE_HEAD(global_wq_head);
static DECLARE_WAIT_QUEUE_HEAD(logistic_queue_head);
/* helper functions for ring buffer */
void sleep_exclusive(wait_queue_head_t *queue)
{
 struct wait_queue_entry wait;
 init_waitqueue_entry(&wait, current);
 current->state = TASK_INTERRUPTIBLE;
 add_wait_queue_exclusive(queue, &wait);
 schedule();
 remove_wait_queue (queue, &wait);
}
static void *alloc_memory_slow(size_t size, size_t *allocated)
{
 unsigned int fls_result = fls(size);
 void *mem = NULL;
 if (!fls_result) {
  WARN_ON(true);
  return mem;
 }
 size = 1 << (fls_result - 1);
 while (!mem && size) {
  mem = kmalloc(size, GFP_KERNEL);
  *allocated = size;
  size >>= 1;
 }
 return mem;
}
void pstrace_init(void)
{
 size_t allocated;
 // TODO(Hengjiu): deal with kmalloc filed.
 pstrace_buf = (struct pstrace_tree_node *)kmalloc_array(
   PSTRACE_BUF_SIZE, sizeof(struct pstrace_tree_node),
   GFP_KERNEL);
 if (!pstrace_buf) {
  pstrace_buf = alloc_memory_slow(PSTRACE_BUF_SIZE
   * sizeof(struct pstrace_tree_node), &allocated);
  if (!pstrace_buf)
   return;
 }
 pstrace_head = 0;
 atomic_long_set(&awaiting_querers, 0);
}
EXPORT_SYMBOL_GPL(pstrace_init);
void pstrace_fill(struct pstrace_tree_node *node, struct task_struct *p)
{
 if (node == NULL || p == NULL)
  return;
 memcpy(node->comm, p->comm,
        TASK_COMM_LEN * sizeof(char));
 node->state = p->state | p->exit_state;
 node->pid = p->pid;
 node->valid = true;
 node->wake_reason = PSTRACE_WAKE_NORMAL;
}
void pstrace_invalidate_pid(struct pstrace_tree_node *pstrace_buf, pid_t pid)
{
 int i = 0;
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i) {
  if ((pstrace_buf[i].pid == pid) || (pid == -1))
   pstrace_buf[i].valid = false;
 }
}
/* helper functions for tracing_list */
static struct pstrace_tree_node *tracing_list_get_task(
 struct rb_root *root, pid_t pid);
static struct pstrace_tree_node *tracing_list_get_task(
 struct rb_root *root, pid_t pid)
{
 struct rb_node *node = NULL;
 if (root == NULL)
  return NULL;
 node = root->rb_node;
 while (node) {
  struct pstrace_tree_node *data =
   container_of(node, struct pstrace_tree_node, node);
  if (data->pid > pid)
   node = node->rb_left;
  else if (data->pid < pid)
   node = node->rb_right;
  else
   return data;
 }
 return NULL;
}
/* this function will try to insert
 * a new node with pid specified.
 * this function has lock.
 */
static bool tracing_list_insert_pid_lock(
 struct rb_root *root, pid_t pid)
{
 unsigned long flags;
 struct rb_node **new = &(root->rb_node);
 struct rb_node *parent = NULL;
 bool ret = false;
 struct pstrace_tree_node *new_node =
  (struct pstrace_tree_node *)kmalloc (
  sizeof(struct pstrace_tree_node), GFP_KERNEL);
 if (!new_node)
  return false;
 new_node->valid = true;
 new_node->pid = pid;
 init_waitqueue_head(&(new_node->qeurer));
 new_node->wake_reason = PSTRACE_WAKE_NORMAL;
 if (root == NULL) {
  ret = false;
  goto free_exit;
 }
 /* check if pid valid */
 if (find_get_pid(pid) == NULL) {
  ret = false;
  goto free_exit;
 }
 /* Figure out where to put new node */
 spin_lock(&tracing_list_lock);
 {
  while (*new) {
   struct pstrace_tree_node *this = container_of(
    *new, struct pstrace_tree_node, node);
   parent = *new;
   if (this->pid > pid) {
    new = &((*new)->rb_left);
   } else if (this->pid < pid) {
    new = &((*new)->rb_right);
   } else {
    ret = true;
    goto unlock_exit;
   }
  }
  /* Add new node and rebalance tree. */
  rb_link_node(&(new_node->node), parent, new);
  rb_insert_color(&(new_node->node), root);
  new_node = NULL;
 }
unlock_exit:
 spin_unlock(&tracing_list_lock);
 ret = true;
free_exit:
 if (new_node != NULL)
  kfree(new_node);
 return ret;
}
struct pstrace_tree_node *tracing_list_pop(struct rb_root *root, pid_t pid)
{
 struct pstrace_tree_node *node;
 if (root == NULL)
  return NULL;
 node = tracing_list_get_task(root, pid);
 if (node == NULL)
  return NULL;
 rb_erase(&(node->node), root);
 DEBUG_PRINTK("[pstrace] found and pop node\n");
 return node;
}
void tracing_list_erase(struct rb_root *root, pid_t pid)
{
 struct pstrace_tree_node *node = tracing_list_pop(root, pid);
 if (node != NULL)
  kfree(node);
}
void tracing_list_erase_all(struct rb_root *root)
{
 struct rb_node *node;
 struct pstrace_tree_node *post_node = NULL;
 if (root == NULL)
  return;
 node = rb_first(root);
 while (node) {
  rb_erase(node, root);
  post_node = container_of(
   node, struct pstrace_tree_node, node);
  node = rb_next(node);
  kfree(post_node);
 }
}
void tracing_list_invalidate_all(struct rb_root *root)
{
 struct rb_node *node;
 struct pstrace_tree_node *post_node = NULL;
 if (root == NULL)
  return;
 node = rb_first(root);
 while (node) {
  post_node = container_of(
   node, struct pstrace_tree_node, node);
  post_node->valid = false;
 }
}
/**
 * Check if we need to track current pid.
 * i.e if current pid can be found in the tracing_list.
 * it also handle disabled tracking or tracking all.
 * This function has built in lock
 */
static bool is_tracing_task_lock(
 struct rb_root *root, pid_t pid)
{
 bool ret = true;
 unsigned long flags;
 spin_lock(&tracing_list_lock);
 {
  if (tracing_mode == TRACING_DISABLED) {
   ret = false;
  } else if (tracing_mode == TRACING_ALL) {
   ret = true;
  } else if (tracing_mode == TRACING_SELECTIVE) {
   if (tracing_list_get_task(root, pid) != NULL)
    ret = true;
   else
    ret = false;
  }
 }
 spin_unlock(&tracing_list_lock);
 return ret;
}
/* helper functions for wait queue */
void pstrace_add(struct task_struct *p)
{
 struct pstrace_tree_node *tracing_node = NULL;
 unsigned long flags;
 if (unlikely(p == NULL) || unlikely(pstrace_buf == NULL)) {
  /* did not aquire lock at this moment */
  return;
 }
 if (is_tracing_task_lock(&tracing_rbtree, p->pid) == true) {
  DEBUG_PRINTK("[%s] entered for pid %d with state %ld, ",
   __func__, p->pid, p->state | p->exit_state);
  spin_lock(&pstrace_lock);
  {
   /* insert new record in ring buffer */
   /* wait_queue may be used, so use non-irq version */
   /* TODO(Hengjiu): what if head is overflow. */
   /* insert one item into the buffer */
   long head = pstrace_head;
   struct pstrace_tree_node *new_trace =
    &(pstrace_buf[head % PSTRACE_BUF_SIZE]);
   pstrace_fill(new_trace, p);
   WRITE_ONCE(pstrace_head, head + 1);
  }
  spin_unlock(&pstrace_lock);
  DEBUG_PRINTK("[%s] inserted to head for pid %d",
   __func__, p->pid);
  /* wake all process first. */
  spin_lock(&tracing_list_lock);
  tracing_node = tracing_list_get_task(&tracing_rbtree, p->pid);
  spin_unlock(&tracing_list_lock);
  DEBUG_PRINTK("[%s] got tracing node for pid %d",
   __func__, p->pid);
  if (tracing_node != NULL) {
   DEBUG_PRINTK("[%s] waking up local querer pid %d",
    __func__, p->pid);
   wake_up_all(&(tracing_node->qeurer));
  }
  DEBUG_PRINTK("[%s] waking up global querer: %ld",
   __func__, atomic_long_read(&awaiting_querers));
  DEBUG_PRINTK("[%s] recorded pid: %d with state %ld, ", __func__,
   p->pid, p->state | p->exit_state);
  return;
 }
 DEBUG_PRINTK("[%s] skipped pid: %d with state %ld, ", __func__,
  p->pid, p->state | p->exit_state);
}
EXPORT_SYMBOL_GPL(pstrace_add);
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 * If start from init, and pid = -1, tracing_mode = TRACING_ALL;
 * if start from init, and pid != -1, tracking_mode = TRACKING_SELECTIVE;
 * from ALL to SELECTIVE, only care about what are in the tracing_list
 * from selective to all, all will overwrite selective.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flags;
 /* sanity check */
 /* init pstrace_buf at the first time we need it */
 if (pid == -1) {
  spin_lock(&tracing_list_lock);
  tracing_mode = TRACING_ALL;
  spin_unlock(&tracing_list_lock);
 } else {
  if (find_get_pid(pid) != NULL) {
   tracing_mode = TRACING_SELECTIVE;
   if (tracing_list_insert_pid_lock(
    &tracing_rbtree, pid)){
    return 0;
   } else {
    return -EFAULT;
   }
  } else {
   /* does not find pid */
   return -EINVAL;
  }
 }
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 struct pstrace_tree_node *node = NULL;
 unsigned long flags;
 DEBUG_PRINTK("[pstrace_disable] In pstrace_disable %d", pid);
 if (pid == -1) {
  struct rb_root temp_tracing_rbtree = tracing_rbtree;
  spin_lock(&tracing_list_lock);
  {
   tracing_mode = TRACING_DISABLED;
   tracing_rbtree = RB_ROOT;
  }
  spin_unlock(&tracing_list_lock);
  tracing_list_erase_all(&temp_tracing_rbtree);
  DEBUG_PRINTK("[pstrace_disable] has erased all tracing items");
 } else {
  spin_lock(&tracing_list_lock);
  {
   DEBUG_PRINTK("[pstrace_disable] wantto disable %d\n",
    pid);
   node = tracing_list_pop(&tracing_rbtree, pid);
  }
  spin_unlock(&tracing_list_lock);
  if (node != NULL) {
   DEBUG_PRINTK("[pstrace_disable] has erased item for %d",
    pid);
   kfree(node);
  } else {
   /* pid not found */
   return -EINVAL;
  }
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid,
 struct pstrace __user *, buf, long __user *, counter)
{
 struct pstrace buf_out;
 struct pstrace_tree_node *node;
 long user_counter = 0;
 long out_counter = 0;
 long counter_lb = 0;
 long counter_hb = 0;
 long copy_to_user_ret = 0;
 unsigned long flags;
 DEBUG_PRINTK("[pstrace_get] In for pid %d", pid);
 if (!buf || !counter)
  return -EINVAL;
 if (access_ok(counter, sizeof(long)) != 1
  && access_ok(
  buf, PSTRACE_BUF_SIZE * sizeof(struct pstrace)) != 1)
  return -EFAULT;
 if (get_user(user_counter, counter) != 0)
  return -EFAULT;
 if (user_counter < 0)
  return -EINVAL;
 /* put my self to sleep. This should also support wake up
  * due to calling of pstrace_clear
  * need to check if pids are in the bound
  * if pid == -1, just sleep and wait for awaking or event
  */
 if (pid != -1) {
  spin_lock(&tracing_list_lock);
  node = tracing_list_get_task(&tracing_rbtree, pid);
  if (node == NULL) {
   DEBUG_PRINTK("[pstrace_get] pid %d not in list", pid);
   spin_unlock(&tracing_list_lock);
   return -EINVAL;
  }
  spin_unlock(&tracing_list_lock);
  atomic_long_inc(&awaiting_querers);
  /* this process can also be waken by pstrace_clear */
  if (READ_ONCE(pstrace_head)
   < user_counter + PSTRACE_BUF_SIZE) {
   DEBUG_PRINTK("[pstrace_get]  will fall asleep %d",
    node->pid);
   wait_event_interruptible((node->qeurer),
   (READ_ONCE(pstrace_head) >=
   user_counter + PSTRACE_BUF_SIZE)
   || (READ_ONCE(pstrace_wake_reason) == PSTRACE_WAKE_DUMP)
   || (READ_ONCE(node->wake_reason) == PSTRACE_WAKE_DUMP));
  }
  DEBUG_PRINTK("[pstrace_get] has been waken up, now head: %ld",
   pstrace_head);
 } else {
  atomic_long_inc(&awaiting_querers);
  if (READ_ONCE(pstrace_head)
   < user_counter + PSTRACE_BUF_SIZE) {
   DEBUG_PRINTK("[pstrace_get] will fall asleep -1");
   while ((READ_ONCE(pstrace_head) >=
    user_counter + PSTRACE_BUF_SIZE)
    || (pstrace_wake_reason == PSTRACE_WAKE_DUMP)) {
    wait_event_interruptible_timeout(
     global_wq_head, 0,
     msecs_to_jiffies(100));
   }
  }
  DEBUG_PRINTK("[pstrace_get] has been waken up, now head: %ld",
   pstrace_head);
 }
 /* copy from circ buf to user space */
 spin_lock(&pstrace_lock);
 {
  counter_hb = pstrace_head;
  if (counter_hb < PSTRACE_BUF_SIZE) {
   counter_lb = 0;
  } else {
   counter_lb = (counter_hb + PSTRACE_BUF_SIZE + 1)
    % PSTRACE_BUF_SIZE;
   counter_hb = counter_lb + PSTRACE_BUF_SIZE;
  }
  while (counter_lb <= counter_hb) {
   node = &(pstrace_buf[
    (counter_lb++) % PSTRACE_BUF_SIZE]);
   if ((pid != -1) && (pid != node->pid))
    continue;
   if (node->valid == false)
    continue;
   memcpy(buf_out.comm, node->comm, 16 * sizeof(char));
   buf_out.pid = node->pid;
   buf_out.state = node->state;
   copy_to_user_ret = copy_to_user(
    &(buf[out_counter]), &buf_out,
    sizeof(struct pstrace));
   if (copy_to_user_ret > 0) {
    /* cannot write to user memory */
    out_counter = -EFAULT;
    break;
   }
   out_counter++;
  }
 }
 spin_unlock(&pstrace_lock);
 put_user(counter_hb, counter);
 atomic_long_dec_return(&awaiting_querers);
 wake_up_all(&logistic_queue_head);
 DEBUG_PRINTK("[pstrace_get] returned %ld records for %d",
  counter_hb, pid);
 return out_counter;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
void pstrace_clear_one(struct pstrace_tree_node *tracing_node)
{
 if (tracing_node == NULL)
  return;
 DEBUG_PRINTK("[pstrace_clear] got tracing_node for %d",
  tracing_node->pid);
 if (!list_empty(&(tracing_node->qeurer.head))) {
  DEBUG_PRINTK("[pstrace_clear] try to wakeup %d",
   tracing_node->pid);
  tracing_node->wake_reason = PSTRACE_WAKE_DUMP;
  wake_up_all(&(tracing_node->qeurer));
  DEBUG_PRINTK("[pstrace_clear] waiting for qeuerer finish");
  /* someone is waiting for this node */
  wait_event_interruptible(logistic_queue_head,
   list_empty(&(tracing_node->qeurer.head)));
 }
 kfree(tracing_node);
 DEBUG_PRINTK("[pstrace_clear] Done in clear one tracing node");
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 long ret = 0;
 struct pstrace_tree_node *tracing_node = NULL;
 struct rb_node *raw_node = NULL;
 unsigned long flags;
 DEBUG_PRINTK("[pstrace_clear] In pstrace_clear for %d", pid);
 if (pid == -1) {
  /* label all tracing_list items with valid = false; */
  DEBUG_PRINTK("[pstrace_clear] wanted to dump all tracing: %ld",
   READ_ONCE(pstrace_head));
  spin_lock(&pstrace_lock);
  tracing_mode = TRACING_DISABLED;
  pstrace_wake_reason = PSTRACE_WAKE_DUMP;
  spin_unlock(&pstrace_lock);
  while (true) {
   spin_lock(&tracing_list_lock);
   raw_node = rb_first(&tracing_rbtree);
   if (!raw_node) {
           spin_unlock(
     &tracing_list_lock);
    break;
   }
   DEBUG_PRINTK("[pstrace_clear] wake single in list: %ld",
    atomic_long_read(&awaiting_querers));
   rb_erase(raw_node, &tracing_rbtree);
          spin_unlock(&tracing_list_lock);
   tracing_node = container_of(
    raw_node, struct pstrace_tree_node, node);
   pstrace_clear_one(tracing_node);
  }
  DEBUG_PRINTK("[pstrace_clear] wake global: %ld",
    atomic_long_read(&awaiting_querers));
  wake_up_all(&global_wq_head);
  DEBUG_PRINTK("[pstrace_clear] sleep until everyone done");
  /* sleep until all the get finished their work */
  if (atomic_long_read(&awaiting_querers) > 0) {
   wait_event_interruptible(logistic_queue_head,
    atomic_long_read(&awaiting_querers) <= 0);
  }
  DEBUG_PRINTK("[pstrace_clear]  found everyone done");
  /* clear tracing list */
  spin_lock(&tracing_list_lock);
  tracing_list_erase_all(&tracing_rbtree);
  spin_unlock(&tracing_list_lock);
  /* invalidate pstrace_buf */
  spin_lock(&pstrace_lock);
  pstrace_invalidate_pid(pstrace_buf, -1);
  pstrace_head = 0;
  pstrace_wake_reason = PSTRACE_WAKE_NORMAL;
  spin_unlock(&pstrace_lock);
 } else {
  spin_lock(&tracing_list_lock);
  tracing_node =
   tracing_list_pop(&tracing_rbtree, pid);
  if (!tracing_node)
   ret = -EINVAL;
  spin_unlock(&tracing_list_lock);
  pstrace_clear_one(tracing_node);
  spin_lock(&pstrace_lock);
  pstrace_invalidate_pid(pstrace_buf, pid);
  spin_unlock(&pstrace_lock);
 }
 DEBUG_PRINTK("[pstrace_clear] pstrace_clear done for pid %d", pid);
 return ret;
}