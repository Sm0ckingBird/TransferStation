#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kernel.h>
#define PSTRACE_BUF_SIZE 500
DECLARE_WAIT_QUEUE_HEAD(counter_queue);
DEFINE_SPINLOCK(counter_list_lock);
LIST_HEAD(counter_list);
struct counter_node {
 int condition;
 long counter;
 long last_rec_copy_counter;
 pid_t pid;
 int end;
 struct pstrace *snapshot;
 struct list_head list;
};
DEFINE_SPINLOCK(ring_buffer_lock);
struct rb_record {
 int active;
 struct pstrace record;
};
struct ring_buffer {
 long counter;
 int next;
 struct rb_record records[PSTRACE_BUF_SIZE];
} ring_buffer;
DEFINE_SPINLOCK(task_tracer_lock);
struct task_tracer {
 int size;
 int trace_all;
 struct list_head pid_list;
};
struct task_tracer tasks_traced = {
 .size = 0,
 .trace_all = 0,
 .pid_list = { &tasks_traced.pid_list, &tasks_traced.pid_list }
};
struct pid_node {
 int pid;
 struct list_head list;
};
int recursive_pstrace_add_call;
int ring_buffer_add(struct task_struct *p)
{
 int i;
 int counter;
 struct pstrace new;
 if (p->exit_state != 0)
  new.state = p->exit_state;
 else
  new.state = p->state;
 for (i = 0; i < (TASK_COMM_LEN < 16 ? TASK_COMM_LEN : 16); i++)
  new.comm[i] = p->comm[i];
 new.pid = p->pid;
 ring_buffer.records[ring_buffer.next].active = 1;
 ring_buffer.records[ring_buffer.next++].record = new;
 ring_buffer.next %= PSTRACE_BUF_SIZE;
 counter = ++ring_buffer.counter;
 return counter;
}
int do_ring_buffer_copy_to_kernel(int start, struct pstrace *target_buf,
      long *last_rec_copy_counter)
{
 int i, k;
 int j = 0;
 long rb_counter_start = max(0, (ring_buffer.counter -
   PSTRACE_BUF_SIZE));
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  k = (i + start) % PSTRACE_BUF_SIZE;
  if (ring_buffer.records[k].active) {
   target_buf[j++] = ring_buffer.records[k].record;
   *last_rec_copy_counter = rb_counter_start + i;
  }
 }
 return j;
}
int ring_buffer_copy_to_kernel(struct pstrace *target_buf,
  long *last_rec_copy_counter)
{
 if (ring_buffer.counter < PSTRACE_BUF_SIZE)
  return do_ring_buffer_copy_to_kernel(0, target_buf,
    last_rec_copy_counter);
 else
  return do_ring_buffer_copy_to_kernel(ring_buffer.next,
    target_buf,
    last_rec_copy_counter);
}
void ring_buffer_clear_all(void)
{
 int i;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  ring_buffer.records[i].active = 0;
}
void ring_buffer_clear_record(pid_t pid)
{
 int i;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (ring_buffer.records[i].record.pid == pid)
   ring_buffer.records[i].active = 0;
 }
}
int tasks_traced_pid_list_add(struct pid_node *new, pid_t pid)
{
 struct pid_node *node;
 new->pid = pid;
 INIT_LIST_HEAD(&new->list);
 list_for_each_entry(node, &tasks_traced.pid_list, list) {
  if (node->pid == pid)
   return 1;
 }
 list_add(&new->list, &tasks_traced.pid_list);
 tasks_traced.size++;
 return 0;
}
void tasks_traced_pid_list_del_all(void)
{
 struct pid_node *node, *next;
 list_for_each_entry_safe(node, next, &tasks_traced.pid_list, list) {
  list_del(&node->list);
  kfree(node);
 }
 tasks_traced.size = 0;
}
void tasks_traced_pid_list_del(pid_t pid)
{
 struct pid_node *node, *next;
 list_for_each_entry_safe(node, next, &tasks_traced.pid_list, list) {
  if (node->pid == pid) {
   list_del(&node->list);
   kfree(node);
   break;
  }
 }
 tasks_traced.size--;
}
int validate_state(struct task_struct *p)
{
 if (p->state == TASK_RUNNING ||
     task_is_interruptible(p) ||
     task_is_uninterruptible(p) ||
     task_is_stopped(p) ||
     p->exit_state == EXIT_ZOMBIE ||
     p->exit_state == EXIT_DEAD)
  return 1;
 else
  return 0;
}
int ps_is_traced(struct task_struct *p)
{
 struct pid_node *node;
 int is_on_pid_list = 0;
 if (!validate_state(p))
  return 0;
 list_for_each_entry(node, &tasks_traced.pid_list, list) {
  if (node->pid == p->pid) {
   is_on_pid_list = 1;
   break;
  }
 }
 return tasks_traced.trace_all ^ is_on_pid_list;
}
/*
 * Method to record state in ring buffer.
 * If valid: lock, insert, unlock.
 */
void pstrace_add(struct task_struct *p)
{
 unsigned long flags;
 int is_traced;
 int wake_counter_queue = 0;
 long counter;
 struct counter_node *node, *next;
 spin_lock_irqsave(&task_tracer_lock, flags);
 is_traced = ps_is_traced(p);
 spin_unlock_irqrestore(&task_tracer_lock, flags);
 if (!is_traced)
  return;
 spin_lock_irqsave(&ring_buffer_lock, flags);
 counter = ring_buffer_add(p);
 spin_unlock(&ring_buffer_lock);
 spin_lock(&counter_list_lock);
 list_for_each_entry_safe(node, next, &counter_list, list) {
  if ((node->counter == counter) && !node->condition) {
   node->end = ring_buffer_copy_to_kernel(
     node->snapshot,
     &node->last_rec_copy_counter);
   node->condition = 1;
   wake_counter_queue = 1;
   list_del(&node->list);
  }
 }
 spin_unlock_irqrestore(&counter_list_lock, flags);
 if (wake_counter_queue && !recursive_pstrace_add_call) {
  recursive_pstrace_add_call = 1;
  wake_up_all(&counter_queue);
 }
 recursive_pstrace_add_call = 0;
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
long pstrace_enable(pid_t pid)
{
 struct pid_node *new;
 if (pid < -1)
  return -ESRCH;
 new = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
 if (!new)
  return -ENOMEM;
 spin_lock_irq(&task_tracer_lock);
 if (pid == -1) {
  tasks_traced.trace_all = 1;
  tasks_traced_pid_list_del_all();
  goto new_node_not_added;
 }
 if (tasks_traced.trace_all == 1) {
  tasks_traced_pid_list_del(pid);
  goto new_node_not_added;
 }
 if (tasks_traced_pid_list_add(new, pid))
  goto new_node_not_added;
 goto new_node_added;
new_node_not_added:
 spin_unlock_irq(&task_tracer_lock);
 kfree(new);
 return 0;
new_node_added:
 spin_unlock_irq(&task_tracer_lock);
 return 0;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 return pstrace_enable(pid);
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
long pstrace_disable(pid_t pid)
{
 struct pid_node *new;
 if (pid < -1)
  return -ESRCH;
 new = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
 if (!new)
  return -ENOMEM;
 spin_lock_irq(&task_tracer_lock);
 if (pid == -1) {
  tasks_traced.trace_all = 0;
  tasks_traced_pid_list_del_all();
  goto new_node_not_added;
 }
 if (tasks_traced.trace_all == 0) {
  tasks_traced_pid_list_del(pid);
  goto new_node_not_added;
 }
 if (tasks_traced_pid_list_add(new, pid))
  goto new_node_not_added;
 goto new_node_added;
new_node_not_added:
 spin_unlock_irq(&task_tracer_lock);
 kfree(new);
 return 0;
new_node_added:
 spin_unlock_irq(&task_tracer_lock);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 return pstrace_disable(pid);
}
long wait_do_pstrace_get(pid_t pid, int user_counter,
    struct pstrace *rb_snapshot,
    struct counter_node *my_node,
    long *last_rec_copy_counter)
{
 int end = 0;
 DEFINE_WAIT(wait);
 my_node->condition = 0;
 my_node->counter = user_counter;
 my_node->last_rec_copy_counter = 0;
 my_node->pid = pid;
 my_node->end = 0;
 my_node->snapshot = rb_snapshot;
 INIT_LIST_HEAD(&my_node->list);
 spin_lock(&counter_list_lock);
 list_add(&my_node->list, &counter_list);
 spin_unlock(&counter_list_lock);
 spin_unlock_irq(&ring_buffer_lock);
 add_wait_queue(&counter_queue, &wait);
 while (!my_node->condition) {
  if (signal_pending(current)) {
   spin_lock(&counter_list_lock);
   list_del(&my_node->list);
   spin_unlock(&counter_list_lock);
   break;
  }
  prepare_to_wait(&counter_queue, &wait, TASK_INTERRUPTIBLE);
  schedule();
 }
 *last_rec_copy_counter = my_node->last_rec_copy_counter;
 end = my_node->end;
 finish_wait(&counter_queue, &wait);
 return end;
}
long do_pstrace_get(pid_t pid, struct pstrace *buf, long user_counter,
      struct pstrace *rb_snapshot, struct counter_node *my_node,
      long *user_counter_pointer)
{
 int i;
 int end = 0;
 long last_rec_copy_counter = 0;
 long j = 0;
 spin_lock_irq(&ring_buffer_lock);
 if (user_counter <= 0) {
  end = ring_buffer_copy_to_kernel(
   rb_snapshot, &last_rec_copy_counter);
 } else if (user_counter + 500 < ring_buffer.counter - 500) {
  last_rec_copy_counter = ring_buffer.counter;
  end = 0;
 } else if (user_counter + 500 < ring_buffer.counter) {
  end = min(((long) ring_buffer_copy_to_kernel(rb_snapshot,
    &last_rec_copy_counter)),
    (ring_buffer.next -
    (user_counter % PSTRACE_BUF_SIZE)));
 } else {
  end = wait_do_pstrace_get(pid, user_counter +
    PSTRACE_BUF_SIZE, rb_snapshot, my_node,
    &last_rec_copy_counter);
  goto skip_unlock;
 }
 spin_unlock_irq(&ring_buffer_lock);
skip_unlock:
 kfree(my_node);
 if (signal_pending(current)) {
  kfree(rb_snapshot);
  return -EINTR;
 }
 j = 0;
 for (i = 0; i < end; i++) {
  if (rb_snapshot[i].pid == pid || pid == -1) {
   if (copy_to_user(buf + j, rb_snapshot + i,
      sizeof(struct pstrace))) {
    kfree(rb_snapshot);
    return -EFAULT;
   }
   j++;
  }
 }
 kfree(rb_snapshot);
 if (copy_to_user(user_counter_pointer, &last_rec_copy_counter,
    sizeof(long)))
  return -EFAULT;
 return j;
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
long pstrace_get(pid_t pid, struct pstrace *buf, long *counter)
{
 long user_counter;
 long rb_counter;
 struct pstrace *rb_snapshot;
 struct counter_node *my_node;
 rb_counter = 0;
 if (pid < -1)
  return -ESRCH;
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if (copy_from_user(&user_counter, counter, sizeof(long)))
  return -EFAULT;
 rb_snapshot = kmalloc_array(PSTRACE_BUF_SIZE,
   sizeof(struct pstrace), GFP_KERNEL);
 if (unlikely(!rb_snapshot))
  return -ENOMEM;
 my_node = kmalloc(sizeof(struct counter_node), GFP_KERNEL);
 if (unlikely(!my_node)) {
  kfree(rb_snapshot);
  return -ENOMEM;
 }
 return do_pstrace_get(pid, buf, user_counter, rb_snapshot, my_node,
   counter);
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct __user pstrace *,
  buf, long __user *, counter)
{
 return pstrace_get(pid, buf, counter);
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
long pstrace_clear(pid_t pid)
{
 struct counter_node *node, *next;
 int wake_counter_queue = 0;
 if (pid < -1)
  return -ESRCH;
 spin_lock_irq(&ring_buffer_lock);
 spin_lock(&counter_list_lock);
 list_for_each_entry_safe(node, next, &counter_list, list) {
  if (node->pid == pid) {
   node->end = ring_buffer_copy_to_kernel(
     node->snapshot,
     &node->last_rec_copy_counter);
   node->condition = 1;
   wake_counter_queue = 1;
   list_del(&node->list);
  }
 }
 if (pid == -1)
  ring_buffer_clear_all();
 else
  ring_buffer_clear_record(pid);
 spin_unlock(&counter_list_lock);
 spin_unlock_irq(&ring_buffer_lock);
 if (wake_counter_queue)
  wake_up_all(&counter_queue);
 return 0;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 return pstrace_clear(pid);
}