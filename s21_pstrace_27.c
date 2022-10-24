#include <linux/hashtable.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/printk.h> //TODO: Delete after debugging
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
#define RBCHRON_DO_WRAP 0x1
#define RBCHRON_NEED_UNLOCK 0x2
/* The data structure stored in the ring buffer. */
struct pst_entry {
 int counter; /* The counter value when this entry was produced */
 struct pstrace rbuf[PSTRACE_BUF_SIZE]; /* Ring buffer at that time */
};
static DEFINE_RWLOCK(ring_buffer_lock);
static struct {
 struct pstrace buffer[PSTRACE_BUF_SIZE];
 struct pst_entry *buf_copies[PSTRACE_BUF_SIZE];
 unsigned int counter;
} ring_buffer;
struct pid_hash_entry {
 pid_t pid;
 struct hlist_node h_node;
};
struct cached_buffer {
 struct pstrace buffer[PSTRACE_BUF_SIZE];
 unsigned int counter;
 int filled;
 pid_t pid;
 struct hlist_node h_node;
};
static DEFINE_SPINLOCK(cached_buffers_lock);
static DEFINE_HASHTABLE(cached_buffers, 8);
static DEFINE_SPINLOCK(hash_lock);
static DEFINE_HASHTABLE(pid_hash, 8); // TODO: how big?
static int pid_count = 0;/* Requires hash_lock to modify */
static DECLARE_WAIT_QUEUE_HEAD(pstraceq);
static DEFINE_SPINLOCK(add_wakeup_lock);
static int trace_all = 0;
/* Call without hash_lock held */
static void pid_hash_clear(void)
{
 struct hlist_node *tmp;
 struct pid_hash_entry *curr;
 int bkt;
 hash_for_each_safe(pid_hash, bkt, tmp, curr, h_node) {
  hash_del(&curr->h_node);
  kfree(curr);
 }
 pid_count = 0;
}
/* This locks &hash_lock so should not be acquired with write lock held */
static int pid_hash_contains(pid_t pid)
{
 struct hlist_node *tmp;
 struct pid_hash_entry *curr;
 hash_for_each_possible_safe(pid_hash, curr, tmp, h_node,
  pid) { //TODO: remove safe
  if (curr->pid == pid)
   return 1;
 }
 return 0;
}
static inline int trackable_state(long state)
{
 return !state || state & TASK_INTERRUPTIBLE ||
        state & TASK_UNINTERRUPTIBLE ||
        state & __TASK_STOPPED ||
        state & TASK_DEAD;
}
/* Call without hash_lock held */
static long pid_hash_add(pid_t pid)
{
 struct pid_hash_entry *pid_node;
 if (pid_hash_contains(pid))
  return 0;
 if (pid_count >= PSTRACE_BUF_SIZE)
  return -ENOSPC;
 pid_node = kmalloc(sizeof(struct pid_hash_entry), GFP_KERNEL);
 if (pid_node == NULL)
  return -ENOMEM;
 pid_node->pid = pid;
 hash_add(pid_hash, &pid_node->h_node, pid);
 pid_count++;
 return 0;
}
/* Call without hash_lock held */
static long pid_hash_remove(pid_t pid)
{
 struct hlist_node *tmp;
 struct pid_hash_entry *curr;
 hash_for_each_possible_safe(pid_hash, curr, tmp, h_node,
  pid) {
  if (curr->pid == pid) {
   hash_del(&curr->h_node);
   kfree(curr);
   pid_count--;
   break;
  }
 }
 return 0;
}
static inline int pid_should_track(pid_t pid)
{
 return trace_all ^ pid_hash_contains(pid);
}
static void task_struct_to_pstrace(struct pstrace *dest, struct task_struct
  *origin)
{
 strncpy(dest->comm, origin->comm, sizeof(dest->comm));
 dest->pid = origin->pid;
 if (origin->state & TASK_DEAD)
  dest->state = origin->exit_state;
 else
  dest->state = origin->state;
}
static inline void ring_buffer_add(struct pstrace *pstrace_p)
{
 ring_buffer.buffer[ring_buffer.counter++ % PSTRACE_BUF_SIZE]
  = *pstrace_p;
}
static void ring_buffer_copy(struct pstrace *buffer)
{
 int i;
 for (i = 0; i < (ring_buffer.counter < PSTRACE_BUF_SIZE ?
    ring_buffer.counter : PSTRACE_BUF_SIZE); i++)
  buffer[i] = ring_buffer.buffer[i];
}
/* Should be called with ring_buffer_lock held in write mode */
static void ring_buffer_cache(void)
{
 struct cached_buffer *curr;
 struct hlist_node *tmp;
 hash_for_each_possible_safe(cached_buffers, curr, tmp, h_node,
  ring_buffer.counter) {
  if (curr->counter == ring_buffer.counter) {
   ring_buffer_copy(curr->buffer);
   curr->filled = 1;
   hash_del(&curr->h_node);
  }
 }
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid) // TODO: check for invalid PID
{
 unsigned long flags;
 long exit_status;
 spin_lock_irqsave(&hash_lock, flags);
 if (pid < -1) {
  exit_status = -EINVAL;
  goto unlock;
 } else if (pid == -1) {
  trace_all = 1;
  pid_hash_clear();
  exit_status = 0;
  goto unlock;
 }
 if (!trace_all)
  exit_status = pid_hash_add(pid);
 else
  exit_status = pid_hash_remove(pid);
unlock:
 spin_unlock_irqrestore(&hash_lock, flags);
 return exit_status;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 unsigned long flags;
 long exit_status;
 spin_lock_irqsave(&hash_lock, flags);
 if (pid < -1) {
  exit_status = -EINVAL;
  goto unlock;
 } else if (pid == -1) {
  trace_all = 0;
  pid_hash_clear();
  exit_status = 0;
  goto unlock;
 }
 if (!trace_all)
  exit_status = pid_hash_remove(pid);
 else
  exit_status = pid_hash_add(pid);
unlock:
 spin_unlock_irqrestore(&hash_lock, flags);
 return exit_status;
}
void pstrace_add(struct task_struct *p)
{
 struct pstrace pst;
 unsigned long flags;
 task_struct_to_pstrace(&pst, p);
 spin_lock_irqsave(&hash_lock, flags);
 if (!pid_should_track(p->pid) || !trackable_state(p->state)) {
  spin_unlock_irqrestore(&hash_lock, flags);
  return;
 }
 spin_unlock_irqrestore(&hash_lock, flags);
 write_lock_irqsave(&ring_buffer_lock, flags);
 ring_buffer_add(&pst);
 spin_lock(&cached_buffers_lock);
 ring_buffer_cache();
 spin_unlock(&cached_buffers_lock);
 write_unlock_irqrestore(&ring_buffer_lock, flags);
   if (spin_trylock_irqsave(&add_wakeup_lock, flags)) {
  wake_up_all(&pstraceq);
  spin_unlock_irqrestore(&add_wakeup_lock, flags);
 }
}
static int ring_buffer_copy_to_user(struct pstrace *buf, long counter,
  struct pstrace *user_buf, long *user_counter)
{
 if (copy_to_user(user_buf, buf, sizeof(*buf) * PSTRACE_BUF_SIZE) ||
     copy_to_user(user_counter, &counter, sizeof(counter)))
  return -EFAULT;
 return 0;
}
static int pid_match(pid_t input, pid_t actual)
{
 return actual != -1 && (input == -1 || input == actual);
}
// TODO: do we need __user labels?
static long copy_with_options(struct pstrace *from, long start, long end,
  struct pstrace *to, long *to_ctr, pid_t filter_pid)
{
 struct pstrace tempbuf[PSTRACE_BUF_SIZE];
 struct pstrace ctrace;
 int idx = 0;
 int i;
 for (i = start; i < end; i++) {
  ctrace = from[i % PSTRACE_BUF_SIZE];
  if (pid_match(filter_pid, ctrace.pid))
   tempbuf[idx++] = ctrace;
 }
 if (idx < PSTRACE_BUF_SIZE)
  tempbuf[idx++].pid = -1; // Signify end
 if (copy_to_user(to, tempbuf, idx*sizeof(*tempbuf))
   || copy_to_user(to_ctr, &end, sizeof(end)))
  return -EFAULT;
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter)
{
 long kcounter, target_counter;
 struct cached_buffer *cached_buffer;
 int copy_result;
 unsigned long flags;
 // TODO: filter when copying
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if (copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
 if (kcounter < 1 && kcounter != -1)
  return -EINVAL;
 target_counter = kcounter + PSTRACE_BUF_SIZE;
 read_lock_irqsave(&ring_buffer_lock, flags);
 if (kcounter == -1) {
  copy_result = ring_buffer_copy_to_user(ring_buffer.buffer,
    ring_buffer.counter, buf, counter);
  read_unlock_irqrestore(&ring_buffer_lock, flags);
  return copy_result;
 } else if (ring_buffer.counter > target_counter + PSTRACE_BUF_SIZE) {
  // Nothing remaining
  read_unlock_irqrestore(&ring_buffer_lock, flags);
  return -EINVAL;
 } else if (ring_buffer.counter >= target_counter) {
  //Copy whatever is left
  read_unlock_irqrestore(&ring_buffer_lock, flags);
  return 0;
 }
 read_unlock_irqrestore(&ring_buffer_lock, flags);
 cached_buffer = kmalloc(sizeof(*cached_buffer), GFP_KERNEL);
 if (cached_buffer == NULL)
  return -ENOMEM;
 cached_buffer->counter = target_counter;
 cached_buffer->pid = pid;
 cached_buffer->filled = 0;
 spin_lock(&cached_buffers_lock);
 hash_add(cached_buffers, &cached_buffer->h_node,
   cached_buffer->counter);
 spin_unlock(&cached_buffers_lock);
 printk(KERN_ALERT "Added cached buffer to hashtable. Preparing to wait\n");
 //TODO: Check wait result
 wait_event_interruptible(pstraceq, cached_buffer->filled);
 copy_result = ring_buffer_copy_to_user(cached_buffer->buffer,
   cached_buffer->counter, buf, counter);
 kfree(cached_buffer);
 return copy_result;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 unsigned long flags;
 struct cached_buffer *curr;
 struct hlist_node *tmp;
 int bkt;
 int i;
 write_lock_irqsave(&ring_buffer_lock, flags);
 spin_lock(&cached_buffers_lock);
 hash_for_each_safe(cached_buffers, bkt, tmp, curr, h_node) {
  if (pid_match(pid, curr->pid)) {
   ring_buffer_copy(curr->buffer);
   curr->filled = 1;
   printk(KERN_ALERT "caching for %d\n", curr->counter);
   hash_del(&curr->h_node);
  }
 }
 spin_unlock(&cached_buffers_lock);
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (pid_match(pid, ring_buffer.buffer[i].pid))
   ring_buffer.buffer[i].pid = -1; // Flag as deleted
 }
 write_unlock_irqrestore(&ring_buffer_lock, flags);
 //TODO: wake up
 if (spin_trylock(&add_wakeup_lock)) {
  // TODO: doesn't match book docs
  printk(KERN_ALERT " Woke up ! \n");
  wake_up_all(&pstraceq);
  spin_unlock(&add_wakeup_lock);
 }
 return 0;
}