#include <linux/errno.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/spinlock_types.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
/**
 * Entry in the circular pstrace buffer.
 *
 * Entries consist of state change info and the record number of the state
 * change. Reflects the value of the pstrace buffer's counter when the state
 * change was recorded.
 */
struct pstrace_buffer_entry {
 /* Record number of the process state change. */
 long record_number;
 /* Process state change info. */
 struct pstrace *info;
};
/**
 * Defines a circular buffer for tracing process state changes within the
 * kernel.
 *
 * The buffer is circular, meaning it will contain no more than
 * $(_PSTRACE_BUF_SIZE) elements. Writing element $(_PSTRACE_BUF_SIZE) + 1 will
 * overwrite the element at buf->start.
 */
struct pstrace_buffer {
 /* Whether process state tracing is enabled. */
 long trace_enabled;
 /* Total number of process state changes since startup. */
 long counter;
 /* Process id to trace. If -1, includes all processes. */
 pid_t pid;
 /* Write index of the circular pstrace buffer. */
 long write;
 /* Current size of the pstrace buffer. Always <= $(_PSTRACE_BUF_SIZE) */
 long size;
 /* Buffer storing entries */
 struct pstrace_buffer_entry buf[_PSTRACE_BUF_SIZE];
};
/** Pstrace buffer for tracing process changes. */
static struct pstrace_buffer pstrace_buf =
 (struct pstrace_buffer){ .trace_enabled = _PSTRACE_DISABLED,
     .counter = 0,
     .pid = -1,
     .write = 0,
     .size = 0 };
/** Synchronization mechanism for the pstrace buffer. */
static DEFINE_SPINLOCK(pstrace_lock);
/** Wait queue for notifying pstrace_get on changes to the pstrace buffer. */
static DECLARE_WAIT_QUEUE_HEAD(pstrace_wait_queue);
/** Flag to determine whether calls to pstrace_get should stop. */
static int pstrace_wait_queue_stop_flag = 0;
/**
 * pstrace_buf_get - Returns a ptr to the buffer entry at the given index.
 *   Returns NULL if the given index is out of bounds.
 */
static struct pstrace_buffer_entry *__pstrace_buf_get(long index)
{
 printk("get pstrace_buffer_entry: %ld\n", index);
 if (index < 0 || index >= _PSTRACE_BUF_SIZE)
  return NULL;
 return &pstrace_buf.buf[index];
}
/**
 * pstrace_buf_get_write - Returns a pointer to the buffer's write head.
 */
static struct pstrace_buffer_entry *__pstrace_buf_get_write(void)
{
 return __pstrace_buf_get(pstrace_buf.write);
}
/**
 * pstrace_buf_get_earliest - Returns the index of the record in the circular
 *   pstrace buffer with the lowest record number. Returns -1 if the
 *   buffer is empty.
 */
static long __pstrace_buf_get_earliest_index(void)
{
 long min_record_number;
 long min_index = 0;
 long iter = 0;
 if (pstrace_buf.size < 1)
  // Buffer is empty.
  return -1;
 min_record_number = __pstrace_buf_get(0)->record_number;
 while (iter < _PSTRACE_BUF_SIZE) {
  long record_number = __pstrace_buf_get(iter)->record_number;
  if (record_number < min_record_number) {
   min_record_number = record_number;
   min_index = iter;
  }
  iter++;
 }
 return min_index;
}
/**
 * pstrace_buf_increment - Increments the given buffer index to the next index
 *   and returns it, wrapping back to the start if necessary.
 * @iter: buffer index
 */
static long __pstrace_buf_increment(long iter)
{
 if (iter == _PSTRACE_BUF_SIZE - 1)
  // Wrap back to buffer start.
  return 0;
 return iter + 1;
}
/**
 * pstrace_buf_decrement - Decrements the given buffer index to the previous
 *   index and returns it, wrapping back to the end if necessary.
 * @iter: buffer index
 */
static long __pstrace_buf_decrement(long iter)
{
 if (iter == 0)
  // Wrap back to buffer end.
  return _PSTRACE_BUF_SIZE - 1;
 return iter - 1;
}
/**
 * pstrace_buf_increment_write - Increments the pstrace buffer's write index,
 *   wrapping back to the start if necessary. This operation is not
 *   atomic, and should only be called from a thread-safe context.
 */
static void __pstrace_buf_increment_write(void)
{
 printk("increment pstrace_buf write\n");
 pstrace_buf.write = __pstrace_buf_increment(pstrace_buf.write);
}
/**
 * pstrace_buf_copy - Copies all of the entries in the buffer to the provided
 *   user buffer without waiting for the buffer to fill. Entries are
 *   copied in order of ascending record number, starting the given
 *   record number. If the record number is 0, starts with the
 *   earliest record in the buffer. Returns the number of entries
 *   copied.
 * @buf: user space buffer
 * @start: 
 */
static long __pstrace_buf_copy(struct pstrace *buf, long start)
{
 long err = 0;
 long copied_count = 0;
 long iter;
 long end;
 struct pstrace_buffer_entry *entry;
 iter = __pstrace_buf_get_earliest_index();
 if (iter == -1)
  // pstrace buffer is empty.
  return 0;
 // The ending index will be the index before the iterator.
 end = __pstrace_buf_decrement(iter);
 while (iter != end && copied_count < pstrace_buf.size) {
  entry = __pstrace_buf_get(iter);
  if (start > 0 && entry->record_number < start) {
   // If given a start record, don't copy earlier records.
   iter = __pstrace_buf_increment(iter);
   continue;
  }
  err = copy_to_user(buf, entry->info, sizeof(struct pstrace));
  if (err)
   return -EFAULT;
  copied_count++;
  iter = __pstrace_buf_increment(iter);
 }
 return copied_count;
}
static long do_pstrace_add(struct task_struct *p, long state)
{
 long err = 0;
 struct pstrace_buffer_entry *entry;
 struct pstrace *info;
 printk("call do_pstrace_add pid: %d, state: %ld\n", p->pid, state);
 spin_lock(&pstrace_lock);
 entry = __pstrace_buf_get_write();
 if (!entry) {
  // Bad address contained in write head.
  err = -EFAULT;
  goto error;
 }
 info = kmalloc(sizeof(struct pstrace), GFP_KERNEL);
 if (!info) {
  err = -ENOMEM;
  goto error;
 }
 // pid, tid in userspace is the counterpart of tgid, pid in task_struct.
 info->pid = p->tgid;
 info->tid = p->pid;
 printk("p->pid: %d\n", info->pid);
 printk("p->tid: %d\n", info->tid);
 memcpy(info->comm, p->comm, 16);
 entry->info = info;
 entry->record_number = pstrace_buf.counter;
 // Move the position of the write head, and increment the counter.
 __pstrace_buf_increment_write();
 pstrace_buf.counter++;
 if (pstrace_buf.size < _PSTRACE_BUF_SIZE)
  pstrace_buf.size++;
 spin_unlock(&pstrace_lock);
 // Wake up waiting calls to pstrace_get.
 wake_up_interruptible(&pstrace_wait_queue);
 printk("complete do_pstrace_add");
 return 0;
error:
 printk("error in do_pstrace_add");
 if (info)
  kfree(info);
 spin_unlock(&pstrace_lock);
 return err;
}
/**
 * pstrace_add - Adds a record of the provided state change to the pstrace ring
 *   buffer.
 * @p:   process being traced
 * @state:  current state to record for the process
 */
void pstrace_add(struct task_struct *p, long state)
{
 long unused_err;
 if (!pstrace_buf.trace_enabled)
  return;
 /// TODO: Verify this is the correct field for pid.
 if (pstrace_buf.pid != -1 && pstrace_buf.pid != p->tgid) {
  // Tracing is not enabled for this process.
  return;
 }
 unused_err = do_pstrace_add(p, state);
}
static long do_pstrace_enable(pid_t pid)
{
 printk("call do_pstrace_enable");
 spin_lock(&pstrace_lock);
 pstrace_buf.pid = pid;
 if (!pstrace_buf.trace_enabled)
  pstrace_buf.trace_enabled = _PSTRACE_ENABLED;
 spin_unlock(&pstrace_lock);
 return 0;
}
/**
 * pstrace_enable - Syscall No. 441. Traces a given process, or all processes.
 * @pid:  traces the given pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *task;
 printk("syscall pstrace_enable... pid: %ld\n", (long)pid);
 if (pid > -1) {
  // Return an error if the given pid does not exist.
  task = find_task_by_vpid(pid);
  if (!task)
   return -EINVAL;
 }
 pstrace_wait_queue_stop_flag = 0;
 return do_pstrace_enable(pid);
}
static long do_pstrace_disable(void)
{
 printk("call do_pstrace_disable\n");
 spin_lock(&pstrace_lock);
 pstrace_buf.trace_enabled = _PSTRACE_DISABLED;
 pstrace_buf.pid = -1;
 spin_unlock(&pstrace_lock);
 return 0;
}
/**
 * pstrace_disable - Syscall No. 442. Disables tracing for all processes.
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 printk("syscall pstrace_disable...\n");
 if (!pstrace_buf.trace_enabled)
  return 0;
 // Wake up waiting calls to pstrace_get.
 pstrace_wait_queue_stop_flag = 1;
 wake_up_interruptible(&pstrace_wait_queue);
 return do_pstrace_disable();
}
static long do_pstrace_get(struct pstrace *buf, long *user_counter,
      long counter)
{
 long err = 0;
 long new_counter = pstrace_buf.counter;
 long copied_count = 0;
 printk("call do_pstrace_get counter: %ld\n", counter);
 if (counter == 0) {
  // Case 1: (counter == 0)
  // Copies the entire buffer without blocking, sets the user
  // counter to the global counter, and returns the number of
  // records copied.
  goto copy_buffer;
 } else if (pstrace_buf.counter - counter < 500) {
  // Case 2: (counter > 0), buffer is partially empty
  // Blocks until the entire buffer is full. Copies the entire
  // buffer, sets the user counter to the global counter, and
  // returns the number of records copied.
  /// TODO: Fix potential race condition.
  err = wait_event_interruptible(
   pstrace_wait_queue,
   /* condition= */
   pstrace_buf.counter == counter + _PSTRACE_BUF_SIZE ||
    pstrace_wait_queue_stop_flag);
  if (err)
   return -EINTR;
  goto copy_buffer;
 } else if (pstrace_buf.counter - counter >= 2 * _PSTRACE_BUF_SIZE) {
  // Case 3: (counter > 0), none in range [counter, counter+size)
  // in buffer.
  // Sets the user counter to the global counter and returns 0,
  // for zero entries copied.
  goto copy_counter;
 } else {
  // Case 4: (counter > 0), some in range [counter, counter+size)
  // in buffer.
  // Copies up to 500 entries within the range
  // [counter, counter+size), sets the user counter to the last
  // record copied, and returns the number of records copied.
  new_counter = counter + _PSTRACE_BUF_SIZE;
  goto copy_buffer;
 }
copy_buffer:
 // Copy ring buffer contents and return the number of records copied.
 spin_lock(&pstrace_lock);
 copied_count = __pstrace_buf_copy(buf, counter);
 goto copy_counter;
copy_counter:
 // Copy new counter to user space.
 err = copy_to_user(user_counter, &new_counter, sizeof(long));
 spin_unlock(&pstrace_lock);
 if (err)
  return -EFAULT;
 return copied_count;
}
/**
 * pstrace_get - Syscall No. 443. Copies the pstrace ring buffer into user
 *   space.
 * @buf:  user space buffer
 * @counter:  copies $(PSTRACE_BUF_SIZE) records, starting with record
 *   @counter + 1. If counter < 0, returns immediately.
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace *, buf, long *, counter)
{
 long k_counter;
 printk("syscall pstrace_get...\n");
 if (copy_from_user(&k_counter, counter, sizeof(long)))
  return -EFAULT;
 if (k_counter < 0)
  return -EINVAL;
 return do_pstrace_get(buf, counter, k_counter);
}
static long do_pstrace_clear(void)
{
 long iter = 0;
 struct pstrace_buffer_entry *entry;
 printk("call do_pstrace_clear");
 spin_lock(&pstrace_lock);
 while (iter < pstrace_buf.size) {
  entry = __pstrace_buf_get(iter);
  if (entry->info)
   // Free any dynamically-allocated memory in the buffer.
   kfree(entry->info);
  // Zero initialize the buffer entry.
  memset(entry, 0, sizeof(struct pstrace_buffer_entry));
  iter++;
 }
 pstrace_buf.write = 0;
 pstrace_buf.size = 0;
 spin_unlock(&pstrace_lock);
 return 0;
}
/**
 * pstrace_clear - Syscall No. 444. Clears the pstrace ring buffer.
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 printk("syscall pstrace_clear...\n");
 // Wake up waiting calls to pstrace_get.
 pstrace_wait_queue_stop_flag = 1;
 wake_up_interruptible(&pstrace_wait_queue);
 return do_pstrace_clear();
}