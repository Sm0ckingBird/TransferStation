#define _GNU_SOURCE
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/printk.h>
#include <linux/string.h>
// #include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
// #include <atomic.h>
#include <linux/wait.h>
#include <linux/unistd.h>
/* The maximum size of the ring buffer */
#define PSTRACE_BUF_SIZE 500
#define TRACKON 1
#define TRACKOFF 0
DEFINE_SPINLOCK(process_list_lock);
DEFINE_SPINLOCK(ring_buffer_lock); /* initialize spin lock */
atomic_t trace_pid;
int pidtracker = -2;
int tracing_enabled;
/* ring buffer */
struct pstrace_buffer {
 struct pstrace pstr_buf[PSTRACE_BUF_SIZE];
 long head;
 long tail;
 long is_empty; /* flag for no data in queue */
 long is_cleared; /* flag for cleared queue */
 long counter; /* persistent count of # records that recorded to the ring buffer */
};
struct pstrace_buffer ring_buffer;
int enable_count = 0, disable_count = 0;
pid_t enable_track[PSTRACE_BUF_SIZE];
/* initialize wait queue */
wait_queue_head_t wq;
DECLARE_WAIT_QUEUE_HEAD(wq);
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long lock;
 /* printk(KERN_DEBUG "Enter enabling for %d", pid); */
 spin_lock_irqsave(&process_list_lock, lock);
 if (pid != -1 && get_root(pid) == NULL) {
  /* printk(KERN_DEBUG "error"); */
  spin_unlock_irqrestore(&process_list_lock, lock);
  return -EINVAL;
 }
 if (pid == pidtracker) {
  spin_unlock_irqrestore(&process_list_lock, lock);
  /* printk(KERN_DEBUG "Already tracking %d", pid); */
  return 0;
 } else if (pid == -1) {
  pidtracker = pid;
  tracing_enabled = TRACKON;
 } else {
  pidtracker = pid;
  tracing_enabled = TRACKON;
 }
 spin_unlock_irqrestore(&process_list_lock, lock);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 unsigned long lock;
 /* printk(KERN_DEBUG "Enter disabling for %d", pid); */
 spin_lock_irqsave(&process_list_lock, lock);
 if ((tracing_enabled == TRACKOFF) && (pid == -1)) {
  spin_unlock_irqrestore(&process_list_lock, lock);
  /* printk(KERN_DEBUG "Already disabled %d", pid); */
  return 0;
 } else if (pid == -1) {
  tracing_enabled = TRACKOFF;
  pidtracker = -2;
  /* printk(KERN_DEBUG "Pid should be -1 and it is: %d", pid); */
 } else {
  if (pid == pidtracker) {
   tracing_enabled = TRACKOFF;
   pidtracker = -2;
  } else {
   spin_unlock_irqrestore(&process_list_lock, lock);
   /*
    * printk(KERN_DEBUG "Pid: %d not in enabled list, current tracking = %d",
    * pid, tracing_enabled);
    */
   return -EINVAL;
  }
 }
 spin_unlock_irqrestore(&process_list_lock, lock);
 return 0;
}
/*
 * Syscall No. 443
 *
 * Copy the pstrace ring buffer info @buf.
 * If @counter > 0, the caller process will wait until a full buffer can
 * be returned after record @counter (i.e. return record @counter + 1 to
 * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
 *
 * Returns the number of records copied.
 *
 * Reference: EdStem #449
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace *, buf, long *, counter)
{
 unsigned long lock;
 int i;
 long count;
 int status;
 int partcopy;/* flag to track whether entire buffer should be copied */
 int new_records = PSTRACE_BUF_SIZE;
 partcopy = 0;
 status = copy_from_user(&count, counter, sizeof(long));
 if (status != 0) {
  /* printk(KERN_DEBUG "Could not Copy From User!"); */
  return -EINVAL;
 }
 if (count < 0) { /* case 1 : invalid counter */
  return -EINVAL;
 }
 spin_lock_irqsave(&ring_buffer_lock, lock);
 if (count > 0) {
  /* case 4: buffer is not full wait */
  if (count + PSTRACE_BUF_SIZE > ring_buffer.counter) {
   /* printk(KERN_DEBUG "buffer not full so wait"); */
   spin_unlock_irqrestore(&ring_buffer_lock, lock);
   /* printk(KERN_DEBUG "Case 4: %d", new_records); */
   /* wait until overall counter=counter+PSTRACE_BUF_SIZE; */
   /* need while loop since otherwise will wake up in pstrace_add */
   while (wait_event_interruptible(wq, ring_buffer.counter >=
   count + PSTRACE_BUF_SIZE)) {
    // wait was woken up, but condition may not be met
    if (ring_buffer.is_cleared)
     break;
   }
   spin_lock_irqsave(&ring_buffer_lock, lock);
   if (ring_buffer.head != ring_buffer.tail || ring_buffer.is_empty)
    new_records =
    (ring_buffer.tail - ring_buffer.head + PSTRACE_BUF_SIZE) %
    PSTRACE_BUF_SIZE;
  }
  /* case 3: buffer already full */
  /* overwritten so return nothing */
  else if (count + PSTRACE_BUF_SIZE <= ring_buffer.counter - PSTRACE_BUF_SIZE) {
   new_records = 0;
   /* printk(KERN_DEBUG "Case 3.1: %d", new_records); */
  } else {
   /* not completely overwritten so copy head to (count + PSTRACE_BUF_SIZE) */
   new_records = count + PSTRACE_BUF_SIZE -
   (ring_buffer.counter - PSTRACE_BUF_SIZE);
   partcopy = 1;
   /* printk(KERN_DEBUG "Case 3.2: %d", new_records); */
  }
 } else { /* case 2: count == 0 */
  /* return all valid entries in buffer */
  if (ring_buffer.head != ring_buffer.tail || ring_buffer.is_empty)
   new_records = PSTRACE_BUF_SIZE;
  /* printk(KERN_DEBUG "Case 2: %d", new_records); */
 }
 spin_unlock_irqrestore(&ring_buffer_lock, lock);
 for (i = 0; i < new_records; i++) {
  status = copy_to_user(&buf[i],
  &ring_buffer.pstr_buf[(ring_buffer.head+i) % PSTRACE_BUF_SIZE],
  sizeof(struct pstrace));
  if (status != 0) {
   /* printk(KERN_DEBUG "Could not Copy To User!"); */
   return -EINVAL;
  }
 }
 if (partcopy == 1) {
  count = count + PSTRACE_BUF_SIZE;
  status = copy_to_user(counter, &count, sizeof(long));
 } else {
  status = copy_to_user(counter, &ring_buffer.counter, sizeof(long));
 }
 if (status != 0) {
  /* printk(KERN_DEBUG "Could not Copy To User!"); */
  return -EINVAL;
 }
 return new_records;
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 int i;
 unsigned long lock;
 spin_lock_irqsave(&ring_buffer_lock, lock);
 spin_unlock_irqrestore(&ring_buffer_lock, lock);
 wake_up_all(&wq);
 spin_lock_irqsave(&ring_buffer_lock, lock);
 ring_buffer.head = 0;
 ring_buffer.tail = 0;
 ring_buffer.is_empty = 1;
 ring_buffer.is_cleared = 1;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  ring_buffer.pstr_buf[i].comm[0] = '\0';
  ring_buffer.pstr_buf[i].state = 0;
  ring_buffer.pstr_buf[i].pid = 0;
  ring_buffer.pstr_buf[i].tid = 0;
 }
 spin_unlock_irqrestore(&ring_buffer_lock, lock);
 return 0;
}
/* Add a record of the state change into the ring buffer.
 * The first parameter is a task_struct pointer, the second is the state you try to log.
 */
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long ringbuf_flags;
 if (p->exit_state == EXIT_DEAD || p->exit_state == EXIT_ZOMBIE)
  state = p->exit_state;
 if ((state == TASK_RUNNING) || (state == TASK_INTERRUPTIBLE) || (state == EXIT_ZOMBIE) ||
 (state == EXIT_DEAD) || (state == TASK_UNINTERRUPTIBLE) ||
 (state == TASK_STOPPED) || (state == TASK_RUNNABLE)) {
  spin_lock_irqsave(&ring_buffer_lock, ringbuf_flags);
  if (state == TASK_STOPPED)
   state = __TASK_STOPPED;
  if ((tracing_enabled == TRACKON && p->tgid == pidtracker) || pidtracker == -1) {
   spin_unlock_irqrestore(&ring_buffer_lock, ringbuf_flags);
   local_irq_save(ringbuf_flags);
   spin_lock_irqsave(&ring_buffer_lock, ringbuf_flags);
   memcpy(ring_buffer.pstr_buf[ring_buffer.tail].comm, p->comm,
   sizeof(char)*16);
   ring_buffer.pstr_buf[ring_buffer.tail].state = state;
   /*
    * Without threads, the tid = the pid. With threads, all threads have
    * the same pid, but each one has a unique tid. EdStem #448
    */
   ring_buffer.pstr_buf[ring_buffer.tail].pid = p->tgid;
   ring_buffer.pstr_buf[ring_buffer.tail].tid = p->pid;
   if
   (((ring_buffer.tail - ring_buffer.head + PSTRACE_BUF_SIZE)
   % PSTRACE_BUF_SIZE) == PSTRACE_BUF_SIZE - 1) {
    /* if buffer is full, increment ring_buffer.head */
    ring_buffer.head = (ring_buffer.head + 1) % PSTRACE_BUF_SIZE;
   }
   ring_buffer.tail = (ring_buffer.tail + 1) % PSTRACE_BUF_SIZE;
   ring_buffer.counter++;
   ring_buffer.is_empty = 0;
   ring_buffer.is_cleared = 0;
   spin_unlock_irqrestore(&ring_buffer_lock, ringbuf_flags);
   wake_up_all(&wq);
   local_irq_restore(ringbuf_flags);
  } else {
   spin_unlock_irqrestore(&ring_buffer_lock, ringbuf_flags);
  }
 }
}