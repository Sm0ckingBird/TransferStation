/*
 * [TEAMMATE]
 * include header files in alphabetical order
 */
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/circ_buf.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/types.h>
/*
 * [TEAMMATE]
 * WRITE YOUR CODE AND, IF NEEDED, HELPER FUNCTIONS
 * **IN YOUR SECTION ONLY**
 * DO NOT WRITE IN OTHER'S SECTION UNLESS HE
 * ALLOWS YOU TO DO SO
 */
/*
 * [TEAMMATE]
 * PSTRACE_BUF_SIZE is defined in pstrace
 */
atomic_t add_count = ATOMIC_INIT(-1);
long global_counter;
struct psrecord global_ring_buffer[PSTRACE_BUF_SIZE];
pid_t trace_list[PSTRACE_BUF_SIZE] = { [0 ... PSTRACE_BUF_SIZE - 1] = -1 };
bool should_trace = true; /* disable(-1) by default */
struct pstrace_notifier pstn = { .lock = __SPIN_LOCK_UNLOCKED(pstn.lock),
     .wait_list = LIST_HEAD_INIT(pstn.wait_list) };
DEFINE_SPINLOCK(trace_lock); /* trace_list, should_trace */
DEFINE_SPINLOCK(buffer_lock); /* ring buffer, counter */
static void pstrace_init(void)
{
 int i;
 /* trace_list, should_trace */
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  global_ring_buffer[i].id = -1;
}
/*****************************436, 437*****************************/
/*
 * Helper functions start with __ must be called after grabbing trace_lock
 *
 * Make sure every unlock is placed right before the return statement.
 */
void __print_tl_first_ten(void)
{
 int i;
 printk(KERN_INFO "[PSTRACE_DEBUG] trace list: [");
 for (i = 0; i < 10; i++) {
  printk(KERN_CONT "%d, ", trace_list[i]);
 }
 printk(KERN_CONT "] (should_trace = %d)\n", should_trace);
}
void __clear_trace_list(void)
{
 int i;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  trace_list[i] = -1;
}
int __find_in_trace_list(pid_t pid)
{
 int i;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  if (trace_list[i] == pid)
   return i;
 return -1;
}
static inline void __set_trace_list_by_index(int ind, pid_t pid)
{
 trace_list[ind] = pid;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *child;
 int trace_list_ind = -1;
 if (pid < -1)
  return -EINVAL;
 spin_lock_irq(&trace_lock);
 if (pid == -1) {
  /*
   * Tracing all processes, then the pids in trace_list
   * should not be traced if there are any.
   */
  should_trace = false;
  __clear_trace_list();
  spin_unlock_irq(&trace_lock);
  return 0;
 }
 child = find_get_task_by_vpid(pid);
 if (!child) {
  spin_unlock_irq(&trace_lock);
  return -ESRCH;
 }
 // In enable(-1) trace-all mode already, all pids are enabled.
 if (!should_trace) {
  spin_unlock_irq(&trace_lock);
  return 0;
 }
 trace_list_ind = __find_in_trace_list(pid);
 if (trace_list_ind >= 0) {
  spin_unlock_irq(&trace_lock);
  return 0; /* being traced already */
 }
 /* Find empty slot in trace_list */
 trace_list_ind = __find_in_trace_list(-1);
 /* No empty slot */
 if (trace_list_ind == -1) {
  spin_unlock_irq(&trace_lock);
  return -ENOMEM;
 }
 /* Assign pid to empty slot */
 __set_trace_list_by_index(trace_list_ind, pid);
 __print_tl_first_ten();
 spin_unlock_irq(&trace_lock);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 int trace_list_ind = -1;
 if (pid < -1)
  return -EINVAL;
 spin_lock_irq(&trace_lock);
 if (pid == -1) {
  /*
   * Stop tracing all processes, then the processes in
   * trace_list should be traced if there are any.
   */
  should_trace = true;
  __clear_trace_list();
  spin_unlock_irq(&trace_lock);
  return 0;
 }
 /* In disable(-1) not-trace-all mode already, all pids are disabled. */
 if (should_trace) {
  spin_unlock_irq(&trace_lock);
  return 0;
 }
 trace_list_ind = __find_in_trace_list(pid);
 if (trace_list_ind >= 0) {
  spin_unlock_irq(&trace_lock);
  return 0; /* not being traced already */
 }
 /* Find empty slot in trace_list */
 trace_list_ind = __find_in_trace_list(-1);
 /* No empty slot */
 if (trace_list_ind == -1) {
  spin_unlock_irq(&trace_lock);
  return -ENOMEM;
 }
 /* Assign pid to empty slot */
 __set_trace_list_by_index(trace_list_ind, pid);
 __print_tl_first_ten();
 spin_unlock_irq(&trace_lock);
 return 0;
}
/*****************************pstrace_add*****************************/
/* Must grab buffer_lock before calling this! */
void __take_buffer_snapshot(struct psrecord *snapshot)
{
 int i;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++)
  snapshot[i] = global_ring_buffer[i];
}
static struct pstrace get_pstrace(struct task_struct *p)
{
 struct pstrace pst;
 get_task_comm(pst.comm, p);
 pst.pid = p->pid;
 pst.state = p->state;
 if (p->exit_state)
  pst.state = p->exit_state;
 return pst;
}
void pstrace_add(struct task_struct *p)
{
 struct pstrace pst;
 struct psrecord record;
 int tail;
 unsigned long flags;
 int trace_list_ind = -1;
 bool in_trace_list;
 if (atomic_inc_and_test(&add_count)) {
  printk(KERN_INFO "[PSTRACE_DEBUG] pstrace initialized");
  pstrace_init();
 }
 atomic_set(&add_count, 1); /* make sure no overflow */
 spin_lock_irqsave(&trace_lock, flags);
 trace_list_ind = __find_in_trace_list(p->pid);
 spin_unlock_irqrestore(&trace_lock, flags);
 in_trace_list = (trace_list_ind != -1);
 /*    Truth Table
  * shd_trce | in_trce_lst | add to RB
  * ---------------------------------------------------------
  * True  | True  | True
  * False  | True  | False
  * True  | False  | False
  * False  | False  | True
  */
 if (should_trace != in_trace_list) {
  return;
 }
 pst = get_pstrace(p);
 spin_lock_irqsave(&buffer_lock, flags);
 record.pst = pst;
 record.id = global_counter;
 tail = global_counter % PSTRACE_BUF_SIZE;
 global_ring_buffer[tail] = record;
 global_counter += 1;
 if (atomic_read(&add_wake_count) <= 0)
  wake_up_by_counter(&pstn, global_counter - 1);
 spin_unlock_irqrestore(&buffer_lock, flags);
}
/*****************************438, 439*****************************/
long copy_from_ring_buffer(pid_t pid, struct psrecord *ring_buffer,
      struct pstrace *buf, long *counter)
{
 int i, buf_pos = 0;
 long copied_count = 0, updated_counter = *counter;
 int head, tail;
 int rngL, rngR;
 int rel_i;
 bool check_range = true;
 if (updated_counter <= 0) {
  check_range = false;
  updated_counter = global_counter - PSTRACE_BUF_SIZE;
  if (updated_counter < 0)
   updated_counter = global_counter;
 }
 tail = global_counter;
 head = 0;
 updated_counter = *counter;
 if (global_counter >= PSTRACE_BUF_SIZE) {
  head = (tail + 1) % PSTRACE_BUF_SIZE;
  tail = (updated_counter + PSTRACE_BUF_SIZE - 1) %
         PSTRACE_BUF_SIZE;
 }
 if (global_counter == 0) {
  *counter = 0;
  return 0;
 }
 updated_counter = *counter;
 if (global_counter >= PSTRACE_BUF_SIZE)
  head = (tail + 1) % PSTRACE_BUF_SIZE;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  rel_i = (head + i) % PSTRACE_BUF_SIZE;
  if (ring_buffer[rel_i].pst.pid < 0 ||
      (pid != -1 && pid != ring_buffer[rel_i].pst.pid))
   continue;
  rngL = *counter + 1;
  rngR = *counter + 500;
  if (check_range && (ring_buffer[rel_i].id < rngL ||
        ring_buffer[rel_i].id > rngR))
   continue;
  buf[buf_pos].pid = ring_buffer[rel_i].pst.pid;
  strncpy(buf[buf_pos].comm, ring_buffer[rel_i].pst.comm, 16);
  buf[buf_pos].state = ring_buffer[rel_i].pst.state;
  buf_pos++;
  copied_count++;
  updated_counter = ring_buffer[rel_i].id;
  if (rel_i == tail)
   break;
 }
 *counter = updated_counter;
 return copied_count;
}
int insert_get_request(struct pstrace_notifier *pstn,
         struct pstrace_waiter *waiter, long counter, pid_t pid)
{
 unsigned long flags;
 spin_lock_irqsave(&pstn->lock, flags);
 list_add_tail(&waiter->list, &pstn->wait_list);
 waiter->pid = pid;
 waiter->counter = counter;
 waiter->up = false;
 waiter->task = current;
 for (;;) {
  if (signal_pending_state(TASK_INTERRUPTIBLE, current))
   goto interrupted;
  __set_current_state(TASK_INTERRUPTIBLE);
  spin_unlock_irq(&pstn->lock);
  schedule();
  spin_lock_irq(&pstn->lock);
  if (waiter->up) {
   spin_unlock_irqrestore(&pstn->lock, flags);
   return 0;
  }
 }
interrupted:
 list_del(&waiter->list);
 spin_unlock_irqrestore(&pstn->lock, flags);
 return -EINTR;
}
/* called with buffer_lock grabbed */
void wake_up_by_counter(struct pstrace_notifier *pstn, long counter)
{
 unsigned long flags;
 long copied_count;
 struct list_head *p, *next;
 struct pstrace_waiter *waiter;
 spin_lock_irqsave(&pstn->lock, flags);
 list_for_each_safe (p, next, &pstn->wait_list) {
  waiter = list_entry(p, struct pstrace_waiter, list);
  if (counter == -1 || waiter->counter + 500 <= counter) {
   __take_buffer_snapshot(waiter->snapshot);
   list_del(&waiter->list);
   waiter->up = true;
   copied_count = copy_from_ring_buffer(waiter->pid,
            waiter->snapshot,
            waiter->buf,
            &waiter->counter);
   waiter->copied_count = copied_count;
   spin_unlock(&buffer_lock);
   wake_up_process(waiter->task);
   spin_lock(&buffer_lock);
  }
 }
 spin_unlock_irqrestore(&pstn->lock, flags);
}
void wake_up_get_request(struct pstrace_notifier *pstn,
    struct psrecord *ring_buffer_snapshot, long counter,
    pid_t pid)
{
 unsigned long flags;
 long copied_count;
 struct list_head *p, *next;
 struct pstrace_waiter *waiter;
 spin_lock_irqsave(&pstn->lock, flags);
 list_for_each_safe (p, next, &pstn->wait_list) {
  waiter = list_entry(p, struct pstrace_waiter, list);
  if ((counter == -1 || waiter->counter + 500 <= counter) &&
      (pid == -1 || pid == waiter->pid)) {
   list_del(&waiter->list);
   waiter->up = true;
   copied_count = copy_from_ring_buffer(
    waiter->pid, ring_buffer_snapshot, waiter->buf,
    &waiter->counter);
   waiter->copied_count = copied_count;
   wake_up_process(waiter->task);
  }
 }
 spin_unlock_irqrestore(&pstn->lock, flags);
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter)
{
 int i;
 long ret;
 long wanted_counter = 0, current_counter;
 struct pstrace *target_buf;
 int tb_size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 struct pstrace_waiter *waiter = kmalloc(sizeof(struct pstrace_waiter), GFP_KERNEL);
 if (!waiter)
  return -ENOMEM;
 if (buf == NULL || counter == NULL) {
  kfree(waiter);
  return -EINVAL;
 }
 if (copy_from_user(&wanted_counter, counter, sizeof(long))) {
  kfree(waiter);
  return -EFAULT;
 }
 target_buf = kmalloc(tb_size, GFP_KERNEL);
 if (target_buf == NULL) {
  kfree(waiter);
  return -ENOMEM;
 }
 spin_lock(&buffer_lock);
 current_counter = global_counter;
 spin_unlock(&buffer_lock);
 if (wanted_counter <= 0 ||
     current_counter >= wanted_counter + PSTRACE_BUF_SIZE) {
  spin_lock(&buffer_lock);
  ret = copy_from_ring_buffer(pid, global_ring_buffer, target_buf,
         &wanted_counter);
  spin_unlock(&buffer_lock);
 } else {
  ret = insert_get_request(&pstn, waiter, wanted_counter, pid);
  if (ret) {
   kfree(target_buf);
   kfree(waiter);
   return ret;
  }
  ret = waiter->copied_count;
  wanted_counter = waiter->counter;
  for (i = 0; i < ret; i++)
   target_buf[i] = waiter->buf[i];
 }
 if (copy_to_user(buf, target_buf, tb_size)) {
  kfree(target_buf);
  kfree(waiter);
  return -EFAULT;
 }
 if (copy_to_user(counter, &wanted_counter, sizeof(long))) {
  kfree(target_buf);
  kfree(waiter);
  return -EFAULT;
 }
 printk(KERN_INFO "[PSTRACE_DEBUG] pstrace_get() global_counter = %ld\n",
        global_counter);
 kfree(target_buf);
 kfree(waiter);
 return ret;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i;
 struct psrecord *ring_buffer_snapshot =
  kmalloc(sizeof(struct psrecord) * PSTRACE_BUF_SIZE, GFP_KERNEL);
 struct pstrace garbage_pst = { .comm = "garbage",
           .pid = -1,
           .state = -1 };
 if (pid < -1) {
  kfree(ring_buffer_snapshot);
  return -EINVAL;
 }
 spin_lock(&buffer_lock);
 __take_buffer_snapshot(ring_buffer_snapshot);
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (pid == -1 || pid == global_ring_buffer[i].pst.pid) {
   global_ring_buffer[i].pst = garbage_pst;
   global_ring_buffer[i].id = -1;
  }
 }
 spin_unlock(&buffer_lock);
 wake_up_get_request(&pstn, ring_buffer_snapshot, -1, pid);
 kfree(ring_buffer_snapshot);
 return 0;
}