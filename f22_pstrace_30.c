#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/pstrace.h>
#define PSTRACE_MAX_BUF 500
#define PSTRACE_BLOCKING_OFFSET 300
/* HELPER STRUCTS */
struct pstrace_wait {
 struct task_struct *tsk;
 long target_counter;
 struct pstrace *kbuf;
};
struct pstrace_clear {
 long counter;
 bool cleared;
};
struct pstrace_buffer {
 struct pstrace ring_buffer[PSTRACE_MAX_BUF];
 unsigned short index;
 long counter;
 struct pstrace_clear *clear_info;
};
/* GLOBALS */
DEFINE_SPINLOCK(pstrace_buffer_lock);
struct pstrace_clear clear_info = {
 .counter = 0,
 .cleared = false,
};
struct pstrace_buffer trace_buffer = {
 .index = 0,
 .counter = 0,
 .clear_info = &clear_info,
};
atomic_t trace_pid = ATOMIC_INIT(-2);
atomic_t waiting_processes = ATOMIC_INIT(0);
atomic_t is_waking_up = ATOMIC_INIT(0);
DECLARE_WAIT_QUEUE_HEAD(wait_counter);
DECLARE_WAIT_QUEUE_HEAD(clear_wait);
/* PSTRACE ADD */
static inline void add_trace_to_buf(struct task_struct *tsk, long state)
{
 struct pstrace *trace;
 trace = &trace_buffer.ring_buffer[trace_buffer.index];
 strcpy(trace->comm, tsk->comm);
 trace->state = state;
 trace->pid = tsk->tgid;
 trace->tid = tsk->pid;
}
static inline void increase_counters(void)
{
 trace_buffer.index++;
 if (trace_buffer.index >= PSTRACE_MAX_BUF)
  trace_buffer.index = 0;
 trace_buffer.counter++;
}
/*
 * (core.c) try_to_wake_up -- TASK_RUNNABLE
 * (core.c) __schedule -- TASK_RUNNING
 * (core.c) schedule -- TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE
 * (exit.c) exit_notify -- EXIT_ZOMBIE
 * (exit.c) release_task -- EXIT_DEAD
 */
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long flags;
 pid_t pid;
 pid = atomic_read(&trace_pid);
 if (p->pid != pid && pid != -1)
  return;
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 add_trace_to_buf(p, state);
 increase_counters();
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
}
/* PSTRACE ENABLE */
static inline bool is_valid_pid(pid_t pid)
{
 struct task_struct *tsk;
 rcu_read_lock();
 tsk = pid == 0 ? &init_task : find_task_by_vpid(pid);
 rcu_read_unlock();
 return tsk != NULL;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 long ret;
 ret = 0;
 if (pid == -1)
  atomic_set(&trace_pid, -1);
 else if (pid < 0)
  ret = -EINVAL;
 else if (!is_valid_pid(pid))
  ret = -ESRCH;
 else
  atomic_set(&trace_pid, pid);
 return 0;
}
/* PSTRACE DISABLE */
SYSCALL_DEFINE0(pstrace_disable)
{
 atomic_set(&trace_pid, -2);
 return 0;
}
/* PSTRACE GET */
static inline void fill_regular_kbuf(struct pstrace *kbuf, int offset)
{
 long items, size;
 items = (PSTRACE_MAX_BUF - trace_buffer.index);
 size = items * sizeof(struct pstrace);
 memcpy(kbuf + offset, trace_buffer.ring_buffer + trace_buffer.index,
        size);
 size = (trace_buffer.index - offset) * sizeof(struct pstrace);
 memcpy(kbuf + items + offset, trace_buffer.ring_buffer, size);
}
static inline bool has_cleared_recently(void)
{
 bool has_cleared, is_recent;
 has_cleared = trace_buffer.clear_info->counter > 0;
 is_recent = (trace_buffer.counter - trace_buffer.clear_info->counter) <
      PSTRACE_MAX_BUF;
 return has_cleared && is_recent;
}
static inline unsigned long fill_non_blocking_buffer(struct pstrace *kbuf,
           long *kcounter)
{
 unsigned long flags, items, size;
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 if (unlikely(trace_buffer.counter < PSTRACE_MAX_BUF)) {
  size = trace_buffer.counter * sizeof(struct pstrace);
  memcpy(kbuf, trace_buffer.ring_buffer, size);
 } else if (has_cleared_recently()) {
  items = trace_buffer.counter - trace_buffer.clear_info->counter;
  size = items * sizeof(struct pstrace);
  memcpy(kbuf, trace_buffer.ring_buffer, size);
 } else {
  fill_regular_kbuf(kbuf, 0);
  size = PSTRACE_MAX_BUF * sizeof(struct pstrace);
 }
 *kcounter = trace_buffer.counter;
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
 return size;
}
static inline unsigned long fill_overwritten_kbuf(struct pstrace *kbuf,
        long *kcounter)
{
 unsigned long flags, overwritten, items, size;
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 if (has_cleared_recently()) {
  overwritten = trace_buffer.clear_info->counter - *kcounter;
  items = PSTRACE_MAX_BUF - overwritten;
  size = items * sizeof(struct pstrace);
  memcpy(kbuf, trace_buffer.ring_buffer, size);
 } else {
  overwritten =
   trace_buffer.counter - (*kcounter + PSTRACE_MAX_BUF);
  if (overwritten >= PSTRACE_MAX_BUF) {
   size = 0;
  } else {
   items = PSTRACE_MAX_BUF - overwritten;
   if (trace_buffer.index + items <= PSTRACE_MAX_BUF) {
    size = items * sizeof(struct pstrace);
    memcpy(kbuf,
           trace_buffer.ring_buffer +
            trace_buffer.index,
           size);
   } else {
    items = PSTRACE_MAX_BUF - trace_buffer.index;
    size = items * sizeof(struct pstrace);
    memcpy(kbuf,
           trace_buffer.ring_buffer +
            trace_buffer.index,
           size);
    items = PSTRACE_MAX_BUF - overwritten - items;
    size = items * sizeof(struct pstrace);
    memcpy(kbuf + (PSTRACE_MAX_BUF -
            trace_buffer.index),
           trace_buffer.ring_buffer, size);
   }
   size = (PSTRACE_MAX_BUF - overwritten) *
          sizeof(struct pstrace);
  }
 }
 *kcounter = *kcounter + PSTRACE_MAX_BUF;
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
 return size;
}
static inline void copy_kbuf_beginning(struct pstrace *kbuf, int begin_index)
{
 long items, size, copy_index;
 items = trace_buffer.counter - begin_index;
 if (trace_buffer.index - items >= 0) {
  copy_index = trace_buffer.index - items;
  memcpy(kbuf, trace_buffer.ring_buffer + copy_index,
         PSTRACE_BLOCKING_OFFSET * sizeof(struct pstrace));
 } else {
  copy_index = PSTRACE_MAX_BUF - (items - trace_buffer.index);
  items = PSTRACE_BLOCKING_OFFSET - copy_index;
  size = items * sizeof(struct pstrace);
  memcpy(kbuf, trace_buffer.ring_buffer + copy_index,
         PSTRACE_BLOCKING_OFFSET * sizeof(struct pstrace));
  items = PSTRACE_BLOCKING_OFFSET - items;
  size = items * sizeof(struct pstrace);
  memcpy(kbuf + (PSTRACE_BLOCKING_OFFSET - copy_index),
         trace_buffer.ring_buffer, size);
 }
}
static inline int should_stop_blocking(void *data)
{
 unsigned long flags;
 bool beginning_copied;
 struct pstrace_wait *wait_entry;
 beginning_copied = false;
 wait_entry = (struct pstrace_wait *)data;
 while (!kthread_should_stop()) {
  spin_lock_irqsave(&pstrace_buffer_lock, flags);
  if (wait_entry->target_counter <= trace_buffer.counter) {
   spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
   wake_up_process(wait_entry->tsk);
   break;
  }
  if ((trace_buffer.counter - PSTRACE_BLOCKING_OFFSET) >
       (wait_entry->target_counter - PSTRACE_MAX_BUF) &&
      !beginning_copied) {
   copy_kbuf_beginning(wait_entry->kbuf,
         wait_entry->target_counter -
          PSTRACE_MAX_BUF);
   beginning_copied = true;
  }
  spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
  schedule();
 }
 return 0;
}
static inline int start_blocking_psget(struct pstrace *kbuf,
           long target_counter)
{
 DEFINE_WAIT(w);
 struct pstrace_wait wait_entry;
 struct task_struct *p;
 unsigned long flags;
 bool ret;
 ret = false;
 wait_entry.tsk = current;
 wait_entry.target_counter = target_counter + PSTRACE_MAX_BUF;
 wait_entry.kbuf = kbuf;
 w.private = &wait_entry;
 atomic_inc(&waiting_processes);
 p = kthread_run(should_stop_blocking, &wait_entry, "blocking_psget");
 if (!p)
  return -ENOMEM;
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 while (wait_entry.target_counter > trace_buffer.counter) {
  prepare_to_wait(&wait_counter, &w, TASK_INTERRUPTIBLE);
  spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
  if (signal_pending(current)) {
   kthread_stop(p);
   ret = -EINTR;
   break;
  }
  schedule();
  spin_lock_irqsave(&pstrace_buffer_lock, flags);
 }
 finish_wait(&wait_counter, &w);
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
 if (ret == false && trace_buffer.clear_info->cleared)
  ret = true;
 return ret;
}
static inline long fill_blocking_buffer(struct pstrace *kbuf, long *kcounter,
     long *skip)
{
 long size;
 unsigned long flags, items, index;
 int interrupted;
 interrupted = start_blocking_psget(kbuf, *kcounter);
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 if (interrupted < 0)
  return interrupted;
 if (interrupted) {
  if (trace_buffer.counter > *kcounter) {
   items = trace_buffer.counter - *kcounter;
   index = (*kcounter - trace_buffer.clear_info->counter) %
    PSTRACE_MAX_BUF;
   if (index + items <= PSTRACE_MAX_BUF) {
    size = items * sizeof(struct pstrace);
    memcpy(kbuf, trace_buffer.ring_buffer + index,
           size);
   } else {
    items = PSTRACE_MAX_BUF - index;
    size = items * sizeof(struct pstrace);
    memcpy(kbuf, trace_buffer.ring_buffer + index,
           size);
    items = trace_buffer.counter - *kcounter -
     items;
    size = items * sizeof(struct pstrace);
    memcpy(kbuf + (PSTRACE_MAX_BUF - index),
           trace_buffer.ring_buffer, size);
    size = (trace_buffer.counter - *kcounter) *
           sizeof(struct pstrace);
   }
  } else {
   size = 0;
  }
  *kcounter = trace_buffer.counter;
 } else {
  fill_regular_kbuf(kbuf, trace_buffer.counter - *kcounter -
      PSTRACE_MAX_BUF);
  if (has_cleared_recently()) {
   *skip = *kcounter - trace_buffer.clear_info->counter;
   size = (PSTRACE_MAX_BUF - *skip) *
          sizeof(struct pstrace);
  } else {
   size = PSTRACE_MAX_BUF * sizeof(struct pstrace);
  }
  *kcounter = *kcounter + PSTRACE_MAX_BUF;
 }
 atomic_dec(&waiting_processes);
 wake_up_interruptible_all(&clear_wait);
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
 return size;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter)
{
 long kcounter, size, ret, skip;
 struct pstrace *kbuf;
 ret = 0;
 skip = 0;
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 if (kcounter < 0)
  return -EINVAL;
 kbuf = kmalloc(sizeof(struct pstrace) * PSTRACE_MAX_BUF, GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
 if (kcounter == 0)
  size = fill_non_blocking_buffer(kbuf, &kcounter);
 else if (kcounter + PSTRACE_MAX_BUF <= trace_buffer.counter)
  size = fill_overwritten_kbuf(kbuf, &kcounter);
 else
  size = fill_blocking_buffer(kbuf, &kcounter, &skip);
 if (size < 0) {
  ret = size;
  goto exit;
 }
 if (put_user(kcounter, counter) ||
     copy_to_user(buf, kbuf + skip, size)) {
  ret = -EFAULT;
 }
exit:
 kfree(kbuf);
 return ret;
}
/* PSTRACE CLEAR */
SYSCALL_DEFINE0(pstrace_clear)
{
 unsigned long flags;
 struct wait_queue_entry *pos, *n;
 struct pstrace_wait *wait_entry;
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 trace_buffer.clear_info->cleared = true;
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
 spin_lock_irq(&wait_counter.lock);
 list_for_each_entry_safe(pos, n, &wait_counter.head, entry) {
  wait_entry = (struct pstrace_wait *)pos->private;
  wait_entry->target_counter = 0;
 }
 spin_unlock_irq(&wait_counter.lock);
 do {
  wait_event_interruptible(clear_wait,
      atomic_read(&waiting_processes) == 0);
 } while (atomic_read(&waiting_processes) != 0);
 spin_lock_irqsave(&pstrace_buffer_lock, flags);
 memset(trace_buffer.ring_buffer, 0,
        sizeof(struct pstrace) * PSTRACE_MAX_BUF);
 trace_buffer.index = 0;
 trace_buffer.clear_info->cleared = false;
 trace_buffer.clear_info->counter = trace_buffer.counter;
 spin_unlock_irqrestore(&pstrace_buffer_lock, flags);
 return 0;
}