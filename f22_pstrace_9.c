#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/list.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
struct pstrace_buffer_manager {
 struct pstrace buf[PSTRACE_BUF_SIZE];
 long _count; /* Count of all traces we've recorded */
 long _head;
 long _tail; /* Index of next trace; wraps around */
 long _last_clear_count;
} pbm;
struct target_pid_manager {
 pid_t _target_pid;
 bool _trace_enabled;
} tpm;
struct pstrace_event {
 long counter;
 bool is_call_by_interrupt;
 bool is_pstrace_clear_set;
 wait_queue_head_t *wq;
 struct list_head list;
};
LIST_HEAD(pstrace_event_list);
DEFINE_SPINLOCK(pbm_lock);
char *translate_process_state(int state)
{
 if (!state || state == PSTRACE_WAKE_UP_ENABLED)
  return "TASK_RUNNING";
 if (state == TASK_RUNNABLE)
  return "TASK_RUNNABLE"; /* 0x3, can't bitwise '&' check this one. */
 if (state == (TASK_RUNNABLE | PSTRACE_WAKE_UP_ENABLED))
  return "TASK_RUNNABLE";
 if (state & TASK_INTERRUPTIBLE)
  return "TASK_INTERRUPTIBLE";
 if (state & TASK_UNINTERRUPTIBLE)
  return "TASK_UNINTERRUPTIBLE";
 if (state & __TASK_STOPPED)
  return "__TASK_STOPPED";
 if (state & EXIT_ZOMBIE)
  return "EXIT_ZOMBIE";
 if (state & EXIT_DEAD)
  return "EXIT_DEAD";
 return "NOT_DEFINED";
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
long pstrace_enable(pid_t pid)
{
 if (pid < -1)
  return -EINVAL;
 if (pid > 0 && !find_task_by_vpid(pid))
  return -ESRCH;
 tpm._target_pid = pid;
 tpm._trace_enabled = true;
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
 */
long pstrace_disable(void)
{
 tpm._trace_enabled = false;
 return 0;
}
/** Sets len_to_copy and start_index using their pointers */
void set_copy_params(long *len_to_copy, long *start_index, long kcounter)
{
 if (!kcounter) {
  /* Non-blocking call, return all valid entries in buffer up to max */
  if (pbm._count - pbm._last_clear_count >= PSTRACE_BUF_SIZE) {
   *len_to_copy = (pbm._count < PSTRACE_BUF_SIZE) ?
            pbm._count :
            PSTRACE_BUF_SIZE;
   *start_index = pbm._tail;
  } else {
   *len_to_copy = pbm._count - pbm._last_clear_count;
   *start_index = pbm._last_clear_count % PSTRACE_BUF_SIZE;
  }
 } else {
  if (kcounter + PSTRACE_BUF_SIZE <= pbm._count) {
   *len_to_copy = (pbm._count - pbm._last_clear_count >=
     PSTRACE_BUF_SIZE) ?
            kcounter - pbm._count +
             2 * PSTRACE_BUF_SIZE :
            kcounter + PSTRACE_BUF_SIZE -
             pbm._last_clear_count;
   if (*len_to_copy > 0) {
    *start_index =
     (pbm._count - pbm._last_clear_count >=
      PSTRACE_BUF_SIZE) ?
      pbm._tail :
      pbm._last_clear_count %
       PSTRACE_BUF_SIZE;
   } else {
    *len_to_copy = 0;
    *start_index = 0;
   }
  } else {
   /* Wait for cur_count to increment until we can */
   /* copy entire buffer starting from counter     */
   *len_to_copy = (pbm._count - pbm._last_clear_count >=
     PSTRACE_BUF_SIZE) ?
            PSTRACE_BUF_SIZE :
            kcounter + PSTRACE_BUF_SIZE -
             pbm._last_clear_count;
   if (*len_to_copy > PSTRACE_BUF_SIZE)
    *len_to_copy = PSTRACE_BUF_SIZE;
   if (pbm._last_clear_count > kcounter) {
    *start_index =
     (pbm._count - pbm._last_clear_count >=
      PSTRACE_BUF_SIZE) ?
      kcounter % PSTRACE_BUF_SIZE :
      pbm._last_clear_count %
       PSTRACE_BUF_SIZE;
   } else {
    *start_index = kcounter % PSTRACE_BUF_SIZE;
   }
  }
 }
 pr_info("COPY LEN: kcounter=%ld,pbm._count=%ld,pbm._last_clear_count=%ld,len_to_copy=%ld,start_index=%ld,\n",
        kcounter, pbm._count, pbm._last_clear_count, *len_to_copy,
        *start_index);
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
 */
long pstrace_get(struct pstrace *buf, long *counter)
{
 int i = 0; /* index for ring buffer */
 int j = 0; /* index for copied buffer */
 int r; /* index for printk traversal */
 long len_to_copy;
 long start_index;
 int chunk_len;
 int leftover_len;
 unsigned long flags;
 struct pstrace_event get_event = { .counter =
         *counter + PSTRACE_BUF_SIZE,
        .is_call_by_interrupt = false,
        .is_pstrace_clear_set = false };
 DECLARE_WAIT_QUEUE_HEAD(wait_queue_head);
 DEFINE_WAIT(w);
 spin_lock_irqsave(&pbm_lock, flags);
 /* Initialize copy params */
 len_to_copy = 0;
 start_index = 0;
 /* Figure out length to copy in advance for buffer allocation */
 set_copy_params(&len_to_copy, &start_index, *counter);
 /* Counter = 0 case */
 pr_info("ADRIEN: copying..\n");
 if (!*counter) {
  if (pbm._count > PSTRACE_BUF_SIZE) {
   for (i = start_index; i < PSTRACE_BUF_SIZE; i++) {
    pr_info(" copying %d into buf[%d]\n",
           pbm.buf[i].pid, j + 1);
    buf[j++] = pbm.buf[i];
   }
   for (i = 0;
        i < len_to_copy - (PSTRACE_BUF_SIZE - start_index);
        i++) {
    pr_info(" copying %d into buf[%d]\n",
           pbm.buf[i].pid, j + 1);
    buf[j++] = pbm.buf[i];
   }
  } else {
   for (i = start_index; i < PSTRACE_BUF_SIZE; i++) {
    pr_info(" copying %d into buf[%d]\n",
           pbm.buf[i].pid, j + 1);
    buf[j++] = pbm.buf[i];
   }
  }
  /* Counter should always be count for this case*/
  *counter = pbm._count;
  spin_unlock_irqrestore(&pbm_lock, flags);
  /* Counter > 0 case */
 } else {
  spin_unlock_irqrestore(&pbm_lock, flags);
  get_event.wq = &wait_queue_head;
  list_add_tail(&(get_event.list), &pstrace_event_list);
  while (!get_event.is_pstrace_clear_set &&
         !get_event.is_call_by_interrupt &&
         pbm._count < get_event.counter) {
   pr_debug("I am called!!!========> %ld vs %ld\nis_pstrace_clear_set: %d, is_call_by_interrupt: %d\n",
    pbm._count, get_event.counter,
    get_event.is_pstrace_clear_set,
    get_event.is_call_by_interrupt);
   prepare_to_wait(get_event.wq, &w, TASK_INTERRUPTIBLE);
   schedule();
   if (signal_pending(current)) {
    get_event.is_call_by_interrupt = true;
    break;
   }
  }
  list_del(&(get_event.list));
  finish_wait(get_event.wq, &w);
  /* Return EINTR when the program is exited by interrupt */
  if (get_event.is_call_by_interrupt)
   return -EINTR;
  pr_debug("counter pbm._count: %ld, *counter: %ld awakening...\n",
         pbm._count, *counter);
  pr_info("ADRIEN: buffer_state:\n");
  for (r = 0; r < PSTRACE_BUF_SIZE; r++)
   pr_info("  buf[%d] = %d\n", r, buf[r].pid);
  spin_lock_irqsave(&pbm_lock, flags);
  pr_info("ADRIEN: copying..\n");
  chunk_len = PSTRACE_BUF_SIZE - start_index;
  if (len_to_copy <= chunk_len) {
   /* There's enough to copy the entire thing over in one go */
   for (i = start_index; i < PSTRACE_BUF_SIZE; i++) {
    pr_info(" copying %d into buf[%d]\n",
           pbm.buf[i].pid, j + 1);
    buf[j++] = pbm.buf[i];
   }
  } else {
   /* Copy in two chunks, from start_index to end, then from 0 to leftover */
   for (i = start_index; i < PSTRACE_BUF_SIZE; i++) {
    pr_info(" copying %d into buf[%d]\n",
           pbm.buf[i].pid, j + 1);
    buf[j++] = pbm.buf[i];
   }
   leftover_len = len_to_copy - chunk_len;
   for (i = 0; i < leftover_len; i++) {
    pr_info(" copying %d into buf[%d]\n",
           pbm.buf[i].pid, j + 1);
    buf[j++] = pbm.buf[i];
   }
  }
  /* If less than max records are copied, update counter to last copied value */
  if (len_to_copy > 0 && len_to_copy < PSTRACE_BUF_SIZE) {
   *counter = (pbm._count - pbm._last_clear_count >=
        PSTRACE_BUF_SIZE) ?
        pbm._count + PSTRACE_BUF_SIZE +
         len_to_copy :
        pbm._last_clear_count + len_to_copy;
  } else {
   /* Otherwise update counter to current value of buffer counter */
   *counter = pbm._count;
  }
  spin_unlock_irqrestore(&pbm_lock, flags);
 }
 return len_to_copy;
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 */
long pstrace_clear(void)
{
 struct pstrace_event *e;
 pr_info("PSTRACE CLEAR is called\n");
 list_for_each_entry(e, &pstrace_event_list, list) {
  e->is_pstrace_clear_set = true;
  wake_up_interruptible(e->wq);
 }
 spin_lock(&pbm_lock);
 pbm._last_clear_count = pbm._count;
 spin_unlock(&pbm_lock);
 return 0;
}
pid_t pstrace_target_pid(void)
{
 return tpm._target_pid;
}
/* Add a record of the state change into the ring buffer.
 * state & 0x4000 => Decativate Add
 * state & 0x2000 => Activate WAKE_UP
 */
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long flag;
 struct pstrace trace;
 if (!tpm._trace_enabled)
  return;
 if (tpm._target_pid != -1 && tpm._target_pid != p->pid)
  return;
 /* Set trace details */
 if (!(state & PSTRACE_ADD_DISABLE)) {
  memcpy(&(trace.comm), p->comm, 16);
  state = state & (~PSTRACE_WAKE_UP_ENABLED);
  state = state & (~PSTRACE_ADD_DISABLE);
  trace.state = state;
  trace.pid = p->pid;
  trace.tid = p->tgid;
  spin_lock_irqsave(&pbm_lock, flag);
  /* Add trace to ring buffer */
  pbm.buf[pbm._tail++] = trace;
  pbm._tail %= PSTRACE_BUF_SIZE;
  pbm._count++;
  spin_unlock_irqrestore(&pbm_lock, flag);
 }
 if (state & PSTRACE_WAKE_UP_ENABLED) {
  /* This wake_up causes deadlock in ARM settings*/
  struct pstrace_event *e;
  list_for_each_entry(e, &pstrace_event_list, list) {
   if (pbm._count > e->counter)
    wake_up_interruptible(e->wq);
  }
 }
};
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 return pstrace_enable(pid);
};
SYSCALL_DEFINE0(pstrace_disable)
{
 return pstrace_disable();
};
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter)
{
 long kcounter;
 struct pstrace *kbuf;
 long len_to_copy;
 pr_info("ADRIEN: before copy_from_user\n");
 if (copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
 pr_info("ADRIEN: after copy_from_user\n");
 if (kcounter < 0)
  return -EINVAL;
 kbuf = kmalloc((PSTRACE_BUF_SIZE) * sizeof(struct pstrace), GFP_KERNEL);
 if (kbuf == NULL)
  return -ENOMEM;
 len_to_copy = pstrace_get(kbuf, &kcounter);
 if (len_to_copy < 0)
  return len_to_copy;
 pr_info("ADRIEN: before copy_TO_user\n");
 if (copy_to_user(buf, kbuf, len_to_copy * sizeof(struct pstrace)))
  return -EFAULT;
 if (copy_to_user(counter, &kcounter, sizeof(long)))
  return -EFAULT;
 pr_info("ADRIEN: after copy_TO_user\n");
 kfree(kbuf);
 return len_to_copy;
};
SYSCALL_DEFINE0(pstrace_clear)
{
 return pstrace_clear();
};