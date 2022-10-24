#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
static struct buffer rb;
static DECLARE_WAIT_QUEUE_HEAD(wait_q);
static DEFINE_SPINLOCK(pstrace_lock);
static atomic_t current_state = ATOMIC_INIT(TRACK_NONE);
static atomic_t pstrace_pid = ATOMIC_INIT(-10);
static atomic_t global_counter = ATOMIC_INIT(0);
static atomic_t local_counter = ATOMIC_INIT(0);
static atomic_t clear_flag = ATOMIC_INIT(0);
static atomic_t waiting_processes = ATOMIC_INIT(0);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if (pid < -1)
  return -EINVAL;
 preempt_disable();
 /* Validate passed PID */
 atomic_set(&pstrace_pid, pid);
 if (pid == -1)
  atomic_set(&current_state, TRACK_ALL);
 else
  atomic_set(&current_state, TRACK_PID);
 preempt_enable();
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 atomic_set(&current_state, TRACK_NONE);
 return 0;
}
static void extract_info(struct pstrace *bn, struct task_struct *p, int state)
{
 bn->pid = task_pid_nr(p);
 bn->tid = task_tgid_nr(p);
 bn->state = state;
 get_task_comm(bn->comm, p);
}
void pstrace_add(struct task_struct *p, long state)
{
 int idx;
 unsigned long flags;
 if (atomic_read(&current_state) == TRACK_NONE)
  return;
 if (state != TASK_RUNNING && state != TASK_INTERRUPTIBLE &&
     state != TASK_UNINTERRUPTIBLE && state != TASK_RUNNABLE &&
     state != __TASK_STOPPED && state != EXIT_DEAD &&
     state != EXIT_ZOMBIE && state != -1)
  return;
 if (!p || state == -1)
  goto wake_up;
 if (atomic_read(&current_state) == TRACK_PID &&
     atomic_read(&pstrace_pid) != task_pid_nr(p)) {
  return;
 }
 idx = atomic_read(&local_counter) % PSTRACE_BUF_SIZE;
 spin_lock_irqsave(&pstrace_lock, flags);
 extract_info(&rb.process_list[idx], p, state);
 spin_unlock_irqrestore(&pstrace_lock, flags);
 atomic_inc(&global_counter);
 atomic_inc(&local_counter);
 return;
wake_up:
 wake_up_all(&wait_q);
}
static void copy_to_kbuf(struct pstrace *kbuf, long start, long end)
{
 int i, idx;
 for (i = 0; start < end; i++) {
  idx = start % PSTRACE_BUF_SIZE;
  kbuf[i].pid = rb.process_list[idx].pid;
  kbuf[i].tid = rb.process_list[idx].tid;
  strncpy(kbuf[i].comm, rb.process_list[idx].comm, 16);
  kbuf[i].state = rb.process_list[idx].state;
  start++;
 }
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace *, buf, long *, counter)
{
 int kcounter;
 long start, end, i, valid_end;
 struct pstrace *kbuf;
 size_t size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 if (kcounter < 0)
  return -EINVAL;
 kbuf = kmalloc(size, GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
 if (kcounter == 0) {
  if (atomic_read(&local_counter) < PSTRACE_BUF_SIZE) {
   start = 0;
   end = atomic_read(&local_counter);
  } else {
   start = atomic_read(&local_counter) % PSTRACE_BUF_SIZE;
   end = start + PSTRACE_BUF_SIZE;
  }
  spin_lock(&pstrace_lock);
  copy_to_kbuf(kbuf, start, end);
  spin_unlock(&pstrace_lock);
  end = atomic_read(&global_counter);
  goto final;
 } else {
  if (atomic_read(&local_counter) ==
      atomic_read(&global_counter)) {
   valid_end =
    atomic_read(&global_counter) - PSTRACE_BUF_SIZE;
  } else {
   valid_end = atomic_read(&global_counter) -
        atomic_read(&local_counter);
  }
  if (kcounter + PSTRACE_BUF_SIZE < valid_end) {
   end = atomic_read(&global_counter);
   goto final;
  }
  atomic_inc(&waiting_processes);
  if (wait_event_interruptible(
       wait_q,
       atomic_read(&clear_flag) ||
        atomic_read(&global_counter) >=
         kcounter + PSTRACE_BUF_SIZE)) {
   kfree(kbuf);
   return -EINTR;
  }
  spin_lock(&pstrace_lock);
  if (atomic_read(&global_counter) - kcounter <=
      PSTRACE_BUF_SIZE) {
   start = kcounter;
   end = atomic_read(&global_counter);
  } else {
   /* If cleared and local counter is less than PSTRACE_BUF_SIZE */
   if (atomic_read(&local_counter) - PSTRACE_BUF_SIZE <
       0) {
    start = 0;
    end = atomic_read(&local_counter);
   } else {
    start = atomic_read(&local_counter) -
     PSTRACE_BUF_SIZE;
    end = kcounter + PSTRACE_BUF_SIZE;
   }
  }
  copy_to_kbuf(kbuf, start, end);
  spin_unlock(&pstrace_lock);
  atomic_dec(&waiting_processes);
 }
final:
 i = atomic_read(&global_counter);
 if (put_user(end, counter) || copy_to_user(buf, kbuf, size)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return 0;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 atomic_set(&clear_flag, 1);
 wake_up_all(&wait_q);
 while (atomic_read(&waiting_processes) != 0)
  ;
 atomic_set(&clear_flag, 0);
 spin_lock(&pstrace_lock);
 memset(rb.process_list, 0,
        sizeof(PSTRACE_BUF_SIZE * sizeof(struct pstrace)));
 spin_unlock(&pstrace_lock);
 atomic_set(&local_counter, 0);
 return 0;
}