// SPDX-License-Identifier: no checkpatch warning
#include <linux/pstrace.h>
pid_t curr_tracking_pid = -2; /* -2 means no tracking, -1 means track all, other is the tracking pid */
struct pstrace_ring_buffer ring_buf;
DEFINE_SPINLOCK(renew_tracking_pid_lock);
DEFINE_SPINLOCK(ring_buf_lock);
DEFINE_SPINLOCK(req_lst_lock);
LIST_HEAD(req_lst_head);
// wait_queue_head_t req_wait_que;
DECLARE_WAIT_QUEUE_HEAD(req_wait_que);
/*441*/
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flags;
 // todo check invalid pids
 if (pid != -1 && is_pid_valid(pid) == 0)
  return -EINVAL;
 spin_lock_irqsave(&renew_tracking_pid_lock, flags);
 /* set to the valid pid*/
 curr_tracking_pid = pid;
 // printk(KERN_INFO "enable, curr_tracking_pid %d\n", curr_tracking_pid);
 spin_unlock_irqrestore(&renew_tracking_pid_lock, flags);
 return 0;
}
/*442*/
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flags;
 spin_lock_irqsave(&renew_tracking_pid_lock, flags);
 /* set to invalid pid*/
 curr_tracking_pid = -2;
 // printk(KERN_INFO "disable, curr_tracking_pid %d\n", curr_tracking_pid);
 // print_ring_buf();
 spin_unlock_irqrestore(&renew_tracking_pid_lock, flags);
 return 0;
}
/*443*/
SYSCALL_DEFINE2(pstrace_get, struct pstrace *, buf, long *, counter)
{
 long kcounter, num_cpy, start, tail = 0;
 long kbuf_size = sizeof(struct pstrace) * PSTRACE_BUF_SIZE;
 struct pstrace *kbuf = NULL;
 struct ring_request *req;
 unsigned long flags;
 DEFINE_WAIT(wait);
 if (copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
 kbuf = kmalloc(kbuf_size, GFP_USER);
 if (!kbuf)
  return -ENOMEM;
 /* invalid counter value*/
 if (kcounter < 0) {
  kfree(kbuf);
  return -EINVAL;
 }
 tail = kcounter + PSTRACE_BUF_SIZE;
 /* immediately return: counter == 0 */
 if (kcounter == 0) {
  spin_lock_irqsave(&ring_buf_lock, flags);
  start = max(ring_buf.start, ring_buf.cnt - PSTRACE_BUF_SIZE);
  tail = ring_buf.cnt;
  ring_buf_copy_to_kbuf(kbuf, start, tail);
  if (copy_to_user(buf, kbuf, kbuf_size))
   return -EFAULT;
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  kfree(kbuf);
  num_cpy = tail - start;
  if (copy_to_user(counter, &tail, sizeof(long)))
   return -EFAULT;
  return num_cpy;
 }
 /* immediately return: tail < cnt */
 spin_lock_irqsave(&ring_buf_lock, flags);
 if (tail <= ring_buf.cnt) {
  start = max(ring_buf.start, ring_buf.cnt - PSTRACE_BUF_SIZE);
  /* tail is not in the ring_buf range */
  if (start >= tail) {
   tail = ring_buf.cnt;
   spin_unlock_irqrestore(&ring_buf_lock, flags);
   num_cpy = 0;
   if (copy_to_user(counter, &tail, sizeof(long)))
    return -EFAULT;
   kfree(kbuf);
   return num_cpy;
  }
  /* tail is in the ringn_buf range */
  ring_buf_copy_to_kbuf(kbuf, start, tail);
  spin_unlock_irqrestore(&ring_buf_lock, flags);
  if (copy_to_user(buf, kbuf, kbuf_size))
   return -EFAULT;
  kfree(kbuf);
  num_cpy = tail - start;
  if (copy_to_user(counter, &tail, sizeof(long)))
   return -EFAULT;
  return num_cpy;
 }
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 /* tail is larger than cnt, add a request and wait for response */
 spin_lock_irqsave(&ring_buf_lock, flags);
 start = max(ring_buf.start, kcounter);
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 req = add_request(kbuf, &kcounter);
 if (!req) {
  kfree(kbuf);
  return -ENOMEM;
 }
 /* sleep to wait */
 while (1) {
  /* p sleep*/
  prepare_to_wait(&req_wait_que, &wait, TASK_INTERRUPTIBLE);
  if (req->flag)
   break;
  if (signal_pending(current))
   break;
  schedule();
 }
 finish_wait(&req_wait_que, &wait);
 spin_lock_irqsave(&ring_buf_lock, flags);
 // tail = ring_buf.cnt;
 start = max(start, ring_buf.cnt - PSTRACE_BUF_SIZE);
 ring_buf_copy_to_kbuf(kbuf, start, tail);
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 kfree(req);
 if (copy_to_user(buf, kbuf, kbuf_size))
  return -EFAULT;
 kfree(kbuf);
 num_cpy = tail - start;
 if (copy_to_user(counter, &tail, sizeof(long)))
  return -EFAULT;
 return num_cpy;
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
 struct ring_request *pos, *next;
 unsigned long flags, req_flags;
 spin_lock_irqsave(&ring_buf_lock, flags);
 spin_lock_irqsave(&req_lst_lock, req_flags);
 /* go through the request list and check for if need to wake up */
 list_for_each_entry_safe(pos, next, &req_lst_head, req_node) {
  pos->flag = true;
  list_del(&pos->req_node);
  /* wake up the whole queue, the unsatisfied ones will sleep again */
  wake_up(&req_wait_que);
 }
 spin_unlock_irqrestore(&req_lst_lock, req_flags);
 ring_buf.start = ring_buf.cnt;
 spin_unlock_irqrestore(&ring_buf_lock, flags);
 return 0;
}
void ring_buf_copy_to_kbuf(struct pstrace *kbuf, long start, long tail)
{
 int i;
 if (tail - start > PSTRACE_BUF_SIZE)
  start = tail - PSTRACE_BUF_SIZE;
 for (i = 0; i < tail-start; i++)
  kbuf[i] = ring_buf.buf[(start + i) % PSTRACE_BUF_SIZE];
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 struct ring_request *pos, *next;
 unsigned long flags, req_flags;
 /* check if the tracing is enabled */
 if (!(curr_tracking_pid == -1
 || curr_tracking_pid == p->tgid))
  return;
 /* check if the state is interested */
 if (!(state == TASK_RUNNING
 || state == TASK_RUNNABLE
 || state == TASK_INTERRUPTIBLE
 || state == TASK_UNINTERRUPTIBLE
 || state == __TASK_STOPPED
 || p->state == __TASK_STOPPED
 || p->exit_state == EXIT_DEAD
 || p->exit_state == EXIT_ZOMBIE))
  return;
 /* if the process is stopped, record exit_state instead of state */
 if (p->exit_state == EXIT_DEAD || p->exit_state == EXIT_ZOMBIE)
  state = p->exit_state;
 /* write to the ring buf*/
 if (p->state == __TASK_STOPPED)
  write_to_buf(p, p->state);
 else
  write_to_buf(p, state);
 /* see if need to wake up the copy to user routine */
 spin_lock_irqsave(&ring_buf_lock, flags);
 spin_lock_irqsave(&req_lst_lock, req_flags);
 list_for_each_entry_safe(pos, next, &req_lst_head, req_node) {
  if (*(pos->counter) + PSTRACE_BUF_SIZE == ring_buf.cnt) {
   pos->flag = true;
   list_del(&pos->req_node);
   wake_up(&req_wait_que);
  }
 }
 spin_unlock_irqrestore(&req_lst_lock, req_flags);
 spin_unlock_irqrestore(&ring_buf_lock, flags);
}
/* helper functions */
int is_pid_valid(pid_t pid)
{
 if (pid == 0)
  return 1;
 if (find_task_by_vpid(pid) == NULL)
  return 0;
 else
  return 1;
}
/*
 * write task_struct to ring_buf with detected state change
 */
void write_to_buf(struct task_struct *p, long state)
{
 /* the position in the ring buf to write new element */
 int idx;
 unsigned long flags;
 spin_lock_irqsave(&ring_buf_lock, flags);
 /* the idx to write into in ring buf */
 idx = ring_buf.cnt++ % PSTRACE_BUF_SIZE;
 strcpy(ring_buf.buf[idx].comm, p->comm);
 ring_buf.buf[idx].state = state;
 /* the thread group id (tgid) in kernel space is the pid in the user space*/
 ring_buf.buf[idx].pid = p->tgid;
 /* the process id (tid) in kernel space is the thread id in the user space*/
 ring_buf.buf[idx].tid = p->pid;
 spin_unlock_irqrestore(&ring_buf_lock, flags);
}
struct ring_request *add_request(struct pstrace *buf, long *counter)
{
 struct ring_request *new_request;
 unsigned long flags;
 new_request = kmalloc(sizeof(struct ring_request), GFP_KERNEL);
 if (!new_request)
  return NULL;
 new_request->counter = counter;
 new_request->buf = buf;
 new_request->flag = false;
 spin_lock_irqsave(&req_lst_lock, flags);
 list_add_tail(&new_request->req_node, &req_lst_head);
 spin_unlock_irqrestore(&req_lst_lock, flags);
 return new_request;
}
char *map_state_name(long state)
{
 char *res;
 if (state == TASK_RUNNING)
  res = "TASK_RUNNING";
 if (state == TASK_RUNNABLE)
  res = "TASK_RUNNABLE";
 if (state == TASK_INTERRUPTIBLE)
  res = "TASK_INTERRUPTIBLE";
 if (state == TASK_UNINTERRUPTIBLE)
  res = "TASK_UNINTERRUPTIBLE";
 if (state == EXIT_DEAD)
  res = "EXIT_DEAD";
 if (state == EXIT_ZOMBIE)
  res = "EXIT_ZOMBIE";
 if (state == __TASK_STOPPED)
  res = "__TASK_STOPPED";
 return res;
}
/*
 * void print_ring_buf(void)
 * {
 *  int i;
 *
 *  // printk(KERN_INFO "printing ring buffer:\n");
 *  // printk(KERN_INFO "cnt %ld\n ", ring_buf.cnt);
 *  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
 *   printk(KERN_INFO "%d %s %s %d %d\n", i,
 *     ring_buf.buf[i].comm,
 *     map_state_name(ring_buf.buf[i].state),
 *     ring_buf.buf[i].pid,
 *     ring_buf.buf[i].tid);
}*
 */