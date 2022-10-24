#include<linux/syscalls.h>
#include<linux/uaccess.h>
#include<linux/pstrace.h>
#include <linux/string.h>
#include <linux/slab.h>
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable,
  pid_t, pid)
{
 unsigned long flags;
 //printk("[pstrace_enable]");
 spin_lock_irqsave(&process_list_lock, flags);
 if (pid != -1 && !is_valid_pid(pid))
  return -EINVAL;
 if (tracking_mode == TRACK_ALL || tracking_mode == TRACK_ALL_EXCEPT) {
  spin_unlock_irqrestore(&process_list_lock, flags);
  return 0;
 } else if (pid == -1) {
  tracking_mode = TRACK_ALL;
  reset_enabled_and_disabled();
 } else {
  int loc = check_if_process_in_list(enabled_processes,
    pid, enabled_process_count);
  if (loc == -1) {
   tracking_mode = TRACK_SOME;
   enabled_processes[enabled_process_count] = pid;
   enabled_process_count = enabled_process_count + 1;
  } else {
   spin_unlock_irqrestore(&process_list_lock, flags);
   return -EINVAL;
  }
 }
 spin_unlock_irqrestore(&process_list_lock, flags);
 //printk("[pstrace_enable] tracking mode set to %d", tracking_mode);
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable,
  pid_t, pid)
{
 unsigned long flags;
 //printk("[pstrace_disable]");
 spin_lock_irqsave(&process_list_lock, flags);
 if (tracking_mode == TRACK_NONE) {
  spin_unlock_irqrestore(&process_list_lock, flags);
  return 0;
 } else if (pid == -1) {
  tracking_mode = TRACK_NONE;
  reset_enabled_and_disabled();
 } else if (tracking_mode == TRACK_ALL
  || tracking_mode == TRACK_ALL_EXCEPT) {
  if (check_if_process_in_list(disabled_processes,
   pid, disabled_process_count) != -1) {
   spin_unlock_irqrestore(&process_list_lock, flags);
   return 0;
  } else {
   tracking_mode = TRACK_ALL_EXCEPT;
   disabled_processes[disabled_process_count] = pid;
   disabled_process_count = disabled_process_count + 1;
  }
 } else {
  int loc;
  loc = check_if_process_in_list(enabled_processes,
   pid, enabled_process_count);
  if (loc >= 0) {
   enabled_processes[loc] = -1;
  } else {
   spin_unlock_irqrestore(&process_list_lock, flags);
   return -EINVAL;
  }
 }
 spin_unlock_irqrestore(&process_list_lock, flags);
 //printk("[pstrace_disable] tracking mode set to %d", tracking_mode);
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
SYSCALL_DEFINE3(pstrace_get,
  pid_t, pid,
  struct pstrace __user *, buf,
  long __user *, counter)
{
 int success;
 if (true) {
  unsigned long flags;
  long *kcounter;
  struct pstrace *kbuf;
  struct task_struct *handler;
  struct request *req;
  unsigned long ring_buf_flags;
  kcounter = kmalloc(sizeof(long), GFP_KERNEL);
  if (!kcounter)
   return -ENOMEM;
  success = copy_from_user(kcounter, counter, sizeof(long));
  if (success != 0) {
   kfree(kcounter);
   return -EFAULT;
  }
  kbuf = kmalloc(sizeof(struct pstrace)*PSTRACE_BUF_SIZE,
   GFP_KERNEL);
  if (!kbuf) {
   kfree(kcounter);
   return -ENOMEM;
  }
  req = kmalloc(sizeof(struct request), GFP_KERNEL);
  if (!req) {
   kfree(kbuf);
   kfree(kcounter);
   return -ENOMEM;
  }
  create_request(req, pid, kcounter, kbuf);
  spin_lock_irqsave(&ring_buf_lock, ring_buf_flags);
  if ((*kcounter)+PSTRACE_BUF_SIZE <= ring_buffer.counter
   || *kcounter <= 0) {
   //Call add to buffer here
   copy_from_buf_to_req(&ring_buffer, req);
   spin_unlock_irqrestore(&ring_buf_lock, ring_buf_flags);
   req->complete_flag = true;
   success = copy_to_user(buf, kbuf,
   sizeof(struct pstrace) * PSTRACE_BUF_SIZE);
   if (success != 0) {
    kfree(req);
    kfree(kbuf);
    kfree(kcounter);
    return -EFAULT;
   }
   success = copy_to_user(counter, kcounter, sizeof(long));
   if (success != 0) {
    kfree(req);
    kfree(kbuf);
    kfree(kcounter);
    return -EFAULT;
   }
   kfree(req);
   kfree(kbuf);
   kfree(kcounter);
   return 0;
  }
  spin_unlock_irqrestore(&ring_buf_lock, ring_buf_flags);
  spin_lock_irqsave(&request_list_lock, flags);
  success = save_request(req);
  spin_unlock_irqrestore(&request_list_lock, flags);
  if (success < 0) {
   kfree(req);
   kfree(kbuf);
   kfree(kcounter);
   return -ENOMEM;
  }
  handler = listener(req);
  //if (!handler)
 //printk("[pstrace_get] handler null before while starts");
  DEFINE_WAIT(wait);
  while (!(req->complete_flag)) {
   //printk("[pstrace_enable] calling prepare_to_sleep");
   prepare_to_wait(&pstrace_wait_q, &wait,
    TASK_INTERRUPTIBLE);
   if (signal_pending(current)) {
    //printk("[pstrace_get] signal is pending");
    //if (!handler)
  //printk(KERN_WARNING "[pstrace_get] handler is null");
    //else
    if (handler)
     thread_cleanup(handler);
    break;
   }
   schedule();
   //printk("[pstrace_enable] woke up from sleep");
  }
  //printk("[pstrace_enable] calling finish_wait");
  finish_wait(&pstrace_wait_q, &wait);
  //printk("[pstrace_enable] finsihed waiting");
  success = copy_to_user(buf, kbuf,
  sizeof(struct pstrace) * PSTRACE_BUF_SIZE);
  if (success != 0) {
   kfree(req);
   kfree(kbuf);
   kfree(kcounter);
   return -EFAULT;
  }
  success = copy_to_user(counter, kcounter, sizeof(long));
  if (success != 0) {
   kfree(req);
   kfree(kbuf);
   kfree(kcounter);
   return -EFAULT;
  }
  kfree(req);
  kfree(kbuf);
  kfree(kcounter);
 }
 return 0;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear,
  pid_t, pid)
{
 unsigned long ring_buf_flags;
 unsigned long request_list_flags;
 struct request *pos, *next;
 //printk(KERN_INFO"[pstrace_clear]");
 spin_lock_irqsave(&request_list_lock, request_list_flags);
 spin_lock_irqsave(&ring_buf_lock, ring_buf_flags);
 if (pid == -1) {
  //for evert element in the request list empty
  list_for_each_entry_safe(pos, next, &request_list_head, list) {
   copy_from_buf_to_req(&ring_buffer, pos);
   pos->complete_flag = true;
   list_del(&pos->list);
  }
  ring_buffer.head = 0;
  ring_buffer.current_size = 0;
 } else {
  int i;
  int current_iteration;
  i = ring_buffer.head;
  //dump all those get requests which match pid
  list_for_each_entry_safe(pos, next, &request_list_head, list) {
   if (pos->pid == pid) {
    copy_from_buf_to_req(&ring_buffer, pos);
    pos->complete_flag = true;
    list_del(&pos->list);
   }
  }
  //remove the pid matching the clear from ring buffer
  for (current_iteration = 0;
  current_iteration < ring_buffer.current_size;
  current_iteration++) {
   if (ring_buffer.buf[i].pid == pid) {
    int j;
    int k;
    j = i;
    for (k = current_iteration;
    k < ring_buffer.current_size;
    k++) {
     ring_buffer.buf[j] =
     ring_buffer.buf
     [(j + 1) % PSTRACE_BUF_SIZE];
     j = (j + 1)
     % PSTRACE_BUF_SIZE;
    }
    ring_buffer.current_size =
    ring_buffer.current_size - 1;
   }
   i = (i+1)%PSTRACE_BUF_SIZE;
  }
 }
 spin_unlock_irqrestore(&ring_buf_lock, ring_buf_flags);
 spin_unlock_irqrestore(&request_list_lock, request_list_flags);
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 unsigned long flags;
 unsigned long ring_buf_flags;
 unsigned long request_list_flags;
 if ((p->state & __TASK_STOPPED)
  || p->state == TASK_INTERRUPTIBLE
  || (p->state == TASK_UNINTERRUPTIBLE)
  || p->state == TASK_RUNNING
  || p->exit_state == EXIT_DEAD
  || p->exit_state == EXIT_ZOMBIE) {
  spin_lock_irqsave(&process_list_lock, flags);
  if (tracking_mode == TRACK_ALL ||
   (tracking_mode == TRACK_ALL_EXCEPT &&
 check_if_process_in_list(disabled_processes,
 p->pid, disabled_process_count) == -1)
   ||
   (tracking_mode == TRACK_SOME &&
  check_if_process_in_list(enabled_processes,
  p->pid, enabled_process_count) != -1)
   ){
   struct request *pos, *next;
   long state_to_be_stored;
   spin_unlock_irqrestore(&process_list_lock, flags);
   local_irq_save(flags);
   spin_lock_irqsave(&request_list_lock,
    request_list_flags);
   spin_lock_irqsave(&ring_buf_lock, ring_buf_flags);
   memcpy(ring_buffer.buf[ring_buffer.head].comm,
    p->comm, sizeof(char)*16);
   ring_buffer.buf[ring_buffer.head].pid = p->pid;
   state_to_be_stored = p->state;
   if (p->exit_state == EXIT_DEAD
    || p->exit_state == EXIT_ZOMBIE)
    state_to_be_stored = p->exit_state;
   ring_buffer.buf[ring_buffer.head].state =
     state_to_be_stored;
   ring_buffer.head = (ring_buffer.head + 1)
    % PSTRACE_BUF_SIZE;
   ring_buffer.counter += 1;
   ring_buffer.current_size += 1;
   if (ring_buffer.current_size > PSTRACE_BUF_SIZE)
    ring_buffer.current_size = PSTRACE_BUF_SIZE;
   list_for_each_entry_safe(pos, next,
    &request_list_head, list) {
    if (ring_buffer.counter ==
    PSTRACE_BUF_SIZE + *(pos->counter)) {
     copy_from_buf_to_req(&ring_buffer, pos);
     pos->complete_flag = true;
     list_del(&pos->list);
    }
   }
   spin_unlock_irqrestore(&ring_buf_lock, ring_buf_flags);
   spin_unlock_irqrestore(&request_list_lock,
     request_list_flags);
   local_irq_restore(flags);
  } else {
   spin_unlock_irqrestore(&process_list_lock, flags);
  }
 }
}