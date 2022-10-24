#include <linux/pstrace.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>
#include <linux/rwlock_types.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>
#include <linux/smp.h>
/* 
 * The process states traced by pstrace
 */
static long traced_states[NUMBER_OF_TRACED_STATES] = { TASK_RUNNING, 
TASK_INTERRUPTIBLE, TASK_UNINTERRUPTIBLE, __TASK_STOPPED };
/* 
 * The process exit states traced by pstrace
 */
static long traced_exit_states[NUMBER_OF_TRACED_EXIT_STATES] = { EXIT_ZOMBIE, 
EXIT_DEAD };
/* 
 * The ring buffer to store state change events 
 */
static struct pstrace pstrace_buf[PSTRACE_BUF_SIZE] = {{{0}}};
/*
 * The ring buffer counter to store the number of past state change events
 */
static long pstrace_buf_counter = 0;
/* 
 * The ring buffer head index
 */
static int pstrace_buf_head = 0;
/* 
 * The list to store the traced processes by pstrace
 */
static LIST_HEAD(pstrace_enable_process_list);
/* 
 * The list to store the processes not being traced by pstrace
 */
static LIST_HEAD(pstrace_disable_process_list);
/* 
 * Boolean indicating if all processes are being traced by pstrace
 */
static bool all_processes_traced = false;
/* 
 * Boolean indicateing if pstrace clear is clearing the buffer
 */
static bool pstrace_clear_active = false;
/* 
 * The wait queue of pstrace_get() processes
 */
static DECLARE_WAIT_QUEUE_HEAD(pstrace_get_wait);
static DEFINE_SPINLOCK(clear_lock);
static DEFINE_RWLOCK(pstrace_buf_lock);
static DEFINE_RWLOCK(pstrace_enable_list_lock);
static DEFINE_RWLOCK(pstrace_disable_list_lock);
/*
 * Returns if the ring buffer index is valid
static bool is_valid_buffer_index(int index)
{
 int start;
 int end;
 int stop;
 if (pstrace_buf_length == 0)
  return false;
 start = pstrace_buf_head;
 end = (pstrace_buf_head + pstrace_buf_length) % PSTRACE_BUF_SIZE;
 stop = end;
 if (start >= end)
  stop = PSTRACE_BUF_SIZE;
   if (index <= start && index < stop)
  return true;
 start = 0;
 stop = end;
 if (index <= start && index < stop)
  return true;
 return false;
}
 */
/*
 * Copy struct pstrace with process pid from pstrace_buf to buffer from entry 
 * start to entry end.
 */
static int copy_to_buffer_in_range(struct pstrace *buffer, pid_t pid, 
int start, int end)
{
     int index;
 int acc;
 index = 0;
 if (end <= start) {
  end += PSTRACE_BUF_SIZE; 
 }
   while(start < end) {
  acc = start % PSTRACE_BUF_SIZE;
  if ((pstrace_buf[acc].status != UNCLEARED) ||
    (pid != -1 && pstrace_buf[acc].pid != pid)) {
   start++;
   continue;
  }
  buffer[index].pid = pstrace_buf[acc].pid;
  buffer[index].state = pstrace_buf[acc].state;
  buffer[index].status = pstrace_buf[acc].status;
  memcpy(buffer[index].comm, pstrace_buf[acc].comm, 16);
  index++;
  start++;
 }
 return index;
}
/*
 * Get process task_struct by pid.
 */
static struct task_struct *get_process(pid_t pid)
{
 if (pid == 0)
  return &init_task;
 return find_task_by_vpid(pid);
}
/*
 * Returns if a process is being traced by pstrace
 */
static bool process_is_traced(struct task_struct *p)
{ 
 unsigned long flags;
 struct pstrace_process *process;
 pid_t pid;
 pid = p->pid;
   if (all_processes_traced)  {
  read_lock_irqsave(&pstrace_disable_list_lock, flags);
  list_for_each_entry(process, &pstrace_disable_process_list, list) {
   if (process->pid == pid) {
    read_unlock_irqrestore(&pstrace_disable_list_lock, flags);
    return false;
   }
  }
  read_unlock_irqrestore(&pstrace_disable_list_lock, flags);
  return true;
 }
 read_lock_irqsave(&pstrace_enable_list_lock, flags);
 list_for_each_entry(process, &pstrace_enable_process_list, list) {
  if (process->pid == pid) {
   read_unlock_irqrestore(&pstrace_enable_list_lock, flags);
   return true;
  }
 }
 read_unlock_irqrestore(&pstrace_enable_list_lock, flags);
 return false;
}
/*
 * If the state is being traced by pstrace i.e. (state in traced_states) ||
 * (state==TASK_DEAD && exit_state in traced_exit_states), save the 
 * state or exit_state into save_state then return true. Else return false.
 */
static bool state_is_traced(struct task_struct *p, long *save_state)
{ 
 long state;
 long exit_state;
 int i;
 int j;
 state = p->state;
 exit_state = p->exit_state;
   if (state == traced_states[0]) {
  *save_state = state;
  return true;
 }
 for (i = 1; i < NUMBER_OF_TRACED_STATES; i++) {
  if ((state & traced_states[i]) != 0) {
   *save_state = state;
   return true;
  }
 }
 /* TODO: Is this necessary? */
 /* This would handle the case that state is not DEAD 
  * AND not in traced_states, but its exit_state is actually one of
  * EXIT_ZOMBIE or EXIT_DEAD. In this case we do not want to track.
  */
 /* End TODO */
 for (j = 0; j < NUMBER_OF_TRACED_EXIT_STATES; j++) {
  if ((exit_state & traced_exit_states[j]) != 0) {
   *save_state = exit_state;
   return true;
  }
 }
 return false;
}
/*
 * Add a record of the state change into the ring buffer.
 */
void pstrace_add(struct task_struct *p)
{
 unsigned long flags;
 int index;
 long save_state;
 /*
  *  Do nothing if the process is not being traced
  */
 if (!process_is_traced(p))
  return;
 /*
  *  Do nothing if the process state is not being traced
  */
 if (!state_is_traced(p, &save_state))
  return;
 if ((pstrace_buf_counter % 1000 == 0) || 
 ((save_state != 0) && (save_state != 1)))
  printk("[ADD] pid %d state %ld is being traced", p->pid, save_state);
 if(pstrace_clear_active)
  printk("[ADD] pstrace_clear_active is true! Waiting..");
 /*
  *  Waits if the buffer is being cleared by pstrace_clear()
  */
   spin_lock_irqsave(&clear_lock, flags);
 /*
  *  Add a state change event to the pstrace buffer
  */
 write_lock_irqsave(&pstrace_buf_lock ,flags);
   index = pstrace_buf_counter % PSTRACE_BUF_SIZE;
 pstrace_buf[index].pid = p->pid;
 pstrace_buf[index].state = save_state;
 get_task_comm(pstrace_buf[index].comm, p);
 pstrace_buf[index].status = UNCLEARED;
   if (pstrace_buf_counter >= PSTRACE_BUF_SIZE) {
  /*
   * check if we need to push head forward 
   * we push here incase like counter = 499
   * */
  pstrace_buf_head++;
  pstrace_buf_head = pstrace_buf_head % PSTRACE_BUF_SIZE;
   }
 pstrace_buf_counter++;
 if (pstrace_buf_counter % 1000 == 1)
  printk("[ADD] pstrace_buf_counter %ld", pstrace_buf_counter);
 if (pstrace_buf_counter >= PSTRACE_BUF_SIZE) {
  /* see the implementation in clear and explanation */
  write_unlock_irqrestore(&pstrace_buf_lock ,flags);
  while (wq_has_sleeper(&pstrace_get_wait))
   wake_up(&pstrace_get_wait);
  write_lock_irqsave(&pstrace_buf_lock ,flags);
 }
   write_unlock_irqrestore(&pstrace_buf_lock ,flags);
 spin_unlock_irqrestore(&clear_lock, flags);
 return;
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t __user, pid)
{
   unsigned long flags;
 struct pstrace_process *process; 
 struct pstrace_process *next;
 struct pstrace_process *p_traced;
 struct task_struct *p;
 /*
  * Check value validity
  */
 if (pid < -1)
  return -EINVAL;
 if (pid == -1) {
  /* 
   * Set all_processes_traced to true and clear the pstrace disable list
   */
  write_lock_irqsave(&pstrace_disable_list_lock, flags);
  all_processes_traced = true;
  list_for_each_entry_safe(process, next, &pstrace_disable_process_list,
  list) {
   list_del(&process->list);
   kfree(process);
  }
  write_unlock_irqrestore(&pstrace_disable_list_lock, flags);
  printk("[ENABLE] all_processes_traced %d\n", all_processes_traced);
  return 0;
 }
 /* 
  * Remove the process from the pstrace diable list if found
  */
 write_lock_irqsave(&pstrace_disable_list_lock, flags);
 list_for_each_entry_safe(process, next, &pstrace_disable_process_list,
 list) {
  if (process->pid == pid) {
   list_del(&process->list);
   kfree(process);
   printk("[ENABLE] Delete pid %d from pstrace_disable_process_list\n", pid);
   break;
  }
 }
 write_unlock_irqrestore(&pstrace_disable_list_lock, flags);
 /*
  * Check if the process exists
  */
 read_lock_irqsave(&tasklist_lock, flags);
 p = get_process(pid);
 if (!p) {
  read_unlock_irqrestore(&tasklist_lock, flags);
  printk("[ENABLE] cannot trace non-existing pid %d\n", pid);
  return -EINVAL;
 }
 read_unlock_irqrestore(&tasklist_lock, flags);
 /* 
  * Add the process to the pstrace enable list if not found
  */
 write_lock_irqsave(&pstrace_enable_list_lock, flags);
 list_for_each_entry_safe(process, next, &pstrace_enable_process_list,
 list) {
  if (process->pid == pid) {
   write_unlock_irqrestore(&pstrace_enable_list_lock, flags);
   printk("[ENABLE] pid %d already being traced\n", pid);
   return 0;
  }
 }
 p_traced = kmalloc(sizeof(struct pstrace_process), GFP_KERNEL);
 if (p_traced == NULL) {
  write_unlock_irqrestore(&pstrace_enable_list_lock, flags);
  return -ENOMEM;
 }
 p_traced->pid = pid;
 INIT_LIST_HEAD(&p_traced->list);
 list_add_tail(&p_traced->list, &pstrace_enable_process_list);
 printk("[ENABLE] pid %d added to enable_list \n", pid);
 write_unlock_irqrestore(&pstrace_enable_list_lock, flags);
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t __user, pid)
{
 unsigned long flags;
 struct pstrace_process *process;
 struct pstrace_process *next;
 struct pstrace_process *p_traced;
 struct task_struct *p;
 /*
  *  Check value validity
  */
 if (pid < -1)
  return -EINVAL;
 if (pid == -1) {
  /* 
   * Set all_processes_traced to false and clear the pstrace enable list
   */
  write_lock_irqsave(&pstrace_enable_list_lock, flags);
  all_processes_traced = false;
  list_for_each_entry_safe(process, next, &pstrace_enable_process_list,
  list) {
   list_del(&process->list);
   kfree(process);
  }
  write_unlock_irqrestore(&pstrace_enable_list_lock, flags);
  printk("[DISABLE] all_processes_traced %d\n", all_processes_traced);
  return 0;
 }
 /* 
  * Remove the process from the pstrace enable list if found
  */
 write_lock_irqsave(&pstrace_enable_list_lock, flags);
 list_for_each_entry_safe(process, next, &pstrace_enable_process_list,
 list) {
  if (process->pid == pid) {
   list_del(&process->list);
   kfree(process);
   printk("[DISABLE] Delete pid %d from pstrace_enable_process_list\n", pid);
   break;
  }
 }
 write_unlock_irqrestore(&pstrace_enable_list_lock, flags);
   /*
  * Check if the process exists
  */
 read_lock_irqsave(&tasklist_lock, flags);
 p = get_process(pid);
 if (!p) {
  read_unlock_irqrestore(&tasklist_lock, flags);
  printk("[DISABLE] Do nothing given non-existing pid %d\n", pid);
  return 0;
 }
 read_unlock_irqrestore(&tasklist_lock, flags);
 /* 
  * Add the process to the pstrace disable list if not found
  */
 write_lock_irqsave(&pstrace_disable_list_lock, flags);
 list_for_each_entry_safe(process, next, &pstrace_disable_process_list,
 list) {
  if (process->pid == pid) {
   write_unlock_irqrestore(&pstrace_disable_list_lock, flags);
   printk("[DISABLE] pid %d already in disable_list\n", pid);
   return 0;
  }
 }
 p_traced = kmalloc(sizeof(struct pstrace_process), GFP_KERNEL);
 if (p_traced == NULL) {
  write_unlock_irqrestore(&pstrace_disable_list_lock, flags);
  return -ENOMEM;
 }
 p_traced->pid = pid;
 INIT_LIST_HEAD(&p_traced->list);
 list_add_tail(&p_traced->list, &pstrace_disable_process_list);
 printk("[DISABLE] pid %d added to disable_list \n", pid);
 write_unlock_irqrestore(&pstrace_disable_list_lock, flags);
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
SYSCALL_DEFINE3(pstrace_get, pid_t __user, pid, struct pstrace __user *, buf,
long __user *, counter)
{
 unsigned long flags;
 long k_counter;
 struct pstrace *k_buf;
 int pstrace_buf_tail;
 int num_of_events_copied;
 int num_of_overwrites;
 int num_of_remaining_events;
 if (!buf || !counter || pid < -1)
  return -EINVAL;
 if (copy_from_user(&k_counter, counter, sizeof(k_counter)))
  return -EFAULT;
 k_buf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (k_buf == NULL)
  return -ENOMEM;
 spin_lock_irqsave(&clear_lock, flags);
 read_lock_irqsave(&pstrace_buf_lock ,flags);
 printk("[GET] Buffer Counter = %ld\n", pstrace_buf_counter);
 if (k_counter <= 0) {
  pstrace_buf_tail = pstrace_buf_counter % PSTRACE_BUF_SIZE;
  num_of_events_copied = copy_to_buffer_in_range(k_buf, pid,
  pstrace_buf_head, pstrace_buf_tail);
     spin_unlock_irqrestore(&clear_lock, flags);
  if (copy_to_user(counter, &pstrace_buf_counter, sizeof(long)))
   goto return_fail_copy_to_user;
  if (copy_to_user(buf, k_buf, sizeof(struct pstrace) * PSTRACE_BUF_SIZE))
   goto return_fail_copy_to_user;
     read_unlock_irqrestore(&pstrace_buf_lock ,flags);
  return num_of_events_copied;
 }
 num_of_overwrites = pstrace_buf_counter - (k_counter + PSTRACE_BUF_SIZE);
 if (num_of_overwrites >= PSTRACE_BUF_SIZE) {
  num_of_events_copied = 0;
  spin_unlock_irqrestore(&clear_lock, flags);
  if (copy_to_user(counter, &pstrace_buf_counter, sizeof(long)))
   goto return_fail_copy_to_user;
  if (copy_to_user(buf, k_buf, sizeof(struct pstrace) * PSTRACE_BUF_SIZE))
   goto return_fail_copy_to_user;
  read_unlock_irqrestore(&pstrace_buf_lock ,flags);
  return num_of_events_copied;
 }
 if (num_of_overwrites > 0) {
     num_of_remaining_events = PSTRACE_BUF_SIZE - num_of_overwrites;
  pstrace_buf_tail = (pstrace_buf_head + num_of_remaining_events)
  % PSTRACE_BUF_SIZE;
  num_of_events_copied = copy_to_buffer_in_range(k_buf, pid,
  pstrace_buf_head, pstrace_buf_tail);
  spin_unlock_irqrestore(&clear_lock, flags);
  if (copy_to_user(counter, &pstrace_buf_counter, sizeof(long)))
   goto return_fail_copy_to_user;
  if (copy_to_user(buf, k_buf, sizeof(struct pstrace) * PSTRACE_BUF_SIZE))
   goto return_fail_copy_to_user;
     read_unlock_irqrestore(&pstrace_buf_lock ,flags);
  return num_of_events_copied;
 }
 spin_unlock_irqrestore(&clear_lock, flags);
 DECLARE_WAITQUEUE(wait, current);
 add_wait_queue(&pstrace_get_wait, &wait);
 while (k_counter + PSTRACE_BUF_SIZE  >  pstrace_buf_counter &&
 !pstrace_clear_active) {
  prepare_to_wait(&pstrace_get_wait, &wait, TASK_UNINTERRUPTIBLE);
  /* only after we are sleep, we unlock, so that while writer gain 
   * the clear lock, it stil block until we are on wait queue and unlock read
   * */
  read_unlock_irqrestore(&pstrace_buf_lock ,flags);
  schedule();
     read_lock_irqsave(&pstrace_buf_lock ,flags);
 }
 pstrace_buf_tail = pstrace_buf_head;
 num_of_events_copied = copy_to_buffer_in_range(k_buf, pid,
 pstrace_buf_head, pstrace_buf_tail);
 if (copy_to_user(counter, &pstrace_buf_counter, sizeof(long)))
  goto return_fail_copy_to_user;
 if (copy_to_user(buf, k_buf, sizeof(struct pstrace) * PSTRACE_BUF_SIZE))
  goto return_fail_copy_to_user;
 read_unlock_irqrestore(&pstrace_buf_lock ,flags);
 finish_wait(&pstrace_get_wait, &wait);
 return num_of_events_copied;
return_fail_copy_to_user:
 kfree(k_buf);
 read_unlock_irqrestore(&pstrace_buf_lock ,flags);
 return -EFAULT;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t __user, pid)
{
 unsigned long flags;
 int i;
 spin_lock_irqsave(&clear_lock, flags);
 write_lock_irqsave(&pstrace_buf_lock, flags);
 pstrace_clear_active = true;
   /*
  * Wake up all pstrace_get() calls on the wait queue and wait until they 
  * complete.
  *
  * we do unlock / lock here to ensure our sleeper can have 
  * read lock acquired. otherwise deadlock
  *
  * the implementation of get guarantees that while we holding the 
  * clear lock, no more new reader or writer will intervine
  */
 write_unlock_irqrestore(&pstrace_buf_lock, flags);
 while (wq_has_sleeper(&pstrace_get_wait)) {
  /* dont know if this is neccessary or bad to wake up so many times*/
  wake_up(&pstrace_get_wait);
 }
 write_lock_irqsave(&pstrace_buf_lock, flags);
 /*
 * Clear the buffer by setting flag
 * */
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (pstrace_buf[i].pid == pid || pid == -1)
   pstrace_buf[i].status = CLEARED;
 }
   pstrace_clear_active = false;
 write_unlock_irqrestore(&pstrace_buf_lock, flags);
 spin_unlock_irqrestore(&clear_lock, flags);
   return 0;
}