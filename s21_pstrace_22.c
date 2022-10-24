/* System calls to be defined here */
/* long pstrace_enable(pid_t pid); */
/* long pstrace_disable(pid_t pid); */
/* long pstrace_get(pid_t pid, struct pstrace *buf, int *counter); */
/* long pstrace_clear(pid_t pid) */
#include<linux/pid.h>
#include<linux/types.h>
#include<linux/pstrace.h>
#include<linux/spinlock.h>
#include<linux/slab.h>
#include<linux/syscalls.h>
#include<linux/errno.h>
#include<linux/wait.h>
#include<linux/limits.h>
#include<linux/string.h>
long global_counter;
int process_count;
bool TRACE_ALL;
long waking_index = LONG_MAX;
struct ring_buffer GLOBAL_BUFFER[PSTRACE_BUF_SIZE];
DEFINE_RAW_SPINLOCK(ring_buffer_lock);
DEFINE_RAW_SPINLOCK(wake_index_lock);
//DEFINE_RAW_SPINLOCK(trace_all_bool_lock);
DEFINE_SPINLOCK(trace_all_bool_lock);
static DEFINE_RAW_SPINLOCK(pstrace_lock);
static LIST_HEAD(enable_listhead);
static LIST_HEAD(disable_listhead);
static LIST_HEAD(sleeping_gets_list);
/* Wait Queue */
static DECLARE_WAIT_QUEUE_HEAD(wq);
static struct task_struct *valid_pid(int task_pid)
{
 if (task_pid == 0)
  return &init_task;
 return find_task_by_vpid(task_pid);
}
long copy_to_buffer(long start, long end, struct pstrace *temp_node,
     struct pstrace *buf, pid_t pid)
{
 long start_index, end_index;
 long final_counter;
 int ring_iter;
 int i, j;
 ring_iter = 0;
 j = 0;
 start_index = start % PSTRACE_BUF_SIZE - 1;
 end_index = end % PSTRACE_BUF_SIZE - 1;
 pr_info("------ %%%% Iterating for indexes: (%ld,%ld) &&& (%ld,%ld)\n",
   start, end, start_index, end_index);
 while (ring_iter < 500) {
  i = (start - 1 + ring_iter) % PSTRACE_BUF_SIZE;
  pr_info("Current index: %d", i);
  pr_info("Node: buf_counter= %ld", GLOBAL_BUFFER[i].buf_counter);
  pr_info("Node: COMM= %s", GLOBAL_BUFFER[i].proc.comm);
  pr_info("Node: PID= %d", GLOBAL_BUFFER[i].proc.pid);
  pr_info("Node: STATE= %ld", GLOBAL_BUFFER[i].proc.state);
  pr_info("Start+RING_ITER: %ld | Buf_Counter %ld",
    start+ring_iter, GLOBAL_BUFFER[i].buf_counter);
  if ((start + ring_iter) == GLOBAL_BUFFER[i].buf_counter) {
   if (pid == -1 || pid == GLOBAL_BUFFER[i].proc.pid) {
    pr_info("---- Copying to user space---- for Counter:%ld",
      GLOBAL_BUFFER[i].buf_counter);
    strcpy(buf[j].comm, GLOBAL_BUFFER[i].proc.comm);
    buf[j].state = GLOBAL_BUFFER[i].proc.state;
    buf[j].pid = GLOBAL_BUFFER[i].proc.pid;
    j++;
    final_counter = GLOBAL_BUFFER[i].buf_counter;
   }
  }
  ring_iter++;
 }
 return final_counter;
}
struct get_pinfo *traverse_sleeping_gets(void)
{
 struct get_pinfo *temp;
 list_for_each_entry(temp, &sleeping_gets_list, next) {
  if (temp->end == waking_index)
   return temp;
 }
 /* If not found, set waking index to the next smallest
  * end_range */
 waking_index = LONG_MAX;
 list_for_each_entry(temp, &sleeping_gets_list, next) {
  if (temp->end < waking_index)
   waking_index = temp->end;
 }
 temp = NULL;
 return temp;
}
void empty_list(void)
{
 struct process_node *enable_node;
 struct process_node *disable_node;
 raw_spin_lock(&pstrace_lock);
 list_for_each_entry(enable_node, &enable_listhead, next) {
  list_del(&enable_node->next);
 }
 list_for_each_entry(disable_node, &disable_listhead, next) {
  list_del(&disable_node->next);
 }
 raw_spin_unlock(&pstrace_lock);
}
struct process_node *traverse(pid_t pid)
{
 struct process_node *temp;
 list_for_each_entry(temp, &enable_listhead, next) {
  if (temp->pid == pid)
   return temp;
 }
 return NULL;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 /*
  * Syscall No. 436
  * Enable the tracing for @pid. If -1 given,
  * trace all process
  */
 struct process_node *p;
 unsigned long flags;
 if (pid == -1) {
  spin_lock_irqsave(&trace_all_bool_lock, flags);
  pr_info("Accessing trace_all boolean value: %d", TRACE_ALL);
  TRACE_ALL = true;
  pr_info("sETTING trace_all boolean value: %d", TRACE_ALL);
  /* empty the enable & disable linked lists */
  empty_list();
  spin_unlock_irqrestore(&trace_all_bool_lock, flags);
 } else {
  /* TODO: implementation to be updated */
  /*Check if valid PID id is passed*/
  if (!valid_pid(pid))
   return -EINVAL;
  pr_info("------ INSIDE ENABLE FUNC ----with PID = %d\n", pid);
  if (TRACE_ALL)
   return 0;
  p = kmalloc(sizeof(struct process_node), GFP_KERNEL);
  if (!p)
   return -ENOMEM;
  p->pid = pid;
  raw_spin_lock(&pstrace_lock);
  list_add_tail(&p->next, &enable_listhead);
  process_count++;
  pr_info(" INSIDE ENABLE FUNCTION with Process count = %d\n",
    process_count);
  raw_spin_unlock(&pstrace_lock);
 }
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 /*
  * Syscall No. 437
  * Disable the tracing for @pid. If -1 given,
  * stop tracing all process
  */
 unsigned long flags;
 struct process_node *p;
 if (pid == -1) {
  pr_info("-------- Start of DISABLE call");
  spin_lock_irqsave(&trace_all_bool_lock, flags);
  TRACE_ALL = false;
  /* empty the enable & disable linked lists */
  empty_list();
  spin_unlock_irqrestore(&trace_all_bool_lock, flags);
 } else if (TRACE_ALL) {
  /*Add pid in disable list*/
  p = kmalloc(sizeof(struct process_node), GFP_KERNEL);
  if (!p)
   return -ENOMEM;
  p->pid = pid;
  raw_spin_lock(&pstrace_lock);
  list_add_tail(&p->next, &disable_listhead);
  pr_info("-------@@@@@ INSIDE DISABLE FUNCTION ----- @@@@@ ");
  raw_spin_unlock(&pstrace_lock);
 } else if (process_count > 0) {
  struct process_node *del_node = traverse(pid);
  if (!del_node)
   return -EINVAL;
  raw_spin_lock_irqsave(&pstrace_lock, flags);
  list_del(&del_node->next);
  raw_spin_unlock_irqrestore(&pstrace_lock, flags);
  kfree(del_node);
 } else {
  /* If no process is being tracked and disable is called */
  return -1;
 }
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid,
  struct pstrace __user *, buf,
  long __user *, counter)
{
 /*
  * Syscall No. 438
  * Copy the pstrace ring buffer info @buf.
  * If @pid == -1, copy all records; else, only copy records of @pid.
  * If @counter > 0, caller process will wait until a full buffer can
  * be returned after record @counter (i.e. return record @counter + 1
  * to * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
  * Returns the number of records copied.
  */
 unsigned long flags;
 int i, start, end, ret_immediate;
 struct pstrace *p, *temp_buf;
 struct get_pinfo *getp;
 long cnt, end_range;
 long *ret_count;
 pr_info(" -------@@@@@ INSIDE GET @@@@ -----");
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 pr_info(" --------@@@@ AFTER BUF and COUNTER @@@@ ------");
 /*
 if ((pid != -1) && (!valid_pid(pid)))
  return -EINVAL;
 */
 pr_info(" ----@@@ VALID PID inside GET @@@ -----");
 /* copy counter, which is in the user’s address space, into cnt */
 if (copy_from_user(&cnt, counter, sizeof(long)))
  return -EFAULT;
 if (cnt <= 0)
  ret_immediate = 1;
 else
  ret_immediate = 0;
 temp_buf = kmalloc(PSTRACE_BUF_SIZE *
   sizeof(struct pstrace), GFP_KERNEL);
 if (!temp_buf)
  return -ENOMEM;
 memset(temp_buf, 0, PSTRACE_BUF_SIZE * sizeof(struct pstrace));
 ret_count = kmalloc(sizeof(long), GFP_KERNEL);
 if (!ret_count)
  return -ENOMEM;
 getp = kmalloc(sizeof(struct get_pinfo), GFP_KERNEL);
 if (!getp)
  return -ENOMEM;
 p = kmalloc(sizeof(struct pstrace), GFP_KERNEL);
 if (!p)
  return -ENOMEM;
 end_range = cnt + PSTRACE_BUF_SIZE;
 pr_info("Inside pstrace_get");
 raw_spin_lock(&ring_buffer_lock);
 pr_info("----- $$$$ Acquired GET LOCK ");
 if (end_range > global_counter && !ret_immediate) {
  pr_info(" About to Sleep for end_range: %ld and global_counter:%ld",
    end_range, global_counter);
  DEFINE_WAIT(wait);
  getp->pid = pid;
  getp->end = end_range;
  getp->buf = temp_buf;
  getp->p = (struct task_struct *)wait.private;
  getp->final_counter_copied = ret_count;
  list_add_tail(&getp->next, &sleeping_gets_list);
  raw_spin_lock(&wake_index_lock);
  pr_info("Acquired Wake Index Lock");
  if (waking_index > end_range)
   waking_index = end_range;
  raw_spin_unlock(&wake_index_lock);
  pr_info("^^^^^^ Releasing Wake Lock");
  // while (end_range > global_counter) {
  prepare_to_wait(&wq, &wait, TASK_INTERRUPTIBLE);
  pr_info("SLEEPING....................");
  raw_spin_unlock(&ring_buffer_lock);
  pr_info("!!!!! Released RING BUFFER LOCK");
  schedule();
  pr_info("@@@@ Woke up for end_range %ld", end_range);
  finish_wait(&wq, &wait);
 } else {
  if (cnt <= 0) {
   start = global_counter - PSTRACE_BUF_SIZE + 1;
   if (start < 0)
    start = 1;
   end = global_counter;
  } else {
   start = cnt + 1;
   end = cnt + PSTRACE_BUF_SIZE;
  }
  *ret_count = copy_to_buffer(start, end, p, temp_buf, pid);
  raw_spin_unlock(&ring_buffer_lock);
  pr_info("********* Release RING BUFFER LOCK");
 }
 if (copy_to_user(buf, temp_buf,
    PSTRACE_BUF_SIZE * sizeof(struct pstrace)))
  return -EFAULT;
 if (copy_to_user(counter, ret_count, sizeof(long)))
  return -EFAULT;
 return 0;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 /*
  * Syscall No.439
  * Clear the pstrace buffer. If @pid == -1,
  * clear all records in the buffer,
  * otherwise, only clear records for the give pid.
  * Cleared records should never be returned to pstrace_get.
  */
 return 0;
}
void pstrace_add(struct task_struct *p)
{
 /*
  * Add a record of the state change into the ring buffer.
  */
 int index, pid, flag_to_add;
 long start, end;
 struct process_node *temp;
 unsigned long flags;
 struct get_pinfo *wake_getp;
 struct pstrace *node;
 flag_to_add = 0;
 pid = task_pid_vnr(p);
 node = kmalloc(sizeof(struct pstrace), GFP_KERNEL);
 if (!node)
  return -ENOMEM;
 wake_getp = kmalloc(sizeof(struct get_pinfo), GFP_KERNEL);
 if (!wake_getp)
  return -ENOMEM;
 //local_irq_disable();
 spin_lock_irqsave(&trace_all_bool_lock, flags);
 if (TRACE_ALL) {
  flag_to_add = 1;
  //Check pid entry in disable LL
  list_for_each_entry(temp, &disable_listhead, next) {
   if (temp->pid == pid)
    flag_to_add = 0;
  }
 } else {
  flag_to_add = 0;
  // Check pid entry in enable LL
  list_for_each_entry(temp, &enable_listhead, next) {
   if (temp->pid == pid)
    flag_to_add = 1;
  }
 }
 if (flag_to_add) {
  raw_spin_lock(&ring_buffer_lock);
  pr_info("Acquired lock for ring buffer access inside %s",
    __func__);
  index = global_counter % PSTRACE_BUF_SIZE;
  pr_info("Writing ring buffer index: %d", index);
  get_task_comm(GLOBAL_BUFFER[index].proc.comm, p);
  pr_info("Buffer Node: COMM= %s",
    GLOBAL_BUFFER[index].proc.comm);
  GLOBAL_BUFFER[index].proc.pid = pid;
  pr_info("Buffer Node: PID= %d", GLOBAL_BUFFER[index].proc.pid);
  if (p->state == 0x0080)
   GLOBAL_BUFFER[index].proc.state = p->exit_state;
  else
   GLOBAL_BUFFER[index].proc.state = p->state;
  pr_info("Buffer Node: STATE= %ld",
    GLOBAL_BUFFER[index].proc.state);
  GLOBAL_BUFFER[index].buf_counter = ++global_counter;
  pr_info("Buffer Node: Counter= %ld", global_counter);
  raw_spin_lock(&wake_index_lock);
  //int z = 0;
  if (global_counter == waking_index) {
   wake_getp = traverse_sleeping_gets();
   pr_info("global_counter %ld", global_counter);
   pr_info("waking index %ld", waking_index);
   if (!wake_getp)
    pr_info("NOTHING WAS FOUND");
   end = wake_getp->end;
   start = end - PSTRACE_BUF_SIZE + 1;
   *wake_getp->final_counter_copied =
    copy_to_buffer(start, end, node,
     wake_getp->buf, wake_getp->pid);
   wake_up_process(wake_getp->p);
   /* Deleting this process from sleeping gets list */
   list_del(&wake_getp->next);
   traverse_sleeping_gets();
   pr_info("global_counter %ld", global_counter);
   pr_info("waking_index %ld", waking_index);
   //z++;
  }
  raw_spin_unlock(&wake_index_lock);
  raw_spin_unlock(&ring_buffer_lock);
 }
 spin_unlock_irqrestore(&trace_all_bool_lock, flags);
 kfree(node);
 kfree(wake_getp);
 //local_irq_enable();
}