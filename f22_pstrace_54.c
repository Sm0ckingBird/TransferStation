#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/pstrace.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
#define TASK_RUNNABLE 0x0003
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
int counter = 0;
unsigned long flags;
DEFINE_SPINLOCK(b_lock);
static DECLARE_WAIT_QUEUE_HEAD(waitq_head);
// struct for pid check
struct task_struct *process_group[PSTRACE_BUF_SIZE];
int pgcount = 0; /* count how many tasks are in process_group */
// enable trace sign
int sign = 0;
/* task board:
 * Goal: Write a system call that 
 * enables the tracing of a process and another system call that disables the tracing. 
 * 1. Write a function that record the information from the process (all threads that share the pid)
 * to the buffer
 *      - get the task and info of the task from the given pid
 *      - transform it into pstrace struct
 *      - store it in the pstrace buffer
 * 2. Write a function that will record state changes for the process, and record the changes
 *
 *
*/
/* check if the buffer is successfully created*/
int check_buffer(struct pstrace *buffer)
{
    if (!buffer)
        return -1;
    return 0;
}
/* create the ring buffer */
struct pstrace ring_buffer[PSTRACE_BUF_SIZE];
/* get the target task from the given pid*/
static struct task_struct *get_task (pid_t target_pid)
{
    if (target_pid == 0)
        return &init_task;
    return find_task_by_vpid(target_pid);
}
/* transform task struct into pstrace struct*/
struct pstrace create_pstrace(struct task_struct *task, long state)
{
    struct pstrace pstc;
    get_task_comm(pstc.comm, task);
    pstc.state = state;
    pstc.pid = task_tgid_nr(task); /*since pid represents the group id essentially*/
    pstc.tid = task_pid_nr(task);
    return pstc;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, struct task_struct *cur)
{
    struct pstrace curr;
    int index;
    long state;
    /* (sign && (trace all processes || this process's tgid == being traced process's tgid)) */
    if (sign != 0 && (pgcount == 0 || p->tgid == process_group[0]->tgid)) {
     if (p->state == TASK_RUNNING || p->state == __TASK_STOPPED
       || p->state == TASK_INTERRUPTIBLE 
       || p->state == TASK_UNINTERRUPTIBLE 
       || p->state == TASK_RUNNABLE
       || p->exit_state == EXIT_DEAD 
       || p->exit_state == EXIT_ZOMBIE) {
  spin_lock_irqsave(&b_lock, flags);
      if (p->exit_state == EXIT_DEAD || p->exit_state == EXIT_ZOMBIE)
   state = p->exit_state;
  else {
   if (p->state == TASK_RUNNING && p->pid != cur->pid) {
    state = TASK_RUNNABLE;
   }
   else state = p->state;
  }
      curr = create_pstrace(p, state);
      index = counter % PSTRACE_BUF_SIZE;
      ring_buffer[index] = curr;
      counter++;
  spin_unlock_irqrestore(&b_lock, flags);
   }
    }
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
//long pstrace_enable(pid_t pid);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *p;
 struct task_struct *being_traced;
 /* if pid is -1, then trace all processes */
 if (pid == -1) {
  sign = 1; /* enable tracing */
  spin_lock_irqsave(&b_lock, flags);
  pgcount = 0;
  spin_unlock_irqrestore(&b_lock, flags);
  return 0;
 }
 being_traced = get_task(pid);
 if (!being_traced)
  return -ESRCH;
 //printk("read pid %d\n", pid);
 being_traced = get_task(pid);
 if (!being_traced)
  return -ESRCH;
 //printk("lock\n");
 spin_lock_irqsave(&b_lock, flags);
 pgcount = 0;
 process_group[pgcount++] = being_traced;
 /* add each thread of the process into process_group */
 list_for_each_entry(p, &being_traced->thread_group, thread_group) 
  process_group[pgcount++] = p;
 /* enable tracing */
 sign = 1;
 spin_unlock_irqrestore(&b_lock, flags);
 printk("print %d info\n", pgcount);
 return 0;
}
/*
 * Syscall No. 442
 * Disable tracing.
*/
//long pstrace_disable();
SYSCALL_DEFINE0(pstrace_disable) 
{ 
 int index;
 int i = 0;;
 spin_lock_irqsave(&b_lock, flags);
 sign = 0;
 spin_unlock_irqrestore(&b_lock, flags);
   index = PSTRACE_BUF_SIZE;
 if (index == 0) return -1;
   //return counter;
   while (i < index) {
  printk("%-10s \t %ld \t %d \t %d\n", ring_buffer[i].comm, ring_buffer[i].state, ring_buffer[i].pid, ring_buffer[i].tid);
  i++;
 }
 printk("total records: %d\n", counter);
 return counter;
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter1) {
 int size;
 int offset;
 long * kn_counter; 
 int new_size;
 DEFINE_WAIT(wait_entry);
   size = counter % PSTRACE_BUF_SIZE;
 offset = 0;
 printk("input val\n");
 if (buf == NULL) return -EINVAL;
 kn_counter = kcalloc(1, sizeof(long), GFP_KERNEL);
 if (kn_counter == NULL) return -ENOMEM;
 if (copy_from_user(kn_counter, counter1, sizeof(long))) 
  return -EFAULT;
 printk("copy with %ld\n", *kn_counter);
 if (*kn_counter < 0) return -EINVAL;
 else if (*kn_counter == 0) {
  if (counter > PSTRACE_BUF_SIZE)
   copy(PSTRACE_BUF_SIZE, buf, 0, 0);
  else copy(counter, buf, 0, 0);
  return size;
 }
 new_size = counter + PSTRACE_BUF_SIZE;
 printk("buf size %d\n", new_size);
 add_wait_queue(&waitq_head, &wait_entry);
 printk("in queue\n");
 while (counter < new_size){
  prepare_to_wait(&waitq_head, &wait_entry, TASK_INTERRUPTIBLE);
  spin_unlock(&waitq_head.lock);
  schedule();
  printk("in loop\n");
  spin_lock(&waitq_head.lock);
 }
 finish_wait(&waitq_head, &wait_entry);
 spin_lock_irqsave(&b_lock, flags);
   if (counter > new_size) 
  offset = MAX(*kn_counter % PSTRACE_BUF_SIZE, counter % PSTRACE_BUF_SIZE);
 else offset = *kn_counter;
   kfree(kn_counter);
 if ((size = copy(PSTRACE_BUF_SIZE - offset, buf, offset, 0)) < 0) 
  return -EFAULT;
   spin_unlock_irqrestore(&b_lock, flags);
 return size;
}
/*
 * Syscall No.444
 *
 * Clear the pstrace buffer. Cleared records should
 * never be returned to pstrace_get.  Clear does not
 * reset the value of the buffer counter.
 */
/*
SYSCALL_DEFINE0(pstrace_clear) {
 int i;
 spin_lock_irqsave(&b_lock, flags);
 if (pgcount > 0) 
  kfree(process_group);
   spin_unlock_irqrestore(&b_lock, flags);
 return 0;
}*/
int copy(int size, struct pstrace * buf, int offset, int off_idx) {
 int i = 0;
 // given input size > 0
   while (i < size) {
  if (copy_to_user(&buf[i], &ring_buffer[i + offset], 
     sizeof(struct pstrace))) 
   return -EFAULT;
  i++;
 }
 return i;
}