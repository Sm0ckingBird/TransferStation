#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/pstrace.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
DEFINE_SPINLOCK(pstrace_spinlock);
static int head; 
static int tail;
static int rb_counter;
static int trace_all;
struct pstrace *pstrace_ring_buf;
static pid_t *pid_trace_list;
static DECLARE_WAIT_QUEUE_HEAD(rb_waitq);
static int initialize_ring_buf(void){
 size_t buf_size;
 buf_size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 pstrace_ring_buf =  kmalloc(buf_size, GFP_KERNEL);
 if (!pstrace_ring_buf){
  return -ENOMEM;
 }
 head=0; 
 tail=0;
 rb_counter=0;
 trace_all=0;
 return 0;
}
static int initialize_pid_trace_list(void){
    int i;
 pid_trace_list =  kcalloc(PSTRACE_BUF_SIZE, sizeof(pid_t), GFP_KERNEL);
 if (!pid_trace_list)
  return -ENOMEM;
          for ( i=0; i < PSTRACE_BUF_SIZE; i++)
                pid_trace_list[i]=-1;                          
        return 0;
}
/*
 * is_traced chekcs if the given pid is traced or not 
 * @pid : the process id
 */
static int is_traced(int pid) {
 int i;
 if (!trace_all) {
  for( i=0; i < PSTRACE_BUF_SIZE; i++) {
   if (pid_trace_list[i] == pid)
    break;
  }
  /* check i and return 0 or 1 */
  return (i == PSTRACE_BUF_SIZE)? 0 : 1;
 }
 else {
  return 1;
 }
}
/*
 * Add a record of the state change into the ring buffer
 */
void pstrace_add(struct task_struct *p)
{
 unsigned long flags;
   spin_lock_irqsave(&pstrace_spinlock, flags); /* aquire spinlock */
 if (!pid_trace_list || !pstrace_ring_buf){
  spin_unlock_irqrestore(&pstrace_spinlock, flags);
  return;
 }
        if (is_traced(p->pid)) {
                                 get_task_comm(pstrace_ring_buf[tail].comm, p);
                pstrace_ring_buf[tail].pid = p->pid;
                pstrace_ring_buf[tail].state = p->state;
  printk(KERN_INFO "pid: %d name: %s state: %ld rbuff_pos:%d\n", 
          pstrace_ring_buf[tail].pid,
          pstrace_ring_buf[tail].comm,
          pstrace_ring_buf[tail].state, tail);                
                rb_counter++;
                   tail = ((tail + 1) % PSTRACE_BUF_SIZE);
                if (tail == head) {
                    head = (head + 1) % PSTRACE_BUF_SIZE; 
                }
  wake_up(&rb_waitq);
        }
        spin_unlock_irqrestore(&pstrace_spinlock, flags); /* release spinlock */
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid){
 int i;
 int initialized;
   if (!pstrace_ring_buf){
  initialized = initialize_ring_buf();
  if (initialized){
   return initialized;
  }
 }
 if (!pid_trace_list){
  initialized = initialize_pid_trace_list();
  if (initialized){
   return initialized;
  }
 }
 if (pid == -1) {
  trace_all = 1; // trace all processes
  return 0;
 }
 /* tracing of all processes already enabled */
 if (trace_all)
  return 0;
 /* if pid already exists in table ignore it */ 
 for(i=0; i < PSTRACE_BUF_SIZE; i++) {
  if (pid_trace_list[i] == pid) 
  return 0;
 }
 /* find first empty cell and insert pid */
 for(i=0; i < PSTRACE_BUF_SIZE; i++) {
  if (pid_trace_list[i] == -1) {
   pid_trace_list[i] = pid;
   return 0;
  }
 }
 /* PSTRACE_BUF_SIZE processes are been traced 
  * in other words pid_trace_list is full
  */
 return -1;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
*/
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid){
 int i;
 int initialized;
   if (!pstrace_ring_buf){
  initialized = initialize_ring_buf();
  if (initialized){
   return initialized;
  }
 }
 if (!pid_trace_list){
  initialized = initialize_pid_trace_list();
  if (initialized){
   return initialized;
  }
 }
   if (pid == -1) {
  trace_all = 0; // stop tracing all processes
  for(i=0; i < PSTRACE_BUF_SIZE; i++) {
   pid_trace_list[i] = -1;
  }    
  return 0;
 }
 // find pid in array and set it's content to 0
 for( i=0; i < PSTRACE_BUF_SIZE; i++) {
  if (pid_trace_list[i] == pid) {
   pid_trace_list[i] = -1;
   return 0;
  }
 }
 /* pid not found in pid_trace_list */
 return 1;
}
int copy_rbuf_to_kbuf( pid_t pid, 
   int kcounter,
   struct pstrace *rbuf, 
   struct pstrace *kbuf )
{
 int i, k,  start, end;
 start = (kcounter > 0) ? kcounter + 1 : head;
 end  = (kcounter > 0) ? (kcounter + PSTRACE_BUF_SIZE) : tail;
 end = (end < start)? (end + PSTRACE_BUF_SIZE) : end;
  
  /* Copy the pstrace ring buffer info @buf */
        k = 0;
 for (i = start; i <= end; i++)
 {
  if (pid == -1 && rbuf[i % PSTRACE_BUF_SIZE].pid != -1) {
   strncpy(kbuf[k].comm, rbuf[i % PSTRACE_BUF_SIZE].comm, 16);
   kbuf[k].pid = rbuf[i % PSTRACE_BUF_SIZE].pid;
   kbuf[k].state = rbuf[i % PSTRACE_BUF_SIZE].state;
   k++;
  } 
  else if (rbuf[i % PSTRACE_BUF_SIZE].pid == pid) {
   strncpy(kbuf[k].comm, rbuf[i % PSTRACE_BUF_SIZE].comm, 16);
   kbuf[k].pid = rbuf[i % PSTRACE_BUF_SIZE].pid;
   kbuf[k].state = rbuf[i % PSTRACE_BUF_SIZE].state;
   k++;
  }
 }
 return (k);
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf, long __user *, counter){
 struct pstrace *kbuf;
 long kcounter;
 size_t size;
 int copied;
 if (!buf || !counter || !pstrace_ring_buf || !pid_trace_list)
  return -EINVAL;
 if (get_user(kcounter, counter)) 
  return -EFAULT;
 size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 kbuf = kmalloc(size, GFP_KERNEL);
 if (!kbuf) 
  return -ENOMEM;
   if (kcounter > 0) {
  DEFINE_WAIT(wait);
  while (rb_counter < kcounter + PSTRACE_BUF_SIZE) {
   prepare_to_wait(&rb_waitq, &wait, TASK_INTERRUPTIBLE);
   schedule();
  }
  finish_wait(&rb_waitq, &wait);
 }
 copied = copy_rbuf_to_kbuf(pid, kcounter, pstrace_ring_buf, kbuf);
 kcounter = (kcounter > 0) ? (kcounter + PSTRACE_BUF_SIZE) : rb_counter;
               
  if (copy_to_user(counter, &kcounter, sizeof(int)) || copy_to_user(buf, kbuf, size)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return copied;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid){
 int i;
   for (i=0; i<PSTRACE_BUF_SIZE; i++) {
     if ((pid==-1) || (pid!=-1 && (pstrace_ring_buf[i].pid == pid))) {  
   pstrace_ring_buf[i].pid = -1;
      }
 }
 wake_up(&rb_waitq);
 return 0;
}