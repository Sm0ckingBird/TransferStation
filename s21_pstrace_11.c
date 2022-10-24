#include <linux/pstrace.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/wait.h> // Required for the wait queues
#include <linux/ctype.h>
#define PSTRACE_BUF_SIZE 500
DEFINE_SPINLOCK(SL);
static DECLARE_WAIT_QUEUE_HEAD(wq);
int processes[PSTRACE_BUF_SIZE] = { [0 ... (PSTRACE_BUF_SIZE - 1)] = -1 };
bool track_all;
int loc;
long count;
long target;
struct ring {
 char comm[16];
 pid_t pid;
 long state;
 long exit_state;
 int tracked;
};
struct ring ringbuf[PSTRACE_BUF_SIZE];
void write_ringbuf(int loc, struct task_struct *p)
{ 
 get_task_comm(ringbuf[loc].comm, p);
 ringbuf[loc].pid = p->pid;
 ringbuf[loc].state = p->state & 7;
 ringbuf[loc].exit_state = p->exit_state;
 ringbuf[loc].tracked = 1;
}
/* Avoid recurrent calls and deadlocks
 * void pstrace_add(struct task_struct *p)
 * {
   //add other flag
 local_irq_save(flags);
 write_ringbuf(loc, p);
 loc = (loc+1)%PSTRACE_BUF_SIZE;
 count++;
 //release other flag 
   if(atomic_sub_and_test(1,&rec_flag)){
  atomic_set(&rec_flag, 1);      
  return;
 }else{ 
  spin_lock(&SL); 
  atomic_set(&rec_flag, 1);  
  wake_up_interruptible(&wq);
  atomic_set(&rec_flag, 0);
  spin_unlock(&SL);  
  return;
 }
 local_irq_restore(flags); 
}
*/
void pstrace_add(struct task_struct *p)
{
 int l;
 spin_lock(&SL);
   if (track_all == true) {
  write_ringbuf(loc, p);
  loc = (loc+1)%PSTRACE_BUF_SIZE;
  count++;
 } else {
  for(l = 0; l < PSTRACE_BUF_SIZE; l++) {
   if(processes[l] == p->pid) {
    write_ringbuf(loc, p);
    loc = (loc+1)%PSTRACE_BUF_SIZE;
    count++;
    break;
   }
  }
 }
 spin_unlock(&SL);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 int i;
 spin_lock(&SL); 
 if ( pid == -1 ){
  track_all = true;
 } else {
  for( i = 0; i < PSTRACE_BUF_SIZE; i++){
   if( processes[i] == -1){
    processes[i] = pid;
    break;
   }
  }
 }
 spin_unlock(&SL);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 int j;
   if(!isdigit(pid))
  return -EINVAL;
 if(pid < -1)
  return -EINVAL;
 if(find_task_by_vpid(pid)==NULL)
  return -EINVAL; 
     spin_lock(&SL);
 if ( pid == -1 ){
  for( j = 0; j < PSTRACE_BUF_SIZE; j++){
   processes[j] = -1;
  }
  track_all = false;
 } else {
  for( j = 0; j < PSTRACE_BUF_SIZE; j++){
   if( processes[j] == pid){
    processes[j] = -1;
    break;
   }
  }
 }
 spin_unlock(&SL);
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
   long __user *, counter)
{
 struct pstrace *buffer;
 long c;
 int lc;
 long rc;
 spin_lock(&SL);
 rc = 0;
 if (access_ok(counter, sizeof(long)) == 0)
  return -EFAULT;
 if (copy_from_user(&c, counter, sizeof(*counter)))
  return -EFAULT;
   buffer = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (buffer == NULL)
  return -ENOMEM;
 /* go to sleep and wake up with queue
   int mtarget = count + 500;
 printk("goes to sleep at count: %d, target: %d\n",count, mtarget);
 r = wait_event_interruptible(wq, count>=mtarget);
 printk("wakes up at count: %d, target: %d\n",count, mtarget);
   */
 if( pid == -1 ) {
  for( lc = 0; lc < PSTRACE_BUF_SIZE; lc++ ) {
   if( ringbuf[lc].tracked == 1 ) {
    strcpy(buffer[rc].comm, ringbuf[lc].comm);
    buffer[rc].pid = ringbuf[lc].pid;
    if(ringbuf[lc].exit_state != 0){
     buffer[rc].state = ringbuf[lc].exit_state;
    } else {
     buffer[rc].state = ringbuf[lc].state;
    }
    rc++;
   }
  }
 } else {
  for( lc = 0; lc < PSTRACE_BUF_SIZE; lc++ ) {
   if( (ringbuf[lc].pid == pid) && (ringbuf[lc].tracked == 1) ) {
    strcpy(buffer[rc].comm, ringbuf[lc].comm);
    buffer[rc].pid = ringbuf[lc].pid;
    if(ringbuf[lc].exit_state != 0){
     buffer[rc].state = ringbuf[lc].exit_state;
    } else {
     buffer[rc].state = ringbuf[lc].state;
    }
    rc++;
   }
  }
 }
 c = c + PSTRACE_BUF_SIZE;
 if (copy_to_user(counter, &c, sizeof(long)))
  return -EFAULT;
 if (copy_to_user(buf, buffer, sizeof(struct pstrace) * PSTRACE_BUF_SIZE))
  return -EFAULT;
 spin_unlock(&SL); 
 return rc;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int s;
 spin_lock(&SL); 
 if( pid == -1 ){
  for ( s = 0; s < PSTRACE_BUF_SIZE; s++) {
   ringbuf[s].tracked = 0;
  }
 } else {
  for ( s = 0; s < PSTRACE_BUF_SIZE; s++) {
   if ( ringbuf[s].pid == pid ) {
    ringbuf[s].tracked = 0;
   }
  }
 }
 spin_unlock(&SL);
 return 0;
}