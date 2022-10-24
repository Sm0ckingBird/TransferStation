#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/linkage.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <asm/errno.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/wait.h>
#include <linux/pstrace.h>
//ring_buffer_counter for pstrace_add
long  ring_buffer_counter=0;
pid_t tracing_pid[TRACING_PID_MAX_SIZE] = {[0 ... (TRACING_PID_MAX_SIZE-1)] = -1};
struct pstrace* ring_buffer[PSTRACE_BUF_SIZE] = {NULL};
int current_ring_index = 0;
// wait queue for pstrace_get
static DECLARE_WAIT_QUEUE_HEAD(wq);
//Define spinlock
DEFINE_SPINLOCK(ring_buffer_spinlock);
long print_tracing_pid(void){
 printk("------Tracing_pid Contents Start------\n");
 int i,count = 0;
 for(i=0;i<TRACING_PID_MAX_SIZE;i++){ 
  if(tracing_pid[i] != -1){
      printk("%d \n", tracing_pid[i]);//print non empty element
      count++;
  }
 } 
 printk("------Tracing_pid Contents End, total %d records ------\n", count); 
 return 0;
}
//System call 436
SYSCALL_DEFINE1(pstrace_enable,pid_t , pid)
{
 printk("pstrace_enable, pid_t: %d\n", pid);
        //if trace all proces(pid == -1), put all process in the tracing_pid array
        if(pid == -1){
         int i=0;         
         for(i=0;i<TRACING_PID_MAX_SIZE;i++){ tracing_pid[i] = -1;}//reset array
         struct task_struct *task;
         i=0;
      for_each_process(task){
       tracing_pid[i] = task->pid;
       i++;
      }          
        }
        else{//else, add the target pid to the array empty space(where value = -1)
         int i=0;
         for(i=0;i<TRACING_PID_MAX_SIZE;i++){ 
          if(tracing_pid[i] == -1){
           tracing_pid[i] = pid;
           break;
          }           
         }
        }
 print_ring_buffer();
        //pstrace_add_test();
        print_tracing_pid();//for debug purpose
        return 0;
}
//System call 437
SYSCALL_DEFINE1(pstrace_disable,pid_t , pid)
{
        printk("pstrace_disable, pid_t: %d\n", pid);
                 //if dont trace all proces(pid == -1), clear the tracing_pid array
        if(pid == -1){
         int i=0;
         for(i=0;i<TRACING_PID_MAX_SIZE;i++){ tracing_pid[i] = -1;}        
        }else{//else, remove target pid from array
         int i=0;
         for(i=0;i<TRACING_PID_MAX_SIZE;i++){ 
          if(tracing_pid[i] == pid){
           tracing_pid[i] = -1;
          }   
         }
        }
  //pstrace_add_test();
        print_tracing_pid();//for debug purpose
        return 0;
}
long pstrace_get_kernel(pid_t pid, struct pstrace __user* buf, int* counter)
{
 //int *kcounter;
        //struct pstrace *kbuf;
 unsigned long flags;
 int ring_buffer_full; 
        DEFINE_WAIT(wait);
 printk("pstrace_get\n");
        //kcounter = (int *)kmalloc(sizeof(int), GFP_KERNEL);
        /*if (buf == NULL || counter == NULL)
                return -EINVAL;
        if (access_ok(counter, sizeof(int)) == 0)
                return -EFAULT;
        if (access_ok(buf, (int)sizeof(struct pstrace) * PSTRACE_BUF_SIZE) == 0)
                return -EFAULT;
        if (copy_from_user(kcounter, counter, sizeof(int)) != 0)
                return -EFAULT;*/
        //printk("getting record %d through %d\n", *kcounter + 1, *kcounter + PSTRACE_BUF_SIZE);
 printk("getting record %d through %d\n", *counter + 1, *counter + PSTRACE_BUF_SIZE);
 //if (access_ok(buf, sizeof(struct pstrace) == 0))
        //        return -EFAULT;
 //kbuf = (struct pstrace*)kmalloc((int)sizeof(struct pstrace) * PSTRACE_BUF_SIZE, GFP_KERNEL);
 ring_buffer_full = 0;
 while(!ring_buffer_full){
  prepare_to_wait(&wq, &wait, TASK_INTERRUPTIBLE);
     spin_lock_irqsave(&ring_buffer_spinlock, flags);
  if (ring_buffer_counter >= *counter + PSTRACE_BUF_SIZE){
   ring_buffer_full = 1;
  }
  spin_unlock_irqrestore(&ring_buffer_spinlock,flags);
     printk("counter: %d, ring_buffer_counter: %d\n",*counter, ring_buffer_counter);
     if (!ring_buffer_full){
   printk("buffer is not full: going to sleep\n");
   schedule();
  }
 }
 finish_wait(&wq, &wait);
 // ring buffer is full: wake up
 printk("buffer is full: wake up\n");
     //This is not correct, but will do it for now
   struct pstrace ring_buffer_to_copy[PSTRACE_BUF_SIZE];
 int i=0;
 for(i=0;i<PSTRACE_BUF_SIZE;i++){
  ring_buffer_to_copy[i] = *(ring_buffer[i]); 
 }
   copy_to_user(buf, ring_buffer_to_copy, sizeof(struct pstrace) * PSTRACE_BUF_SIZE);
 printk("buffer copied\n");
   //kfree(kcounter);
        //kfree(kbuf);
        return 0;
}
//System call 438
SYSCALL_DEFINE3(pstrace_get,pid_t, pid,struct pstrace __user*, buf, int __user*, counter){
   int* k_counter = (int *)kmalloc(sizeof(int), GFP_KERNEL);
 copy_from_user(k_counter, counter, sizeof(int));
   return pstrace_get_kernel(pid,buf,k_counter);
}
//System call 439
SYSCALL_DEFINE1(pstrace_clear,pid_t, pid)
{
 //pstrace_add_test();
 printk("printk: pstrace_clear\n");
 pstrace_clear(pid);
        return 0;
}
long print_ring_buffer(void){
 printk("------Ring Buffer Contents------\n");
 int i;
 for(i=0;i<PSTRACE_BUF_SIZE;i++){
  if(ring_buffer[i]!=NULL){
   if(ring_buffer[i]->is_cleared == false){
    printk("%d %s, pid: %d, state %ld, is_cleared %d\n",
      i,
      ring_buffer[i] -> comm,
      ring_buffer[i] -> pid,
      ring_buffer[i] -> state,
      ring_buffer[i] -> is_cleared
     );
   }
  }
 }
 printk("------Ring Buffer End------\n"); 
 return 0;
}
long pstrace_add(struct task_struct *p){
 unsigned long flags;
 struct pstrace* new_record = kmalloc(sizeof(struct pstrace), GFP_KERNEL);
 //printk("Tracing pid %d state %d", p->pid, p->state);
 bool is_target_pid = false;
 int i = 0;
 for(i=0;i<TRACING_PID_MAX_SIZE;i++){ 
  if(tracing_pid[i] == p->pid){
   is_target_pid = true;
   break;
  }
 }
 if(is_target_pid == false){
  return 0;
 }
 spin_lock_irqsave(&ring_buffer_spinlock, flags); 
   //Check is the target pid is in the tracing_pid array
   //setup new record
 //printk('here1');
 strncpy(new_record->comm, p->comm, 16);
 new_record->pid = p->pid;
 new_record->state = p->state;
 if(p->exit_state == 16 || p->exit_state == 32){
  new_record->state = p->exit_state;
 }
 if (!(new_record->state == 0||new_record->state==1 || new_record->state==2||
  new_record->state==4 || new_record->state ==16 || new_record->state == 32))
  {
   spin_unlock_irqrestore(&ring_buffer_spinlock,flags);
   return 0;
  }
   new_record->is_cleared = false;
 //printk('here2');
   //Put it in ring buffer
 if(current_ring_index >= PSTRACE_BUF_SIZE){
  current_ring_index = 0;
 } 
 // if(ring_buffer[current_ring_index] != NULL){
 //  kfree(ring_buffer[current_ring_index]);
 // }
 ring_buffer[current_ring_index] = new_record;
 wake_up(&wq);
   current_ring_index++;
   ring_buffer_counter++;
   spin_unlock_irqrestore(&ring_buffer_spinlock,flags);
 if(ring_buffer[current_ring_index-1]->is_cleared == false){
    printk("%d %s, pid: %d, state %ld, is_cleared %d\n",
      current_ring_index-1,
      ring_buffer[current_ring_index-1] -> comm,
      ring_buffer[current_ring_index-1] -> pid,
      ring_buffer[current_ring_index-1] -> state,
      ring_buffer[current_ring_index-1] -> is_cleared
     );
   }
 return 0;
}
long pstrace_clear(pid_t pid){
   spin_lock(&ring_buffer_spinlock);
   //Mark all target records's is_cleared = true 
 int i;
 for(i=0;i<PSTRACE_BUF_SIZE;i++){
  if(ring_buffer[i]!=NULL){
   if(ring_buffer[i]->pid == pid || pid == -1){
    ring_buffer[i]->is_cleared = true;
   }
  }
 }
   spin_unlock(&ring_buffer_spinlock);
   return 0;
}
long pstrace_add_test(void){
 int i;
 struct pstrace *buf;
 printk("Insert 50 record\n");
 for(i=1;i<50;i++){
  if(find_task_by_vpid(i)!=NULL)
   pstrace_add(find_task_by_vpid(i));
 }
 print_ring_buffer();
   // printk("Clear All\n");
 // pstrace_clear(-1);
 // print_ring_buffer();
   printk("Insert 50 record\n\n");
 for(i=1;i<50;i++){
  if(find_task_by_vpid(i)!=NULL)
   pstrace_add(find_task_by_vpid(i));
 }
   printk("clear 5 17 25 pid");
 pstrace_clear(5);
 pstrace_clear(17);
 pstrace_clear(25);
 // print_ring_buffer();
   pstrace_clear(-1);
 printk("cleared all\n");
   printk("FILL RING BUFFER\n\n");
 for(i=1;i<500;i++){
   if(find_task_by_vpid(5)!=NULL){
    pstrace_add(find_task_by_vpid(5));
   printk("adding record %d\n", i);
  }
 }
   print_ring_buffer();
   int *counter = (int *)kmalloc(sizeof(int), GFP_KERNEL);
 *counter = 0;
 pstrace_get_kernel(-1, buf, counter);
   printk("ring_buffer_counter %d \n",ring_buffer_counter);
 return 0;
}
/*
SYSCALL_DEFINE3(ptree,struct prinfo __user*,buf, int __user*, nr, int ,root_pid)
{
        printk("%s\n",s);
        return 0;
}
*/