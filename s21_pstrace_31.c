#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/signal.h> /* These three for sys_kill function */
#include <linux/spinlock.h> /* For spinlock functions */
#include <linux/semaphore.h> /* For semaphore implementation */
#include <linux/slab.h> /* kmalloc, kfree */
#include <linux/syscalls.h>
#include <linux/pstrace.h> /* syscall prototypes, struct pstrace are in here! */
#include <linux/wait.h> /* To implement wait_queue */
int calculate_index(int total_elements, int index, int size);
bool pid_is_traced(pid_t pid);
bool TRACE_ALL_PROCESSES = false;
int trace_process_index = 0;
pid_t traced_processes[PSTRACE_BUF_SIZE];
/* tracking the condition vals that we are waiting for */
long cond_vals[PSTRACE_BUF_SIZE];
int curr_waiting_pstrace_get_calls = 0;
/* the copy of the trace buf that we will maintain for returning to the user */
struct pstrace trace_buf_copy[PSTRACE_BUF_SIZE];
int trace_buf_index = 0;
struct pstrace trace_buf[PSTRACE_BUF_SIZE];
int num_of_elements_in_trace_buf = 0; /* Keeps track of how many elements are in buf currently */
long total_records_written = 0; /* Keeps track of the total number of records that have been written */
DECLARE_WAIT_QUEUE_HEAD(queue_wait); /* Define global wait queue for pstrace_get */
static struct pstrace empty_entry;
/* Spinlock to be used to syncronize pstrace_add */
DEFINE_SPINLOCK(lock_one);
unsigned long intr_flags;
/* Global desired pid when pstrace_clear is called */
atomic_t pid_gate = ATOMIC_INIT(-2);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid){
 if (pid == -1) {
  spin_lock_irqsave(&lock_one, intr_flags);
  TRACE_ALL_PROCESSES = true;
  spin_unlock_irqrestore(&lock_one, intr_flags);
 }
 else {
  /* TODO: make sure PID is legit */
  if (find_task_by_vpid(pid) == NULL) {
   return -EINVAL;
  }
  /* Log that a specific process should be traced */
  /* Critical Section */
  spin_lock_irqsave(&lock_one, intr_flags);
  traced_processes[trace_process_index] = pid;
  trace_process_index++;
  /* making traced_processes a ring buffer */
  if ((trace_process_index % PSTRACE_BUF_SIZE) == 0)
   trace_process_index = 0;
  spin_unlock_irqrestore(&lock_one, intr_flags);
   
  } 
 return 0L;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid){
 int i;
 if (pid == -1) {
  /* Critical Section */
  spin_lock_irqsave(&lock_one, intr_flags);
  TRACE_ALL_PROCESSES = false;
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
   traced_processes[i] = 0;
  }
  spin_unlock_irqrestore(&lock_one, intr_flags);
 }
 else {
  /* Stop a specific process from being traced 
   * If a process is already not being traced, nothing happens */
  /* Critical Section */
  spin_lock_irqsave(&lock_one, intr_flags);
  for (i = 0; i < trace_process_index; i++) {
   if (traced_processes[i] == pid) {
    /* overwrite the now unnecessary entry */
    for (; i < PSTRACE_BUF_SIZE - 1; i++) {
     traced_processes[i] = traced_processes[i+1];
     traced_processes[i+1] = 0;
    } 
    if (trace_process_index) {
     trace_process_index--;
    }
   }
  }
  spin_unlock_irqrestore(&lock_one, intr_flags);
 }
   return 0L;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace *, buf, long *, counter){
 /* If counter is greater than 0, wait until full buffer can be returned */
 long num_of_records = 0L;
 long kernel_counter;
 bool break_wait = false;
   struct pstrace *internal_buf = (struct pstrace *) kmalloc(sizeof(struct pstrace) * PSTRACE_BUF_SIZE, GFP_KERNEL);
   if (!internal_buf) {
  return -EFAULT;
 }
 if (copy_from_user(&kernel_counter, counter, sizeof(long))) {
  kfree(internal_buf);
  return -EFAULT;
 }
 if (kernel_counter > 0) {
  DEFINE_WAIT(wait);
  int condition = kernel_counter + PSTRACE_BUF_SIZE; /*calc counter val where we return pstrace_get */
  spin_lock_irqsave(&lock_one, intr_flags);  
  cond_vals[curr_waiting_pstrace_get_calls] = condition;
  printk(KERN_DEBUG "A new condition for the counter is: %d\n", condition);
  curr_waiting_pstrace_get_calls++;
  printk(KERN_DEBUG "We have updated the number of waiting pstrace get calls to %d\n", curr_waiting_pstrace_get_calls);
  spin_unlock_irqrestore(&lock_one, intr_flags);
  /* If there are too many calls to pstrace, we can return an error (referencing piazza) */
  if (curr_waiting_pstrace_get_calls > PSTRACE_BUF_SIZE) {
   return -EFAULT;
  }
     add_wait_queue(&queue_wait, &wait);
  printk(KERN_DEBUG "PLACING A PSTRACE_GET CALL ON WAIT QUEUE\n");
  while (1) { /* TODO: Change this condition for pstrace_clear to include gate */
   spin_lock_irqsave(&lock_one, intr_flags);
   if (total_records_written >= condition || atomic_read(&pid_gate) == pid) {
    break_wait = true;
    spin_unlock_irqrestore(&lock_one, intr_flags);
    break;
   }
   spin_unlock_irqrestore(&lock_one, intr_flags);
   prepare_to_wait(&queue_wait, &wait, TASK_INTERRUPTIBLE);
   if (signal_pending(current)) {
    /* Handle signal */
    break_wait = true;
    break; /* ??? index will just copy whats in the buffer in the following section */    
   }
   schedule();
  }
     printk(KERN_DEBUG "WE ARE FINISHING A CALL TO PSTRACE_GET\n");
  finish_wait(&queue_wait, &wait);
     spin_lock_irqsave(&lock_one, intr_flags);
  if (total_records_written >= condition || break_wait) { /*TODO: An else-if for pstrace_clear cond */
   int i;
   int delete_index;
   int index = trace_buf_index;
   for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
    if(pid == -1 || trace_buf_copy[index].pid == pid) {
     internal_buf[num_of_records] = trace_buf_copy[index];
     num_of_records++;
    }
    index++;
    if (index == PSTRACE_BUF_SIZE) {
     index = 0;
    }
   }
   /* pass the buf back to the user */
   if (copy_to_user(buf, internal_buf, sizeof(struct pstrace) * num_of_records)) {
    kfree(internal_buf);
    return -EFAULT;
   }
   /* update the counter val that the user has */
   kernel_counter = total_records_written;
   if (copy_to_user(counter, &kernel_counter, sizeof(long))) {
    kfree(internal_buf);
    return -EFAULT;
   }
   /* the following code manages the array of needed condition vals */
   delete_index = 0;
   for (i = 0; i < curr_waiting_pstrace_get_calls; i++) {
    if (cond_vals[i] == condition) {
     cond_vals[i] = 0;
    delete_index = 1;
    break;
    }
   }
   if (delete_index) {
    for (; i < curr_waiting_pstrace_get_calls; i++) {
     cond_vals[i] = cond_vals[i+1];
    }
    delete_index = 0;
   }
   curr_waiting_pstrace_get_calls--;
   printk(KERN_DEBUG "A CALL TO PSTRACE_GET HAS FINISHED.\n");
   /* now we can give up the lock again */
   spin_unlock_irqrestore(&lock_one, intr_flags);
  }
   
  } else {
  int i;
  int index;
  spin_lock_irqsave(&lock_one, intr_flags);
  index = calculate_index(num_of_elements_in_trace_buf, trace_buf_index, PSTRACE_BUF_SIZE);
  for (i = 0; i < num_of_elements_in_trace_buf; i++) {
   if (pid == -1 || trace_buf_copy[index].pid == pid) {
    internal_buf[num_of_records] = trace_buf[index];
    num_of_records++;
   }
   index++;
   if (index ==  PSTRACE_BUF_SIZE) {
    index = 0;
   }
  }
  spin_unlock_irqrestore(&lock_one, intr_flags);
  if (copy_to_user(buf, internal_buf, sizeof(struct pstrace) * num_of_records)) {
   kfree(internal_buf);
   return -EFAULT;
  }
 }
 kfree(internal_buf);
 return num_of_records;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid){
 int i;
 int j;
 int index;
 int index_2;
   atomic_set(&pid_gate, pid);
 wake_up(&queue_wait);
 spin_lock_irqsave(&lock_one, intr_flags);
 if (pid == -1) {
  /* Clear all records from ring buffer */
  /* Change pid_gate to pid so wakeups will break out of while loop */
  /* Clear actual buffer */
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
   trace_buf[i] = empty_entry;
  }
  trace_buf_index = 0;
  num_of_elements_in_trace_buf = 0;
 }
 else {
  /* Clear records for the given pid */
  /* Change pid_gate to pid so wakeups will break out of while loop */
  /* Clear buf of any elements with same pid */
  index = trace_buf_index;
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
   if (trace_buf[index].pid == pid) {
    index_2 = index;
    for (j = 0; j < PSTRACE_BUF_SIZE; j++) {
     if (j == (PSTRACE_BUF_SIZE - 1)) {
      trace_buf[index_2] = trace_buf[0];
      trace_buf[0] = empty_entry;
      index_2 = 0;
     } else {
      trace_buf[index_2] = trace_buf[index_2 + 1];
      trace_buf[index_2 + 1] = empty_entry;
      index_2++;
     }
    }
    trace_buf_index--;
    num_of_elements_in_trace_buf--;
    if (num_of_elements_in_trace_buf < 0) {
     num_of_elements_in_trace_buf = PSTRACE_BUF_SIZE;
    }
    if (trace_buf_index < 0) {
     trace_buf_index = PSTRACE_BUF_SIZE;
    } 
   }
   if ((++index % PSTRACE_BUF_SIZE) == 0) {
    index = 0;
   }
  }
 } 
 spin_unlock_irqrestore(&lock_one, intr_flags);
 atomic_set(&pid_gate, -2);
 return 0L;
}
/* Calculates where to start index in pstrace_add for adding records to internal buf */
int calculate_index(int total_elements, int index, int size) {
 if (total_elements == index) {
  return 0;
 } else {
  int diff = size - total_elements;
  if (index < diff) {
   return (index + size - diff);
  } else {
   return (index - diff);
  }
 }
}
/* Checks to see if pid is suppose to be traced. Assumes it has been called after acquiring spinlock */
bool pid_is_traced(pid_t pid) {
 int i;
 if (TRACE_ALL_PROCESSES) {
  return true;
 }
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (traced_processes[i] == pid)
   return true;
 }
 return false;
}
/* TODO: Make this method atomic!! */
void pstrace_add(struct task_struct *p){
 struct pstrace trace_entry;
 strcpy(trace_entry.comm,p->comm);
 trace_entry.pid = p->pid;
 /* 4 is the value of state when a task is stopped.
  * If it's greater we know to use exit_state */
 if (p->state <= 4) {
  trace_entry.state = p->state;
 }
 else {
  trace_entry.state = p->exit_state;
 }
 //printk(KERN_DEBUG "PSTRACE_ADD CALL INITIATED!\n");
 /* Critical Section*/
 /* Use spin_lock_irqsave to disable and renable interupts */
 spin_lock_irqsave(&lock_one, intr_flags);
 if (pid_is_traced(p->pid)) {
  int i,j;
  trace_buf[trace_buf_index] = trace_entry;
  trace_buf_index++;
  if (trace_buf_index == PSTRACE_BUF_SIZE) {
   trace_buf_index = 0;
  }
  total_records_written++;
  printk(KERN_DEBUG "THE GLOBAL COUNTER HAS REACHED %ld IN PSTRACE_ADD\n", total_records_written);
  if (num_of_elements_in_trace_buf < PSTRACE_BUF_SIZE) {
   num_of_elements_in_trace_buf++;
  }
  /* check outstanding pstrace_get calls to see if condition will be met */
  for (i = 0; i < curr_waiting_pstrace_get_calls; i++) {
   if (cond_vals[i] == total_records_written) {
    printk(KERN_DEBUG "WE ARE WAKING UP PSTRACE_GET!\n");
    /* make a copy of the ring buffer in this state for pstrace_get to return */
    for (j = 0; j < PSTRACE_BUF_SIZE; j++) {
     trace_buf_copy[j] = trace_buf[j];
    }
    spin_unlock_irqrestore(&lock_one, intr_flags);
    wake_up(&queue_wait); /* We wake up pending pstrace_get calls when a cond_val is met! */
    return;
   }
  }
 }
 spin_unlock_irqrestore(&lock_one, intr_flags);
 //printk(KERN_DEBUG "PSTRACE_ADD CALL COMPLETE!\n");
 return;
}