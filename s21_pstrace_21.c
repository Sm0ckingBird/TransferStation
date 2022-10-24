#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
DEFINE_SPINLOCK(basket_lock);
DEFINE_SPINLOCK(rbuf_lock);
struct pst_ring_buf *rbuf;  /* declares global ring buffer */
struct ps_basket *basket;   /* declares global pid trace buffer */
int ds_initialized = 0;     /* flag to ensure we initialize the buffers once */
/*
 * Convenience function for initializing the ring buffer.
 * This function sets size, index i, and capacity to appropriate inital values.
 */ 
int init_pst_ring_buf(void)
{
        int i;
 rbuf = kmalloc(sizeof(struct pst_ring_buf), GFP_KERNEL);
 if (!rbuf)
  return 1;
          /* allocate and initialize memory for a struct pstrace at loc i */
        for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
                rbuf->buf[i] = kmalloc(sizeof(struct pstrace), GFP_KERNEL);
                memset(rbuf->buf[i], 0, sizeof(struct pstrace));
 } 
        rbuf->capacity = PSTRACE_BUF_SIZE; 
        rbuf->size = 0; 
 rbuf->counter = 0;
 return 0;
}
/*
 * Empties global basket. Used in init and invert.
 */
void clear_basket(void)
{
 int i;
 /* Clear basket */
        for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
                basket->tracking[i] = 0;
  basket->deleted[i] = 0;
        } 
          basket->n = 0;
}
/*
 * Convenience function for initializing the data structure which tracks
 * which processes are being traced (struct ps_basket).
 */ 
int init_basket(void)
{
 basket = kmalloc(sizeof(struct ps_basket), GFP_KERNEL);
 if (!basket)
  return 1;
 //printk(KERN_INFO "basket->tracking_all: %d", basket->tracking_all);
 clear_basket();
 basket->tracking_all = 0;
 //printk(KERN_INFO "basket->tracking_all: %d", basket->tracking_all);
 return 0;
}
/*
 * Check if a task PID is in basket, and return its index in the basket buffer.
 *
 * A PID is in the basket for one of two reasons:
 * 
 * 1. We are not tracking all, and the PID is marked as enabled.
 * 2. We are tracking all, and the PID is marked as diabled.
 * 
 * If found, returns the index of the pid in the basket buffer.
 * If not found, return -1. This return value will be used in if statements.
 */
int basket_index(pid_t pid)
{
 int i;
 short lazy_deleted;
 /* Here you are checking if pid in basket, "tracked" */
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  lazy_deleted = basket->deleted[i];
  if (lazy_deleted && (basket->tracking[i] == pid)) {
   printk(KERN_INFO "pid %d was lazy deleted", pid);
   return -1; // in basket, but marked as deleted
  }
  if (basket->tracking[i] == pid)
   return i;
 }
 /* not in basket */
 return -1;
}
/*
 * Add to global ps_basket the given pid if it is not already in basket
 * The basket represents all processes given by the user, either via
 * enable OR disable.
 */ 
int add_to_basket(pid_t pid)
{
     int i;
 short lazy_deleted;
 printk(KERN_INFO "adding to basket: %d\n", pid);
 /* if PID is already in basket, do nothing */
 if (basket_index(pid) != -1)
  return 0;
 printk(KERN_INFO "finding place to insert into basket\n");
 /* find first lazy_deleted entry for overwriting */
 /* If no entries are lazy deleted, i is first open spot */
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  lazy_deleted = basket->deleted[i];
  if (lazy_deleted)
   break;
  else if (basket->tracking[i] == 0) // empty spot
   break;
 }
   /* check for buffer over-flow */
        if (i >= PSTRACE_BUF_SIZE)
                return 1;
 printk(KERN_INFO "place found: %d\n", i);
 basket->tracking[i] = pid;
 basket->deleted[i] = 0;
        basket->n++;
 /* return success */
 printk(KERN_INFO "added PID: %d\n", pid);
        return 0;
}
/*
 * Lazy delete PID from global ps_basket if it is not already in basket
 */ 
int remove_from_basket(pid_t pid)
{
 int basket_idx;
 printk(KERN_INFO "removing from basket: %d\n", pid);
 /* if PID not in basket, do nothing */
 if ( (basket_idx = basket_index(pid)) == -1)
  return 0;
 /* lazy delete entry */
 basket->deleted[basket_idx] = 1;
 basket->n--;
 /* check for buffer under-flow */
        if (basket->n < 0)
                return 1;
 /* return success */
 printk(KERN_INFO "removed PID: %d\n", pid);
        return 0;
}
void add_to_rbuf(struct task_struct *p)
{
 int ring_buf_loc, invalid_state = 0;
 struct pstrace *entry;
        pid_t pid;
        long state;
   /* get the state of a process */
 state = p->exit_state;
 if (state != EXIT_ZOMBIE && state != EXIT_DEAD) { // 0x0020 ZOMBIE, 0x0010 DEAD
  state = p->state;
  switch (state) {
   case TASK_RUNNING: // 0x0000
   case TASK_INTERRUPTIBLE: // 0x0001
   case TASK_UNINTERRUPTIBLE: // 0x0002
   case __TASK_STOPPED: // 0x0004
   case TASK_STOPPED: // (TASK_WAKEKILL | __TASK_STOPPED)
    invalid_state = 0;
    break;
   default: //to be deleted
    //printk(KERN_INFO "%ld state not tracked\n", state);
    invalid_state = 1;
    break;
  }
 }
 // if we are not tracking a state, do not add to rbuf
 if (invalid_state)
  return;
// printk(KERN_INFO "adding to ring buffer: %d with state %ld", p->pid, p->state);
 /* get location we are going to overwrite, wrap around if applicable */
 ring_buf_loc = rbuf->counter % rbuf->capacity;
 //printk(KERN_INFO "adding comm to rbuf: %s\tlocation: %d", p->comm, ring_buf_loc);
 /* pull in the struct pstrace in the buffer for overwriting */
 entry = rbuf->buf[ring_buf_loc];
 /* fill in data for new entry at its memory location in buf[i] */
         /* printk(KERN_INFO "adding comm to rbuf: %s\tPID: %d\tstate: %ld",
  p->comm, p->pid, p->state);
*/ entry->state = state;
 if (p->comm)
                get_task_comm(entry->comm, p);
        else
                memset(entry->comm, 0, 16);
 //printk(KERN_INFO "entry comm: %s", entry->comm);
        if (p->pid)
                pid = task_pid_nr(p);
        else 
                pid = 0;
 //entry->state = state;
 //printk(KERN_INFO "%d's state is now: %ld\n", pid, state);
 entry->pid = pid;
        /* increment index, wrap-around if applicable */
 rbuf->counter++;
 if (rbuf->size < rbuf->capacity)
  rbuf->size++;
 printk(KERN_INFO "entry comm: %s\tentry pid: %d\tentry state: %ld"
  "\ninserted at: %d\tpost counter: %ld, post rbuf size: %d\n",
  entry->comm, entry->pid, entry->state,
  ring_buf_loc, rbuf->counter, rbuf->size);
// printk(KERN_INFO "added to ring buffer: %d", p->pid);
// printk(KERN_INFO "rbuf size: %d\trbuf counter: %ld\tring_buf_loc: %d",
//  rbuf->size, rbuf->counter, ring_buf_loc);
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 pid_t task_pid;
 int earmarked_pid, tracking_all;
 /* if data structures are not enabled, do nothing. Useful on boot. */
 if (!ds_initialized)
     return;
 if (!is_process(p))
  return;
// printk(KERN_INFO "pstrace_add called");
 task_pid = task_pid_nr(p);
 //printk(KERN_INFO "ptrace_add called with task PID: %d", task_pid);
 spin_lock(&basket_lock); //TODO change to spin_lock_irqsave()
 earmarked_pid = (basket_index(task_pid) != -1);
 tracking_all = basket->tracking_all;
 spin_unlock(&basket_lock); // change this to spin_unlock_irqrestore()
/* if (tracking_all) {
  printk(KERN_INFO "pstrace_add tracking: %s\tearmarked_pid: %d\ttracking_all: %d",
   p->comm, earmarked_pid, tracking_all);
 }
*/ /*
  * Handle conditions of when to add to ring buffer.
  *
  * If we are tracking all and the PID is not earmarked in the basket
  * as a disabled process, add to ring buffer.
  *
  * If we are not tracking all and the PID is in the basket, then the
  * PID is earmarked as enabled. In this case, add to ring buffer.
  *
  * In all other cases, do not add to ring buffer.
  */
 spin_lock(&rbuf_lock);
 if (tracking_all && !earmarked_pid) { // double check logic
  add_to_rbuf(p);
 } else if (!tracking_all && earmarked_pid) {
  add_to_rbuf(p);
 }
 spin_unlock(&rbuf_lock);
// printk(KERN_INFO "ptrace_add PID: %d\treturning.", task_pid);
 return; 
} 
/*
 * Checks whether PID maps to a task, and whether that task is a 
 * process and not a thread.
 *
 * Adapted from HW2
 */
int valid_pid(pid_t pid)
{
 struct task_struct *task;
        if (pid == 0)
                return 1;
 /* check if pid can be found */
        if ( (task = find_task_by_vpid(pid)) == NULL)
  return 0;
   return is_process(task);
}
int is_process(struct task_struct *task) {
 if (task_pid_nr(task) == task_tgid_nr(task))
  return 1;
 else 
  return 0;
}
/*
 * Convenience function to reduce redundancy in
 * pstrace_enable and pstrace_disable.
 *
 * enable_mode == 1 when a PID is being enabled. 
 * enable_mode == 0 when a PID is being disabled.
 * 
 * See internal comments for full behaviour description.
 */
int pstrace_modify_basket(pid_t pid, short enable_mode)
{
 int ret;
 printk(KERN_INFO "PID == %d passed to enable/disable\n", pid);
 spin_lock(&basket_lock);
 spin_lock(&rbuf_lock);
 /* init global structs if not initialized */
 if (!ds_initialized) {
  printk(KERN_INFO "initializing data structures\n");
  /* create a pointer to the pst_ring_buf */
  ret = init_pst_ring_buf(); 
         if (ret) {
                 printk(KERN_ERR "Cannot allocate pst_ring_buf\n");
   spin_unlock(&rbuf_lock);
   spin_unlock(&basket_lock);
                 return -ENOMEM;
         }
    /* create a pointer to the basket buffer */
  ret = init_basket();
         if (ret) {
                 printk(KERN_ERR "Cannot allocate ps_basket\n");
   spin_unlock(&rbuf_lock);
   spin_unlock(&basket_lock);
                 return -ENOMEM;
         }
  /* only initialize the global variable once per process call */
  ds_initialized = 1;
  printk(KERN_INFO "data structures initialized\n");
  //printk(KERN_INFO "basket->tracking_all: %d", basket->tracking_all);
 }
   spin_unlock(&rbuf_lock);
 /* 
  * Handle enable / disable all
  * 
  * Calls to enable / disable all involve clearing the basket of 
  * any PIDs the user has given. This is because the basket only 
  * contains PIDs that are an exception to the tracking_all flag's
  * status (on or off). A call to disable or enable all clears the 
  * basket of any user-specified exceptions.
  *
  * If the tracking_all flag is not in the right state, flip it.
  * In other words, if we are currently tracking all, and a call comes
  * to disable all, then flip the flag bit.
  */
 if (pid == -1) {
  printk(KERN_INFO "bulk action initiated (enable / disable).");
  clear_basket(); 
  printk(KERN_INFO "before: basket->tracking_all: %d", basket->tracking_all);
  printk(KERN_INFO "before: enable_mode: %d", enable_mode);
  if (basket->tracking_all != enable_mode)
   basket->tracking_all = !basket->tracking_all;
  printk(KERN_INFO "after: basket->tracking_all: %d", basket->tracking_all);
  spin_unlock(&basket_lock); 
  printk(KERN_INFO "bulk action successful");
  return 0;
 }
 /* From here, we handle specific PIDs given from the user */
 /* if PID is not a real task, return error */   
/* if (!valid_pid(pid)) { // should we do this?
  spin_unlock(&basket_lock); 
  return -EINVAL;
 }
*/
 /*
  * Handle specific PIDs given from user
  *
  * If we are not tracking all, and a call comes to enable a PID,
  * then we earmark the PID in the basket by adding it.
  * (tracking_all == 0 and enable_mode == 1)
  * 
  * If we are tracking all, and a call comes to disable a PID, 
  * then we earmark the PID in the basket by adding it.
  * (tracking_all == 1 and enable_mode == 0)
  * In this instance, PIDs in the basket represent /disabled/ processes.
  *
  * 
  * If we are not tracking all, and a call comes to disable a PID,
  * then we remove that PID from the basket (if it exists).
  * (tracking_all == 0 and enable_mode == 0)
  * 
  * If we are tracking all, and a call comes to enable a PID,
  * then we remove that PID from the basket (if it exists).
  * (tracking_all == 1 and enable_mode == 1)
  * In this scenario, PIDs in the basket represent PIDs earmarked so that
  * we /don't/ track them. Enabling a PID in the scenario where we 
  * are already tracking all means that we want to undo a previous call
  * to disable tracking that PID.
  */
 if (basket->tracking_all != enable_mode) {
  if (add_to_basket(pid)) {
   spin_unlock(&basket_lock); 
   return -EFAULT;
  }
 } else {
  if (remove_from_basket(pid)) { // remove if exists
   spin_unlock(&basket_lock); 
   return -EFAULT;
  }
 }
   spin_unlock(&basket_lock); 
 //return basket->n;
 return 0;
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{ 
 return pstrace_modify_basket(pid, 1);
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 return pstrace_modify_basket(pid, 0);
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
        long __user *, counter)
{
 long copied_records = 0;
 //int ret;
 long counter_cpy;
 struct pstrace *buf_cpy;
 int i;
        long j = 0, k;
 int index;
 int ret;
 struct pstrace temp;
 /* zero out the memory of a struct pstrace */
 memset(&temp, 0, sizeof(struct pstrace));
   /* need to copy from user for the counter */
 if ((ret = copy_from_user(&counter_cpy, counter, sizeof(long)))) {
  printk(KERN_INFO "copy_from_user returned:%d\n", ret);
  return -EFAULT;
 }
 if (buf == NULL || counter == NULL || counter_cpy < 0)
  return -EINVAL;
 if ( (basket_index(pid) == -1) && !basket->tracking_all) {
  printk(KERN_INFO "invalid pid: %d\n", pid);
  return -EINVAL;
 }
 /* dynamically allocated space for an array of struct prinfos */
 buf_cpy = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (!buf_cpy)
  return -ENOSPC;
 printk(KERN_INFO "locks the ring buffer\n");
 /*You may NOT let the system call spin when the ring buffer is not full */
 /* this lock is for the ring buffer */
 spin_lock(&rbuf_lock);
 /* return all records */
 if (pid == -1) { // should be pid == -1, changed for testing purposes
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  /* need a lock when accessing rbuf, possibly a read lock */
   /* check if the struct is all zeroed out */
   if (memcmp(&buf[i], &temp, sizeof(struct pstrace))!= 0) {
    strncpy(buf_cpy[i].comm, rbuf->buf[i]->comm, 16);
    buf_cpy[i].pid = rbuf->buf[i]->pid;
    buf_cpy[i].state = rbuf->buf[i]->state;
    copied_records++;
   }
  }
  printk(KERN_INFO "unlocks the ring buffer\n");
  spin_unlock(&rbuf_lock);
  /* assume buf is allocated by user already */
  if (copy_to_user(buf, buf_cpy, PSTRACE_BUF_SIZE * sizeof(struct pstrace))) {
   kfree(buf_cpy);
   return -EFAULT;
  }
  kfree(buf_cpy);
  return copied_records;
 }
 /* otherwise, only copy records of @pid */
 /* j is used for calculating the index for buf_cpy */
 /* k is used for iterating the ring buffer from the beginning */
 for (k=0; k < PSTRACE_BUF_SIZE; k++) {
  /* if we find this @pid in the ring buffer, add it to buf_cpy */
  if (rbuf->buf[k]->pid == pid) {
   /* calculate the index for buf_cpy and put the record */
   index = j++; 
   strncpy(buf_cpy[index].comm, rbuf->buf[k]->comm, 16);
   buf_cpy[index].pid = rbuf->buf[k]->pid;
   buf_cpy[index].state = rbuf->buf[k]->state;
   copied_records++;
  }
 }
 spin_unlock(&rbuf_lock);
   /* assume buf is allocated by user already */
 if (copy_to_user(buf, buf_cpy, PSTRACE_BUF_SIZE * sizeof(struct pstrace))) {
  kfree(buf_cpy);
  return -EFAULT;
 }
 kfree(buf_cpy); 
 return copied_records;
}
/**** currently used for testing *****/
// print all the buffer entries
// need to call this here, so we can call disable in other contexts,
// and see the full changes
void print_rbuf(void)
{
 struct pstrace **temp;
 int buffer_size, i = 0;
     printk(KERN_INFO "================================");
 printk(KERN_INFO "WE ARE NOW PRINTING FROM CLEAR");
 temp = rbuf->buf;
 printk(KERN_INFO "has_been_initialized %d", ds_initialized);
 buffer_size = rbuf->size;
 printk(KERN_INFO "basket_size: %d", basket->n);
 printk(KERN_INFO "buf size: %d\n", buffer_size);
 while (i < buffer_size) {
  printk(KERN_INFO "===========================");
  printk(KERN_INFO "temp[%d]->comm: %s\n",i, temp[i]->comm);
  printk(KERN_INFO "temp[%d]->pid: %d\n",i, temp[i]->pid);
  printk(KERN_INFO "temp[%d]->state: %ld\n",i, temp[i]->state);
  printk(KERN_INFO "===========================");
  i++;
 }
}
/*
 * Syscall No. 439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i;
 spin_lock(&rbuf_lock);
 printk(KERN_INFO "Clearing ring buffer of size %d\n", rbuf->size);
 for (i = 0; i < rbuf->size; i++) {
  if ( (rbuf->buf[i]->pid == pid) || (pid == -1) ) {
   printk(KERN_INFO "memseting rbuf->buf[%d] for PID %d\n",
    i, rbuf->buf[i]->pid);
   memset(rbuf->buf[i], 0, sizeof(struct pstrace));
   //if ( memset(rbuf->buf[i], 0, sizeof(struct pstrace)) == NULL)
   // return -EFAULT;
  }
 }
 print_rbuf(); // prints ring buffer to kernel
 spin_unlock(&rbuf_lock);
 return 0;
}