#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/pstrace.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/sched.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
struct pstrace_buffer {
 struct pstrace pstr_buf[PSTRACE_BUF_SIZE];
 long head;
 long tail;
 long counter;
};
DEFINE_SPINLOCK(ring_buffer_lock);
DECLARE_WAIT_QUEUE_HEAD(wqh);
struct pstrace_buffer ring_buffer;
int initialized = 0;
atomic_t g_pid = ATOMIC_INIT(-2);
long ucounter = 0;
int clear = 0;
// kernel/sched/core.c -> __schedule, try_to_wake_up, wake_up_new_task
// exit.c
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
/*
* Syscall No. 441
* Enable the tracing for @pid. If -1 is given, trace all processes.
*/
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if(pid != -1 && !get_root(pid))
  return -ESRCH;
 atomic_set(&g_pid, pid);
 return 0;
}
/*
* Syscall No. 442
* Disable tracing.
*/
SYSCALL_DEFINE0(pstrace_disable)
{
 //pid negative 2 to indicate no process is being traced
 atomic_set(&g_pid,-2);
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace *cur_task_info;
 unsigned long flags;
 if (state != TASK_RUNNING&& 
 state != TASK_INTERRUPTIBLE && 
 state != TASK_UNINTERRUPTIBLE &&
 !(state & __TASK_STOPPED) &&
 state != EXIT_ZOMBIE &&
 state != EXIT_DEAD &&
 state != TASK_RUNNABLE)
  return;
 if (atomic_read(&g_pid) == -2)
  return;
 spin_lock_irqsave(&ring_buffer_lock, flags);
 if (!initialized) {
  ring_buffer.head = 0;
  ring_buffer.tail = -1;
  ring_buffer.counter = 0;
  initialized = 1;
 }
 if (p->tgid == atomic_read(&g_pid) || atomic_read(&g_pid) == -1) {
  ring_buffer.tail += 1;
  if (ring_buffer.tail == PSTRACE_BUF_SIZE) {
   ring_buffer.tail = 0;
   ring_buffer.head = 1;
  }
  if (ring_buffer.tail != 0 
   && ring_buffer.tail == ring_buffer.head) {
   ring_buffer.head += 1;
   if (ring_buffer.head == PSTRACE_BUF_SIZE) {
    ring_buffer.head = 0;
   }
  }
  cur_task_info = &(ring_buffer.pstr_buf[ring_buffer.tail]); 
  strncpy(cur_task_info -> comm, p->comm, sizeof(cur_task_info->comm));
  cur_task_info -> state = state;
  cur_task_info -> pid = task_tgid_nr(p);
  cur_task_info -> tid = task_pid_nr(p);
  ring_buffer.counter += 1;
  // if (ucounter && ring_buffer.counter >= ucounter) {
  if (ucounter + PSTRACE_BUF_SIZE > ring_buffer.counter){
   spin_unlock_irqrestore(&ring_buffer_lock, flags);
   wake_up_all(&wqh);
   spin_lock_irqsave(&ring_buffer_lock, flags);
   ucounter = 0;
  }
 }
 spin_unlock_irqrestore(&ring_buffer_lock, flags);
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, 
  long __user *, counter)
{
 struct pstrace *kbuf;
 int kcounter, num_entries, i, last_counter, length;
 int local_clear = 0;
 size_t size;
 unsigned long flags;
 int exit_signal = 0;
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 if (kcounter < 0){
  return -EINVAL;
 } else if (kcounter == 0) {
  spin_lock_irqsave(&ring_buffer_lock, flags);
  if (ring_buffer.tail < 0)
   num_entries = 0;
  else {
   num_entries = ring_buffer.tail - ring_buffer.head + 1;
   if (num_entries == 0)
    num_entries = PSTRACE_BUF_SIZE;
  }
  last_counter = ring_buffer.counter;
  spin_unlock_irqrestore(&ring_buffer_lock, flags);
 }
 else {
  spin_lock_irqsave(&ring_buffer_lock, flags);
  if (kcounter + 2 * PSTRACE_BUF_SIZE <= ring_buffer.counter) {
   num_entries = 0;
   last_counter = ring_buffer.counter;
   printk(KERN_CRIT "case 1 \n");
   spin_unlock_irqrestore(&ring_buffer_lock, flags);
  }
  else if (kcounter + PSTRACE_BUF_SIZE <= ring_buffer.counter) {
   long offset = ring_buffer.counter - PSTRACE_BUF_SIZE;
   num_entries = kcounter + PSTRACE_BUF_SIZE - offset;
   last_counter = kcounter + PSTRACE_BUF_SIZE;
   printk(KERN_CRIT "case 2 \n");
   printk(KERN_CRIT "num_entries 1: %d\n", num_entries);
   spin_unlock_irqrestore(&ring_buffer_lock, flags);
  }
  else {
   DEFINE_WAIT(wait);
   long bcounter;
   ucounter = kcounter;
   spin_unlock_irqrestore(&ring_buffer_lock, flags);
   printk(KERN_CRIT "going to sleep\n");
   add_wait_queue(&wqh, &wait);
   while (1) {
    prepare_to_wait(&wqh, &wait, TASK_INTERRUPTIBLE);
    spin_lock_irqsave(&ring_buffer_lock, flags);
    bcounter = ring_buffer.counter;
    local_clear = clear;
    spin_unlock_irqrestore(&ring_buffer_lock, flags);
    if (bcounter >= kcounter + PSTRACE_BUF_SIZE) {
     long offset = bcounter - PSTRACE_BUF_SIZE;
     num_entries = kcounter + PSTRACE_BUF_SIZE - offset;
     break;
    }
    if (clear) {
     num_entries = max((long)0, bcounter - kcounter);
     break;
    }
    if (signal_pending(current)) {
     exit_signal = 1; 
     printk(KERN_CRIT "receive signal\n");
     num_entries = 0;
     break;
    }
    printk(KERN_CRIT "sleeping\n");
    schedule();
   }
   finish_wait(&wqh, &wait);
   last_counter = kcounter + PSTRACE_BUF_SIZE;
   printk(KERN_CRIT "case 3 \n");
      spin_lock_irqsave(&ring_buffer_lock, flags);
   clear = 0;
   spin_unlock_irqrestore(&ring_buffer_lock, flags);
  }
 }
 printk(KERN_CRIT "buffer counter: %ld\n", ring_buffer.counter);
 printk(KERN_CRIT "tail: %ld\n", ring_buffer.tail);
 printk(KERN_CRIT "head: %ld\n", ring_buffer.head);
 printk(KERN_CRIT "intialized: %d\n", initialized);
 printk(KERN_CRIT "num_entries 2: %d\n", num_entries);
 size = sizeof(struct pstrace) * num_entries;
 kbuf = kmalloc(size, GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
    spin_lock_irqsave(&ring_buffer_lock, flags);
 if(local_clear){
  length = (ring_buffer.tail - ring_buffer.head) + 1;
  if (length >= 0){
   num_entries = min(num_entries,length);
  }else{
   num_entries = min(num_entries,PSTRACE_BUF_SIZE);
  }
 }
 printk(KERN_CRIT "num_entries 3 : %d\n", num_entries); 
 for (i = 0; i < num_entries; ++i) {
  int cur = (ring_buffer.head + i) % PSTRACE_BUF_SIZE;
  kbuf[i] = ring_buffer.pstr_buf[cur];
 }
 spin_unlock_irqrestore(&ring_buffer_lock, flags);
 if (put_user(last_counter, counter) || 
  copy_to_user(buf, kbuf, size)) {
   kfree(kbuf);
   return -EFAULT;
  }
 kfree(kbuf);
 if(exit_signal)
  return -EINTR;
 return num_entries;
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
 unsigned long flags;
 printk(KERN_CRIT "clearing stuff\n");
 spin_lock_irqsave(&ring_buffer_lock, flags);
 ring_buffer.head = 0;
 ring_buffer.tail = -1;
 clear = 1;
 spin_unlock_irqrestore(&ring_buffer_lock, flags);
 wake_up_all(&wqh);
 spin_lock_irqsave(&ring_buffer_lock, flags);
 printk(KERN_CRIT "wake up thread\n");
 spin_unlock_irqrestore(&ring_buffer_lock, flags);
 return 0;
}