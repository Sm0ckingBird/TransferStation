#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500
struct pstrace buf[PSTRACE_BUF_SIZE];
int nwait;
int bufferCounter;
pid_t traced = -2;
static DEFINE_SPINLOCK(add_lock);
static DEFINE_SEMAPHORE(wait_sem);
static DECLARE_WAIT_QUEUE_HEAD(wq);
bool wake_all = false;
void pstrace_add(struct task_struct *p, long state)
{
 int idx;
 unsigned long flags;
 // if state is a bitwise or of a state of interest, change it to the value we want
 if (state == TASK_KILLABLE || state == TASK_DEAD) // TASK_DEAD recorded elsewhere
  return;
 spin_lock_irqsave(&add_lock, flags); //no one can access add at the same time
 if (p->pid == traced || traced == -1){
  idx = bufferCounter % PSTRACE_BUF_SIZE;
  get_task_comm(buf[idx].comm, p);
  buf[idx].state = state;
  buf[idx].pid = task_tgid_vnr(p);
  buf[idx].tid = task_pid_vnr(p);
  bufferCounter++;
  // wake up a waiting get to have it recheck the condition now that you have added a record
  // todo: what if a different waiting get is looking for a smaller number of records? maybe we need to wake up all here
  wake_up_interruptible(&wq);
 }
 spin_unlock_irqrestore(&add_lock, flags);
}
static struct task_struct *get_root(int pid)
{
 if (pid == 0)
  return &init_task;
 return find_task_by_vpid(pid);
}
static int isWaiting(pid_t pid)
{
 int i = 0;
 // todo: insert lock here since accessing nwait?
 for(; i < nwait; i++){
//<commenting out for now bc prevents compiling>
//  if(waiting[i] == pid){ // todo: need to handle threads
//   return 1;
//  }
 }
 return 0;
}
static void wakeUp(pid_t pid)
{
}
static int copy_ring_buf(struct pstrace *kbuf) // written for get() with counter == 0, may or may not be useful in other cases
{
 int i, idx, count_not_returned;
 count_not_returned = 0;
 // todo: either should have a lock when called or should lock here
 if (bufferCounter <= PSTRACE_BUF_SIZE) {
  idx = 0;
  for (i = 0; i < bufferCounter; i++) {
   if (buf[i].pid == -1) { // don't return cleared records
    count_not_returned++;
    continue;
   }
  // memcpy(kbuf[idx], buf[i], sizeof(struct pstrace)); // make sure calling buf like this will refer to the global var
   memcpy(kbuf[idx].comm, buf[i].comm, 16);
   kbuf[idx].state = buf[i].state;
   kbuf[idx].pid = buf[i].pid;
   kbuf[idx].tid = buf[i].tid;
   idx++;
  }
  return bufferCounter - count_not_returned;
 } else { // ring buffer is full, some records have been overwritten so new method to return in chronological order
  idx = bufferCounter % PSTRACE_BUF_SIZE;
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) { // ring buffer is full so iterate all the way up to PSTRACE_BUF_SIZE
   if (buf[idx].pid == -1) {// don't return cleared records
    count_not_returned++;
    continue;
   }
   memcpy(kbuf[i].comm, buf[idx].comm, 16);
   kbuf[i].state = buf[idx].state;
   kbuf[i].pid = buf[idx].pid;
   kbuf[i].tid = buf[idx].tid;
   idx++; 
  }
  return PSTRACE_BUF_SIZE - count_not_returned;
 }
}
static int copy_ring_buf2(struct pstrace *kbuf, int start)
{
 int i, idx;
 idx = 0;
 for (i = start; i < PSTRACE_BUF_SIZE; i++) {
  memcpy(kbuf[idx].comm, buf[i].comm, 16);
  kbuf[idx].state = buf[i].state;
  kbuf[idx].pid = buf[i].pid;
  kbuf[idx].tid = buf[i].tid;
  idx++;
 }
 for (i = 0; i < (bufferCounter % PSTRACE_BUF_SIZE); i++){
  memcpy(kbuf[idx].comm, buf[i].comm, 16);
  kbuf[idx].state = buf[i].state;
  kbuf[idx].pid = buf[i].pid;
  kbuf[idx].tid = buf[i].tid;
  idx++;
 }
 return PSTRACE_BUF_SIZE;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *tsk;
 spin_lock(&add_lock);
 // if a process is already enabled, reset traced to -2
 traced = -2;
 //if pid != -1 check pid is valid
 if (pid >= 0){
  // if tracing for that pid was already enabled, don't modify traced
  long enable_state;
  rcu_read_lock();
  tsk = get_root(pid);
  if (tsk == NULL) {
   rcu_read_unlock();
   spin_unlock(&add_lock);
   return -ESRCH; // unlock if locked here (should be locked to access the task list so should unlock
  }
  traced = pid;
  // if task has exited, make state exit_state
  if (tsk->state == TASK_DEAD) {
   enable_state = tsk->exit_state;
  } else if (tsk->state == TASK_STOPPED) {
   enable_state = __TASK_STOPPED;
  } else {
   enable_state = tsk->state;
  }
  rcu_read_unlock();
  spin_unlock(&add_lock);
  pstrace_add(tsk, enable_state); // maybe not needed (def don't do for all tasks)
 }
 else if (pid == -1) {
  // set traced = -1 to indicate to add to trace all processes
  // this strategy is efficient but means we don't add the initial state of all tasks to the ring buffer -> but maybe that's fine and we should remove it above anyway bc we are tracing changes? might be a good ed question
  // note if you do go through the whole list and add then you need to unlock first
  traced = -1;
 } else {
  spin_unlock(&add_lock);
  return -EINVAL;
 }
 //todo: I think unlock here
 spin_unlock(&add_lock); // in case of fall through
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 spin_lock(&add_lock);
 traced = -2;
 spin_unlock(&add_lock);
 return 0;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 int i, j;
 i = 0;
 down(&wait_sem); // todo: lock so your isWaiting queue is the same
 for(; i < PSTRACE_BUF_SIZE; i++){
  j = 0;
//  if(isWaiting(buf[i].pid)){
   //if process is waiting, it is woken up. It copies and returns relevant records.
//   wakeUp(buf[i].pid);
//  }
  wake_all = true;
  wake_up_all(&wq);
  buf[i].state = -1;
  buf[i].pid = -1;
  buf[i].tid = -1;
  for(; j < 16; j++){
   buf[i].comm[j] = '\0';
  }
 }
 wake_all = false; // reset wake_all indicator
 up(&wait_sem); //todo: unlock
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 long kcounter;
 struct pstrace *kbuf;
 unsigned long flags;
 size_t size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 if (!buf || !counter){
  return -EINVAL;
 }
 if (get_user(kcounter, counter)) {
  return -EFAULT;
 }
 if (kcounter < 0) {
  return -EINVAL;
 }
 kbuf = kmalloc(size, GFP_KERNEL);
 if (kbuf == NULL) 
  return -ENOMEM;
 spin_lock_irqsave(&add_lock, flags); // wait_event_interruptible requires this
 if (kcounter == 0) {
  int num_copied;
  kcounter = bufferCounter; // buffercounter changed to int instead of atomic_t
  num_copied = copy_ring_buf(kbuf);
  spin_unlock(&add_lock);
    if (put_user(kcounter, counter)) {
   kfree(kbuf);
   return -EFAULT;
  }
  if (copy_to_user(buf, kbuf, size)) { // is size the right amt of bytes here?
   kfree(kbuf);
   return -EFAULT;
  }
  return num_copied;
 } else if (kcounter > 0 && bufferCounter < (kcounter + PSTRACE_BUF_SIZE)) {
  // todo: implement sleeping until full buffer is returned
  // make sure you return the number of records copied
  // make sure you account for records cleared -> see commit 10/19 ~8:35 for quick pattern
         //sleep
  int sig;
  sig = wait_event_interruptible(wq, bufferCounter == (kcounter + PSTRACE_BUF_SIZE) || wake_all); // wake_all will be set to true in clear only so all processes can be awoken
  // add lock should be held after this returns according to documentation (and when it's called - it will release it internally while it blocks)
  if (sig) {
   spin_unlock_irqrestore(&add_lock, flags);
   kfree(kbuf);
   return -EINTR;
  }
  //wait_event_interruptible(waiting, bufferCounter < (kcounter + PSTRACE_BUF_SIZE));
         //fill starting at (kcounter + 1) % PSTRACE_BUF_SIZE
  copy_ring_buf2(kbuf, (kcounter + 1) % PSTRACE_BUF_SIZE);
            spin_unlock_irqrestore(&add_lock, flags);
 } else if (kcounter > 0 && bufferCounter >= (kcounter + PSTRACE_BUF_SIZE)) {
         //fill starting at buffCounter % PSTRACE_BUF_SIZE to (kcounter + PSTRACE_BUF_SIZE) % PSTRACE_BUF_SIZE
  copy_ring_buf2(kbuf, bufferCounter % PSTRACE_BUF_SIZE);
  // make sure you account for records cleared -> see commit 10/19 ~8:35 for quick pattern
         spin_unlock_irqrestore(&add_lock, flags);
     }
   kcounter = kcounter + PSTRACE_BUF_SIZE;
 if(put_user(kcounter, counter)){
  kfree(kbuf);
  return -EFAULT;
 }
 if (copy_to_user(buf, kbuf, size)) { // is size the right amt of bytes here?
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return *counter; // not at all the correct return value for the last two cases
}