#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/types.h>
#include <asm-generic/atomic-instrumented.h>
#include <asm-generic/atomic-long.h>
#include <linux/rwlock.h>
#include <linux/rwlock_types.h>
atomic_long_t counter_pstrace = ATOMIC_LONG_INIT(0);
pid_t traced_pid;
struct ringBufferNode *head;
struct ringBufferNode *current_node;
DEFINE_RWLOCK(mutex_traced_pid);
DEFINE_RWLOCK(mutex_ringBuffer);
void pstrace_add(struct task_struct *p, long state){
 pid_t current_pid = (*p).pid;
 if (current_pid < 0)
  return;
 read_lock(&mutex_traced_pid);
 if (traced_pid != current_pid && traced_pid != -1)
  return; 
 read_unlock(&mutex_traced_pid);
 write_lock(&mutex_ringBuffer);
 if (!head){
  struct ringBufferNode *newNode = kmalloc(sizeof(struct ringBufferNode), GFP_KERNEL);
  strncpy(newNode -> field -> comm, p -> comm, sizeof(p -> comm));
  newNode -> field -> state = state;
  newNode -> field -> pid = current_pid;
  newNode -> field -> tid = current_pid;
  newNode -> count = (long)1;
  if (current_node){
   printk(KERN_ERR "Iamgood current node");
  }
  current_node = newNode;
  head = newNode;
 } else if (current_node -> count < PSTRACE_BUF_SIZE){
  struct ringBufferNode *newNode = kmalloc(sizeof(struct ringBufferNode), GFP_KERNEL);
  strncpy(newNode -> field -> comm, p -> comm, sizeof(p -> comm));
  newNode -> field -> state = state;
  newNode -> field -> pid = current_pid;
  newNode -> field -> tid = current_pid;
  newNode -> count = current_node -> count + 1;
  current_node -> next = newNode;
  current_node = newNode;
 }
 else {
  struct ringBufferNode *newNode = current_node -> next;
  strncpy(newNode -> field -> comm, p -> comm, sizeof(p -> comm));
  newNode -> field -> state = state;
  newNode -> field -> pid = current_pid;
  newNode -> field -> tid = current_pid;
  newNode -> count = current_node -> count + 1;
  current_node = current_node -> next;
 }
 write_unlock(&mutex_ringBuffer);
 atomic_long_inc(&counter_pstrace);
}
static inline long copy_ringBuf(struct pstrace *kbuf, long counter){
   struct ringBufferNode *p1;
 long copied_size;
 read_lock(&mutex_ringBuffer);
 if (counter < 0){
  copied_size = atomic_long_read(&counter_pstrace);
 } else{
  copied_size = PSTRACE_BUF_SIZE;
 }
 p1 = head;
 while (p1 -> count != counter + 1){
  p1 = p1 -> next;
 }
 while (p1 -> count < copied_size + 1){
  strncpy(kbuf -> comm, p1 -> field -> comm, sizeof(p1 -> field -> comm));
  kbuf -> state = p1 -> field -> state;
  kbuf -> pid = p1 -> field -> pid;
  kbuf -> tid = p1 -> field -> tid;
  kbuf += 1;
 }
 read_unlock(&mutex_ringBuffer);
 return copied_size;
}
static inline long remove_ringBuf(){
 struct ringBufferNode *next;
 while ()
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid){
 preempt_disable();
 write_lock(&mutex_traced_pid);
 traced_pid = pid;
 write_unlock(&mutex_traced_pid);
 preempt_enable();
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 preempt_disable();
 write_lock(&mutex_traced_pid);
 traced_pid = -2;
 write_unlock(&mutex_traced_pid);
 preempt_enable();
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 struct pstrace *kbuf;
 long kcounter;
 long size;
 if (!buf || !counter){
  return -EINVAL;
 }
 if (get_user(kcounter, counter))
  return -EFAULT;
 if (kcounter > 0){
 }
 read_lock(&mutex_ringBuffer);   
 size = copy_ringBuf(kbuf, kcounter);
 read_unlock(&mutex_ringBuffer);
 if (put_user(size, counter) || copy_to_user(buf, kbuf, size)){
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return 0;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 write_lock(&mutex_ringBuffer);
 write_unlock(&mutex_ringBuffer);
 return 0;
}  