#include <linux/types.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/list.h>
#define PSTRACE_BUF_SIZE 500
struct pstrace_meta{
 struct pstrace ps;
};
atomic_t pst_enabled = ATOMIC_INIT(0);
atomic_t pst_pid = ATOMIC_INIT(-1);
atomic_t should_wake = ATOMIC_INIT(0);
unsigned long flags;
long last_record;
static DEFINE_SPINLOCK(ring_buf_spinlock);
static DEFINE_SPINLOCK(wl_spinlock);
static DEFINE_SPINLOCK(tmp_spinlock);
struct pstrace_meta buffer[PSTRACE_BUF_SIZE];
struct pstrace_meta *start = buffer;
struct pstrace_meta *end = buffer;
long len = 0;  /*keeps track of things in buffer*/
atomic64_t buffer_counter = ATOMIC64_INIT(0);
struct pstrace_meta tmp[PSTRACE_BUF_SIZE];
//TODO: decide where to properly init
static LIST_HEAD(wait_list);
struct getreq{
 wait_queue_head_t *head;
 long req_len;
 struct list_head list;
 struct task_struct *cur;
 atomic_t woken;
 atomic_t cleared; 
};
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if(pid!=-1 && !(find_task_by_vpid(pid)))
  return -EINVAL;
 atomic_set(&pst_enabled, 1);
 atomic_set(&pst_pid, pid);
 len = 0;
 start = buffer;
 end = buffer;
 return 0;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 /* Add locks */
 struct getreq *ptr;
 struct getreq *next;
 list_for_each_entry_safe(ptr, next, &wait_list, list) {
  if(!atomic_read(&ptr->woken))
  {
   atomic_set(&ptr->woken, 1);
   atomic_set(&ptr->cleared, 1);
   spin_lock(&wl_spinlock);
   list_del(&ptr->list);
   spin_unlock(&wl_spinlock);
   wake_up(ptr->head);
  }
 }
 spin_lock_irqsave(&ring_buf_spinlock, flags);
 start = buffer;
 end = buffer;
 len = 0;
 spin_unlock_irqrestore(&ring_buf_spinlock, flags);
   return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 atomic_set(&pst_enabled, 0);
 return 0;
}
struct pstrace task_to_pstrace(struct task_struct *p, 
  long state){
 struct pstrace curr;
 memcpy(curr.comm, p->comm, TASK_COMM_LEN);
 curr.state = state;
 curr.pid = p->tgid;
 curr.tid = p->pid;
 return curr;
}
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace_meta to_add;
 struct pstrace curr_ps;
   spin_lock(&ring_buf_spinlock);
 curr_ps = task_to_pstrace(p, state);
 memcpy(&(to_add.ps), &curr_ps, sizeof(struct pstrace));
 /* actually add to list */
 //we've reached the end of the buffer
 //wrap around
 if (end == buffer + PSTRACE_BUF_SIZE)
  end = buffer;
 // we are completely full!
 if (end == buffer && start == buffer + PSTRACE_BUF_SIZE && len == PSTRACE_BUF_SIZE){
  start = buffer;
  start++;
 } else if (end == start && len == PSTRACE_BUF_SIZE)
  start++;
 *(end++) = to_add; 
 if (len != PSTRACE_BUF_SIZE)
  len++;
   spin_unlock(&ring_buf_spinlock);
 atomic64_inc(&buffer_counter);
 wake_up_get();
}
void wake_up_get(void)
{
 struct getreq *ptr;
 struct getreq *next;
  list_for_each_entry_safe(ptr, next, &wait_list, list) {
   if(!(atomic_read(&ptr->woken)) && atomic64_read(&buffer_counter)>=ptr->req_len + PSTRACE_BUF_SIZE) {
    spin_lock(&wl_spinlock);
    list_del(&ptr->list);
    spin_unlock(&wl_spinlock);
    atomic_set(&ptr->woken, 1);
    wake_up(ptr->head);
   }
  }
}
void pstrace_add_no_wakeup(struct task_struct *p, long state)
{
 struct pstrace_meta to_add;
 struct pstrace curr_ps;
 spin_lock(&ring_buf_spinlock);
 curr_ps = task_to_pstrace(p, state);
 /* TODO: If new metadata added, modify here */
 memcpy(&(to_add.ps), &curr_ps, sizeof(struct pstrace));
 /* actually add to list */
 if (end == buffer + PSTRACE_BUF_SIZE)
  end = buffer;
 if (end == buffer && start == buffer + PSTRACE_BUF_SIZE && len == PSTRACE_BUF_SIZE){
  start = buffer;
  start++;
 } else if (end == start && len == PSTRACE_BUF_SIZE)
  start++;
 *(end++) = to_add; 
 if (len != PSTRACE_BUF_SIZE)
  len++;
   atomic64_inc(&buffer_counter);
 spin_unlock(&ring_buf_spinlock);
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, 
  long __user *, counter)
{
 long user_counter;
 struct pstrace to_copy;
 int i;
 struct pstrace_meta *loop_start;
 int return_count;
 atomic_t not_woken = ATOMIC_INIT(0);
 atomic_t not_cleared = ATOMIC_INIT(0);
 struct getreq cur_req;
 DEFINE_WAIT(w);    
 DECLARE_WAIT_QUEUE_HEAD(wqh);;
   if(copy_from_user(&user_counter, counter, sizeof(long)))
  return -EFAULT;
 if(user_counter <0){
  return -1;
 }
 else if(atomic64_read(&buffer_counter)-PSTRACE_BUF_SIZE > user_counter &&
   atomic64_read(&buffer_counter) < user_counter + 2*PSTRACE_BUF_SIZE){
  return_count = user_counter - atomic64_read(&buffer_counter) + 2*PSTRACE_BUF_SIZE;
  goto returndata;
 }
 else if(atomic64_read(&buffer_counter) >= user_counter + 2*PSTRACE_BUF_SIZE){
  last_record = atomic64_read(&buffer_counter);
  if(copy_to_user(counter, &last_record, sizeof(long)))
   return -EFAULT;
  return 0;
 }
 while(atomic64_read(&buffer_counter) < user_counter+PSTRACE_BUF_SIZE ||
   len != PSTRACE_BUF_SIZE) {
  prepare_to_wait(&wqh, &w, TASK_INTERRUPTIBLE);
  cur_req.head = &wqh;
  cur_req.req_len = user_counter;
  INIT_LIST_HEAD(&cur_req.list);
  cur_req.cur = current;
  cur_req.woken = not_woken;
  cur_req.cleared = not_cleared;
  spin_lock_irqsave(&wl_spinlock, flags);
  list_add_tail(&cur_req.list, &wait_list);
  spin_unlock_irqrestore(&wl_spinlock, flags);
  schedule();
  if(atomic_read(&cur_req.cleared))
  {
   break;
  }
  if(!(atomic_read(&cur_req.woken)))
  {
   atomic_set(&cur_req.woken, 1);
   finish_wait(&wqh, &w);
   return 0;
  }
 }
 finish_wait(&wqh, &w);
 return_count = len<PSTRACE_BUF_SIZE ? len:PSTRACE_BUF_SIZE;
returndata:
 loop_start = start;
 spin_lock(&tmp_spinlock);
 spin_lock_irqsave(&ring_buf_spinlock, flags);
 for (i = 0; i < return_count; i++) 
 {
  if (loop_start == buffer + PSTRACE_BUF_SIZE)
   loop_start = buffer;
  to_copy = loop_start++ -> ps;
  memcpy(&tmp[i], &to_copy, sizeof(struct pstrace));
 }
 spin_unlock_irqrestore(&ring_buf_spinlock, flags);
 spin_unlock(&tmp_spinlock);
 if(copy_to_user(buf, tmp, return_count*sizeof(struct pstrace))){
   return -EFAULT;
 }
   last_record = atomic64_read(&buffer_counter) - PSTRACE_BUF_SIZE + return_count;
 if(copy_to_user(counter, &last_record, sizeof(long)))
  return -EFAULT;
 return return_count;
}