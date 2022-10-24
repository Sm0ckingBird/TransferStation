#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/rwlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/limits.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/pstrace.h>
static DECLARE_WAIT_QUEUE_HEAD(waitqueue);
static struct buf_rec rb_array[PSTRACE_BUF_SIZE] ;
static struct track_list_rec tl_list[PSTRACE_BUF_SIZE];
static DEFINE_RWLOCK(RB_lock);
static DEFINE_RWLOCK(TL_lock);
static struct rb ring_buffer = {
 .array   = rb_array,
 .head    = 0,
 .tail    = 0,
 .count   = 0,
 .cs             = 0,
 .psget_list  = NULL
};
static struct track_list tracked_list = {
 .state     = _NOTRACE,
 .ps_list   = tl_list,
 .size    = 0
};
static int buffer_empty(void)
{
 return (ring_buffer.head == ring_buffer.tail);
}
static int buffer_full(void)
{
 return ((ring_buffer.head == 0 && ring_buffer.tail == PSTRACE_BUF_SIZE-1)
  ||(ring_buffer.head - ring_buffer.tail == 1));
}
static int pop_buffer_head(void)
{
 if (buffer_empty())
  return FAILED;
   if (ring_buffer.head == PSTRACE_BUF_SIZE)
  ring_buffer.head = 0;
 else
  ring_buffer.head++;
 return SUCCESS;
}
static int buffer_remove_element(pid_t pid)
{
 int rm = 0;
        int i = 0;
        while(i<PSTRACE_BUF_SIZE){
  if (pid == -1 || ring_buffer.array[i].trace_record.pid == pid) {
   ring_buffer.array[i].needsRemoved= 1;
   rm++;
  }
                i++;
 }
 return rm;
}
static int reformat_buffer(void)
{
 int h = ring_buffer.head;
 int nl = ring_buffer.head;
 int ol = ring_buffer.head;
 while (ol != ring_buffer.tail + 1) {
  if (ring_buffer.array[ol].needsRemoved)
   ol++;
  else
   ring_buffer.array[nl++] = ring_buffer.array[ol++];
  ol = ol >= PSTRACE_BUF_SIZE ? 0 : ol;
  nl = nl >= PSTRACE_BUF_SIZE ? 0 : nl;
 }
 ring_buffer.tail = nl;
 return ( ((nl - h) < 0) ? h - nl : nl - h );
}
static int write_to_buffer(struct buf_rec *new_record)
{
 if (buffer_full())
  pop_buffer_head();
 ring_buffer.array[ring_buffer.tail++] = *new_record;
   ring_buffer.count++;
        ring_buffer.array[ring_buffer.tail].pos = ring_buffer.count;
 if (ring_buffer.tail == PSTRACE_BUF_SIZE)
  ring_buffer.tail = 0;
   return SUCCESS;
}
static int contains_ps(pid_t pid)
{
        int i = 0;
        while (i<PSTRACE_BUF_SIZE){
                if (tracked_list.ps_list[i].in_use &&
                         tracked_list.ps_list[i].pid == pid)
                         return TRUE;
                i++;
        }
        return FALSE;
}
static int get_pstrace_info(struct task_struct *task, struct pstrace *rec)
{
        if (task == NULL)
                return FAILED;
        strncpy(rec->comm, task->comm, sizeof(rec->comm));
 if (task->exit_state == EXIT_DEAD
   || task->exit_state == EXIT_ZOMBIE)
  rec->state = task->exit_state;
 else if (task->state == TASK_RUNNING 
  || task->state == TASK_INTERRUPTIBLE
  || task->state == TASK_UNINTERRUPTIBLE 
  || task->state == TASK_STOPPED)
  rec->state = task->state;
 else
  return FAILED;
 rec->pid = task->pid;
        return SUCCESS;
}
static int add_to_tracklist(pid_t pid)
{
        int i = 0;
        if (tracked_list.size == PSTRACE_BUF_SIZE)
                return FAILED;
        while(i<PSTRACE_BUF_SIZE){
                if (!tracked_list.ps_list[i].in_use){
                        tracked_list.ps_list[i].pid = pid;
                        tracked_list.ps_list[i].in_use = 1;
                        tracked_list.size++;
                        return SUCCESS;
                }
                i++;
        }
        printk(KERN_ERR "Something went wrong in add_to_tracklist()");
        return FAILED;
}
static int remove_from_tracklist(pid_t pid)
{
        int i=0;
        while (i<PSTRACE_BUF_SIZE) {
                if (tracked_list.ps_list[i].in_use 
    && tracked_list.ps_list[i].pid == pid) {
                        tracked_list.ps_list[i].in_use= 0;
                        tracked_list.size--;
                        return SUCCESS;
                }
                i++;
        }
        return FAILED;
}
static int should_track_ps(struct task_struct *p)
{
 int res;
        if (p == NULL)
                return 0;
        read_lock(&TL_lock);
        res = ((tracked_list.state != NOTRACE) 
        && (tracked_list.state == TRACE 
        || contains_ps(p->pid)));
        read_unlock(&TL_lock);
        return res;
}   
static int __populate_psget_buffer(struct pstrace *buf, pid_t pid)
{
        int i = ring_buffer.head, j = 0;
        while (j < PSTRACE_BUF_SIZE) {
                if (pid != -1 && pid != ring_buffer.array[i].trace_record.pid) {
                        i++;
                        continue;
                }
                buf[j++] = ring_buffer.array[i++].trace_record;
                i = (i == PSTRACE_BUF_SIZE) ? 0 : i;
                if (i == ring_buffer.tail)
                        break;
        }
        return j;
}
static void populate_psget_buffer(void)
{
        struct psget_struct *mystruct;
        int count;
        list_for_each_entry(mystruct, ring_buffer.psget_list, list){
                if (mystruct->target_counter == ring_buffer.count) {
                        count  = __populate_psget_buffer(mystruct->ps_buf,mystruct->pid);
                        mystruct->filled = 1;
                        mystruct->recs_copied = count;
                }
                ring_buffer.cs = (mystruct->target_counter < ring_buffer.cs
                                  && mystruct->target_counter > ring_buffer.count) ? 
                                  mystruct->target_counter : ring_buffer.cs;
        }
}
void pstrace_add(struct task_struct *p)
{
 struct buf_rec rec;
        unsigned long flags;
 rec.needsRemoved = 0;
 if (get_pstrace_info(p, &(rec.trace_record)) == FAILED)
  return;
 if (!should_track_ps(p)) {
                return;
        }
 write_lock_irqsave(&RB_lock, flags);
 if (ring_buffer.cs){
  if (ring_buffer.count < ring_buffer.cs)
   write_to_buffer(&rec);
  else{
   ring_buffer.cs = LONG_MAX;
   populate_psget_buffer();
   write_to_buffer(&rec);
                        write_unlock_irqrestore(&RB_lock, flags);
   wake_up_all(&waitqueue);  
   return;
  }
 }
 else
  write_to_buffer(&rec);
        write_to_buffer(&rec);
        write_unlock_irqrestore(&RB_lock, flags);
 printk(KERN_INFO"New Rec, Pos %ld, pid [%d] comm[%s] state[%ld]", 
                ring_buffer.count, rec.trace_record.pid, 
                rec.trace_record.comm, rec.trace_record.state);
           }
static int do_pstrace_get(pid_t pid, struct pstrace *buf, long *kcounter)
{
 /*
 handle non-sleeping function first
 handle errors as well
 for the main sleeping function,
  grab a lock and read from the ring_buffer to
  check if there is a list already init, if not do init yourself
  add your buf, pid, and counter on to the list
  update ring_buffer cs and counter as well
  add yourself to waitqueue
  be prepared to handle if woken up by an interrupt
  when woken up, check to make sure your buffer has been filled with your request
  remove yourself from the list
  if you are the last on the list, destroy it 
 */
                 DEFINE_WAIT(wait);
 struct psget_struct mystruct;
        struct list_head *curr_list;
        int counter;
        int count;
        counter = *kcounter + PSTRACE_BUF_SIZE;
 if (*kcounter <= 0){
         write_lock(&RB_lock);
                count = __populate_psget_buffer(buf, pid);
                write_unlock(&RB_lock);
                *kcounter = 0;
                return count;
        }
                 mystruct.pid    = pid;
        mystruct.target_counter   = counter;
        mystruct.ps_buf   = buf;
        mystruct.filled                 = 0;
        mystruct.recs_copied            = 0;
        write_lock(&RB_lock);
        curr_list = ring_buffer.psget_list;
 if (curr_list){
  list_add(&mystruct.list, curr_list);
  if (counter < ring_buffer.cs)
   ring_buffer.cs = counter;
 }
 else {
  INIT_LIST_HEAD(&mystruct.list);
  ring_buffer.cs = counter;
  ring_buffer.psget_list = &mystruct.list;
 }
 write_unlock(&RB_lock);
 /* Prepare to sleep*/
 while (1) {
  prepare_to_wait(&waitqueue, &wait, TASK_INTERRUPTIBLE);
  read_lock(&RB_lock);
  if (mystruct.filled){
   read_unlock(&RB_lock);
   break;
  }
  read_unlock(&RB_lock);                
  if (signal_pending(current))
   break;
  schedule();
 } 
        finish_wait(&waitqueue, &wait);
 /*wake up: Check your buf count,
  Remove yourself from the list,
   if list is empty, reset cs,  */
 write_lock(&RB_lock);
 list_del(&mystruct.list);
 if (list_empty(ring_buffer.psget_list)){
  ring_buffer.psget_list = NULL;
  ring_buffer.cs = 0;
 }
 write_unlock(&RB_lock);
        *kcounter = mystruct.target_counter;
 return mystruct.recs_copied;
}
static int do_pstrace_enable(pid_t pid)
{
 write_lock(&TL_lock);
 if (tracked_list.state == TRACE)
  return SUCCESS;
   if (pid == -1)
  tracked_list.state = TRACE;
 else if (find_task_by_vpid(pid) == NULL)
  return -ESRCH;
 else
  add_to_tracklist(pid);
 write_unlock(&TL_lock);
 return SUCCESS;
}
static int do_pstrace_disable(pid_t pid)
{
 write_lock(&TL_lock);
 if (tracked_list.state == NOTRACE)
  return SUCCESS;
 if (pid == -1)
  tracked_list.state = NOTRACE;
 else if (find_task_by_vpid(pid) == NULL)
  return -ESRCH;
 else
  remove_from_tracklist(pid);
 write_unlock(&TL_lock);
 return SUCCESS;
}
static int do_pstrace_clear(pid_t pid)
{
        struct psget_struct *mystruct;
        int count;
        unsigned long flags;
        write_lock_irqsave(&RB_lock, flags);
        if (ring_buffer.psget_list != NULL){
                list_for_each_entry(mystruct, ring_buffer.psget_list,list){
                        if(pid == -1 || pid == mystruct->pid) {
                                mystruct->recs_copied = __populate_psget_buffer(mystruct->ps_buf,pid);
                                mystruct->filled = 1;
                        }
                }
                write_unlock_irqrestore(&RB_lock, flags);
                wake_up_all(&waitqueue);
        }
                 write_lock_irqsave(&RB_lock, flags);
        count = buffer_remove_element(pid);
        reformat_buffer();
        write_unlock_irqrestore(&RB_lock, flags);
        return count;
         }
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
        return do_pstrace_enable(pid);
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
        return do_pstrace_disable(pid);
}
SYSCALL_DEFINE3(pstrace_get,
  pid_t, pid,
  struct pstrace __user *, buf,
  long __user *, counter)
{
 struct pstrace *kbuf;
 long  kcounter;
 int             size;
        int             recs_copied;
          if (buf == NULL || counter == NULL)
  return -EINVAL;
        if (copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
        size = sizeof(struct pstrace) * PSTRACE_BUF_SIZE;
        kbuf = kmalloc(size, GFP_KERNEL);
        if (kbuf == NULL)
                return -ENOMEM;
        recs_copied = do_pstrace_get(pid, kbuf, &kcounter);
        size =  recs_copied*sizeof(struct pstrace);
                 if (copy_to_user(buf, kbuf, size))
  return -EFAULT;
 if (copy_to_user(counter, &kcounter, sizeof(long)))
  return -EFAULT;
 kfree(kbuf);
        return recs_copied;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
                 do_pstrace_clear(pid);
        return 0;
}