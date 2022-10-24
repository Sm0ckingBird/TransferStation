#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/pstrace.h>
#include <linux/sched.h>
#define PSTRACE_BUF_SIZE 500
#define PSTRACE_WAITQ_INIT_SIZE 25
struct buf_entry {
 char comm[16];
 long state;
 pid_t pid;
 pid_t tid;
 long entry_number;
};
static struct buf_entry *ring_buf;
static int buf_windex;
static atomic_t buf_counter;
static int buf_size;
static int pstrace_enabled;
static int pstrace_all;
static pid_t pstrace_pid;
EXPORT_SYMBOL(pstrace_enabled);
EXPORT_SYMBOL(pstrace_all);
EXPORT_SYMBOL(pstrace_pid);
static DEFINE_SPINLOCK(buf_write_lock);
static DEFINE_SPINLOCK(enable_disable_lock);
static DEFINE_SPINLOCK(waitqarr_lock);
struct get_wait_entry {
 long reqbufcount;
 wait_queue_head_t *wq;
 int woken;
};
static struct get_wait_entry *getwaitq_arr;
static int getwaitq_arr_index;
static int getwaitq_arr_size;
void __init pstracebuffer_init(void)
{
 size_t element_size = sizeof(struct buf_entry);
 ring_buf = kmalloc_array(PSTRACE_BUF_SIZE, element_size, GFP_KERNEL);//TODO: MAKE STATIC + change clear
 getwaitq_arr = NULL;
 getwaitq_arr_index = 0;
 getwaitq_arr_size = 0;
 buf_windex = 0; 
 pstrace_enabled = 0;
 pstrace_all = 0;
 pstrace_pid = -1;
 atomic_set(&buf_counter,0);
 buf_size = 0;
 BUG_ON(!ring_buf);
}
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long flags_lockone;
 unsigned long flags_locktwo;
 int tmp;
 int current_count;
 spin_lock_irqsave(&buf_write_lock,flags_lockone);
 atomic_inc(&buf_counter);
 if (p->comm == NULL) {
  ring_buf[buf_windex].comm[0] = '\0';
 } else {
  /* get_task_comm(ring_buf[buf_windex].comm,p); */
  strncpy(ring_buf[buf_windex].comm, p->comm, 16);
 }
 ring_buf[buf_windex].state = state;
 /*
 * ring_buf[buf_windex].tid = (p->thread_pid == NULL) ? 0 : task_pid_vnr(p);
 * ring_buf[buf_windex].pid = task_tgid_vnr(p);
 */
 ring_buf[buf_windex].tid = (p->thread_pid == NULL) ? 0  : p->tgid;
 ring_buf[buf_windex].pid = p->pid;
 ring_buf[buf_windex].entry_number = atomic_read(&buf_counter);
 buf_windex = (buf_windex + 1) % PSTRACE_BUF_SIZE;
 if (buf_size < PSTRACE_BUF_SIZE)
  buf_size++; 
 spin_unlock_irqrestore(&buf_write_lock, flags_lockone);
   spin_lock_irqsave(&waitqarr_lock, flags_locktwo);
 current_count = atomic_read(&buf_counter);
 if (getwaitq_arr != NULL) {
  for (tmp = 0; tmp < getwaitq_arr_index; tmp++) {
   if (getwaitq_arr[tmp].reqbufcount <= current_count) {
    if(getwaitq_arr[tmp].woken == 0) {
     wake_up(getwaitq_arr[tmp].wq);
     getwaitq_arr[tmp].woken = 1;
    }
   }
  }
 }
 spin_unlock_irqrestore(&waitqarr_lock, flags_locktwo);
}
EXPORT_SYMBOL(pstrace_add);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 int err = 0;
 unsigned long flags;
 spin_lock_irqsave(&enable_disable_lock, flags);
 if (pid == -1) {
  if (pstrace_all == 1) {
   err = -EINVAL;
  } else {
   pstrace_all = 1;
   pstrace_enabled = 1;
   pstrace_pid = -1;
  }
 } else if (pid >= 0) {
  if (pstrace_pid == pid) {
   err = -EINVAL;
  } else if (find_task_by_vpid(pid) == NULL){
   err = -ESRCH;
  } else{
   pstrace_all = 0;
   pstrace_enabled = 1;
   pstrace_pid = pid;
  }
 } else {
  err = -EINVAL;
 }
 spin_unlock_irqrestore(&enable_disable_lock, flags);
 return err;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flags;
 int err = 0;
 spin_lock_irqsave(&enable_disable_lock, flags);
 if (pstrace_enabled == 1)
  pstrace_enabled = 0;
 else
  err = -EINVAL; 
 spin_unlock_irqrestore(&enable_disable_lock, flags);
 return err;
}
struct pstrace *copy_buffer_in_order(long start, long *last, int *total)
{
 int total_to_copy = 0;
 int tmp = 0;
 int found_start;
 struct pstrace *out = NULL;
 int i;
 int min_index = 0;
 int min_val = ring_buf[0].entry_number;
 int loop_count = 0;
 if (buf_size != PSTRACE_BUF_SIZE) {
  while (ring_buf[tmp].entry_number != start) {
   tmp++;
   if (tmp == buf_size)
    goto none;
  }
  found_start = tmp;
  while (tmp < buf_size && ring_buf[tmp].entry_number <= start + PSTRACE_BUF_SIZE) {
   total_to_copy++;
   tmp++;
  }
  out = kmalloc_array(total_to_copy, sizeof (struct pstrace), GFP_KERNEL);
  for (i = 0; i < total_to_copy; i++) {
   out[i].pid = ring_buf[found_start].pid;
   out[i].tid = ring_buf[found_start].tid;
   out[i].state = ring_buf[found_start].state;
   strcpy(out[i].comm, ring_buf[found_start].comm);
   if (i == total_to_copy-1) {
    *last = ring_buf[found_start].entry_number;
   }
   found_start++;
  }
  *total = total_to_copy;
  goto ret;
 } else {
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
   if (ring_buf[i].entry_number < min_val) {
    min_index = i;
    min_val = ring_buf[i].entry_number;
   }
  }
  tmp = min_index;
  loop_count = 0;
  while (loop_count < PSTRACE_BUF_SIZE) {
   if (ring_buf[tmp].entry_number == start) {
    break;
   }
   loop_count++;
   tmp = (tmp + 1) % PSTRACE_BUF_SIZE;
  }
  if (loop_count == PSTRACE_BUF_SIZE)
   goto none;
  found_start = tmp;
  while (ring_buf[tmp].entry_number <= start + PSTRACE_BUF_SIZE) {
   total_to_copy++;
   tmp = (tmp + 1) % PSTRACE_BUF_SIZE;
  }
  out = kmalloc_array(total_to_copy, sizeof (struct pstrace), GFP_KERNEL);
  for (i = 0; i < total_to_copy; i++) {
   out[i].pid = ring_buf[found_start].pid;
   out[i].tid = ring_buf[found_start].tid;
   out[i].state = ring_buf[found_start].state;
   strcpy(out[i].comm, ring_buf[found_start].comm);
   if (i == total_to_copy-1) {
    *last = ring_buf[found_start].entry_number;
   }
   found_start = (found_start + 1) % PSTRACE_BUF_SIZE;
  }
  *total = total_to_copy;
  goto ret;
 }
ret:
 return out;
none:
 *total = 0;
 *last = atomic_read(&buf_counter);
 return out;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user*, buf, long __user*, counter)
{
 int num_copied = 0;
 long asked_counter;
 long last_entry_number_copied;
 unsigned long flags;
 unsigned long flags_waitqlock;
 unsigned long flags_waitqlocktwo;
 struct pstrace *kernel_buf;
 struct get_wait_entry new_entry;
 struct get_wait_entry cpy;
 wait_queue_head_t new_wait_q;
 DEFINE_WAIT(new_wait_entry);
 int added = 0;
 int required_count;
 struct get_wait_entry* old;
 int old_wait_index;
 int tmp; 
 if (buf == NULL || counter == NULL)
   return -EINVAL;
 if (copy_from_user(&asked_counter, counter, sizeof(long)))
   return -EFAULT;
  if (asked_counter < 0)
   return -EINVAL;
 // TODO: Dont let anything enter the code below if we are waking up
 // all threads
 required_count = asked_counter + PSTRACE_BUF_SIZE;
 if (asked_counter == 0) {
  if (buf_size == 0) {
   last_entry_number_copied = atomic_read(&buf_counter);
   goto copycounter;
  }
  goto readwithlock;
 } else if (atomic_read(&buf_counter) >= required_count) {
  goto readwithlock;
 } else {
  spin_lock_irqsave(&waitqarr_lock, flags_waitqlock);
  if (getwaitq_arr == NULL){
   getwaitq_arr = kmalloc_array(PSTRACE_WAITQ_INIT_SIZE,
     sizeof (struct get_wait_entry),
     GFP_KERNEL);
   getwaitq_arr_index = 0;
   getwaitq_arr_size = PSTRACE_WAITQ_INIT_SIZE;
  }
  if (getwaitq_arr_index == getwaitq_arr_size) {
   old = getwaitq_arr;
   old_wait_index = getwaitq_arr_index;
   getwaitq_arr = kmalloc_array(getwaitq_arr_size*2,
     sizeof (struct get_wait_entry),
     GFP_KERNEL);
   getwaitq_arr_index = 0;
   for (tmp = 0; tmp < old_wait_index; tmp++) {
    if(old[tmp].woken == 0) {
     cpy = (struct get_wait_entry){
     .reqbufcount = old[tmp].reqbufcount,
      .wq = (old[tmp].wq), .woken = 0};
     getwaitq_arr[getwaitq_arr_index] = cpy;
     getwaitq_arr_index++;
    }
   }
   kfree(old);
   getwaitq_arr_size = getwaitq_arr_size * 2;
  }
  spin_unlock_irqrestore(&waitqarr_lock, flags_waitqlock);
     init_waitqueue_head(&new_wait_q);
  do {
       prepare_to_wait(&new_wait_q, &new_wait_entry,TASK_INTERRUPTIBLE);
   spin_lock_irqsave(&waitqarr_lock, flags_waitqlocktwo);
   if (added == 0) {
    new_entry = (struct get_wait_entry){
     .reqbufcount = required_count,
      .wq = &new_wait_q, .woken = 0};
    getwaitq_arr[getwaitq_arr_index] = new_entry;
    added = 1;
    getwaitq_arr_index++;
   }
   spin_unlock_irqrestore(&waitqarr_lock, flags_waitqlocktwo);
   schedule();
   //TODO: Check signal
  } while (atomic_read(&buf_counter) < required_count);
 }
readwithlock:
   spin_lock_irqsave(&buf_write_lock,flags);
 kernel_buf = copy_buffer_in_order(asked_counter+1,
   &last_entry_number_copied, &num_copied);
 spin_unlock_irqrestore(&buf_write_lock, flags); 
 if (copy_to_user(buf, kernel_buf, 
    num_copied * sizeof(struct pstrace))) {
   num_copied = -EFAULT;
   goto ret;
  }
copycounter:
  if (copy_to_user(counter, &last_entry_number_copied, sizeof(long))) {
   num_copied = -EFAULT;
   goto ret;
  }
ret:
 kfree(kernel_buf);//TODO: Check if you should free waitqarr by looping
 return num_copied;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 int err = 0;
 size_t element_size = sizeof(struct buf_entry);
 unsigned long flags_buf;
 unsigned long flags_wake;
 int tmp;
   spin_lock_irqsave(&waitqarr_lock, flags_wake);
 //TODO: add global boolean
 if (getwaitq_arr != NULL) {
  for (tmp = 0; tmp < getwaitq_arr_index; tmp++) {
   if(getwaitq_arr[tmp].woken == 0) {
    wake_up(getwaitq_arr[tmp].wq);
    getwaitq_arr[tmp].woken = 1;
   }
  }
 }
 spin_unlock_irqrestore(&waitqarr_lock, flags_wake);
 spin_lock_irqsave(&buf_write_lock, flags_buf);
 if (buf_size == 0)
  goto unlock;
 kfree(ring_buf);
 ring_buf = kmalloc_array(PSTRACE_BUF_SIZE, element_size, GFP_KERNEL);
 buf_windex = 0;
 buf_size = 0;
unlock:
 spin_unlock_irqrestore(&buf_write_lock, flags_buf);
 return err;
}