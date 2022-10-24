#include <linux/types.h>
#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/list.h>
/* The maximum size of the ring buffer */
#define PSTRACE_BUF_SIZE 500
/* Count the number of records in ring buffer */
int pstrace_counter;
/* Data structure used to store pstrace structure with counter*/
struct pstrace_record {
 struct pstrace entry;
 int num;
};
/* Ring buffer for tracing and recording state changes for processes */
struct pstrace_record ringbuf[PSTRACE_BUF_SIZE];
/*
 * define global bitmap that stores all of the traced pids, see the
 * bitmap API below for more details
 */
char pstrace_bitmap[1+PID_MAX_LIMIT/8];
/* have a flag for whether or not the bitmap values are all inited to 0 */
int pstrace_bitmap_init;
/* define a lock to be set whenever reading or writing from the bitmap */
DEFINE_SPINLOCK(pstrace_bitmap_lock);
unsigned long flag_bitmap;
/* define a lock to be set whenever reading or writing from the ringbuf */
DEFINE_SPINLOCK(pstrace_ringbuf_lock);
unsigned long flag_ringbuf;
/*
 * define a linked list head that will be used to store all of the sleeping
 * pstrace_get() calls
 */
LIST_HEAD(pstrace_sleep_list);
/* this is an element of the linked list that will store sleeping syscalls */
struct pstrace_sleep_elem {
 pid_t pid;
 struct pstrace *dest;
 long counter;
 struct task_struct *tsk;
 int *num_copied;
 struct list_head list;
};
/*======== define API for bitmap ========*/
/* turn the x'th bit of the bitmap to 1, return -1 on failure */
int pstrace_add_to_map(int x)
{
 int array_index;
 array_index = x / 8;
 if (array_index > sizeof(pstrace_bitmap))
  return -1;
 spin_lock_irqsave(&pstrace_bitmap_lock, flag_bitmap);
 pstrace_bitmap[array_index] = pstrace_bitmap[array_index]
  | (1<<(7-x%8));
 spin_unlock_irqrestore(&pstrace_bitmap_lock, flag_bitmap);
 return 0;
}
/* turn the x'th bit of the bitmap to 0, return -1 on failure */
int pstrace_remove_from_map(int x)
{
 int array_index;
 array_index = x / 8;
 if (array_index > sizeof(pstrace_bitmap))
  return -1;
 spin_lock_irqsave(&pstrace_bitmap_lock, flag_bitmap);
 pstrace_bitmap[array_index] = pstrace_bitmap[array_index]
  & ~(1<<(7-x%8));
 spin_unlock_irqrestore(&pstrace_bitmap_lock, flag_bitmap);
 return 0;
}
/* if x'th bit of map is 1 return 1, if 0 return 0, return -1 on failure */
int pstrace_check_map(int x)
{
 int array_index;
 char check;
 array_index = x / 8;
 if (array_index > sizeof(pstrace_bitmap))
  return 0;
 spin_lock_irqsave(&pstrace_bitmap_lock, flag_bitmap);
 check = pstrace_bitmap[array_index] & (1<<(7-x%8));
 spin_unlock_irqrestore(&pstrace_bitmap_lock, flag_bitmap);
 if (check > 0)
  return 1;
 else
  return 0;
}
/* clear the bitmap, set all the bits to 0 */
void pstrace_clear_map(void)
{
 int i;
 spin_lock_irqsave(&pstrace_bitmap_lock, flag_bitmap);
 for (i = 0; i < sizeof(pstrace_bitmap); i++)
  pstrace_bitmap[i] = (char) 0;
 spin_unlock_irqrestore(&pstrace_bitmap_lock, flag_bitmap);
}
/* enable all processes, set all the bits to 1 */
void pstrace_enable_all_map(void)
{
 int i;
 spin_lock_irqsave(&pstrace_bitmap_lock, flag_bitmap);
 for (i = 0; i < sizeof(pstrace_bitmap); i++)
  pstrace_bitmap[i] = (char) 1;
 spin_unlock_irqrestore(&pstrace_bitmap_lock, flag_bitmap);
}
/*======= end bitmap API =======*/
/*
 * looks at the current ring buf and copies all pstrace struct with
 * pid = @pid to @buf. Note that buf is expected to be of size PSTRACE_BUF_SIZE.
 * It is also assumed that when this function is called that it is inside a
 * ringbuf lock
 */
int pstrace_buf_copy(struct pstrace *kbuf, pid_t pid, int amt)
{
 int i, index, kbuf_index;
 kbuf_index = 0;
 for (i = 0; i < amt; i++) {
  index = (pstrace_counter+1+i)%PSTRACE_BUF_SIZE;
  if (pid == -1)
   kbuf[kbuf_index++] = ringbuf[index].entry;
  else if (ringbuf[index].entry.pid == pid)
   kbuf[kbuf_index++] = ringbuf[index].entry;
 }
 return kbuf_index;
}
int pstrace_add_sleep(struct task_struct *t, pid_t pid, long count,
  struct pstrace *dest, int *num_copied)
{
 struct pstrace_sleep_elem *elem;
 elem = kmalloc(sizeof(struct pstrace_sleep_elem), GFP_KERNEL);
 if (elem == NULL)
  return -1;
 elem->pid = pid;
 elem->tsk = t;
 elem->counter = count;
 elem->dest = dest;
 elem->num_copied = num_copied;
 INIT_LIST_HEAD(&elem->list);
 list_add(&elem->list, &pstrace_sleep_list);
 return 0;
}
/*
 * use this function to increment pstrace_counter, that way, when an increment
 * happens, we can check if it is time to wake up some sleepig processes.
 * it is assumed that this function is called inside a ringbuf lock
 */
void pstrace_counter_inc(void)
{
 /*
  * go through the sleeping processes and check if need to wake
  * anything up
  */
 struct pstrace_sleep_elem *elem;
 struct pstrace_sleep_elem *next;
 pstrace_counter++;
 list_for_each_entry_safe(elem, next, &pstrace_sleep_list, list) {
  if (pstrace_counter == elem->counter+PSTRACE_BUF_SIZE) {
   *(elem->num_copied) = pstrace_buf_copy(elem->dest,
     elem->pid, PSTRACE_BUF_SIZE);
   wake_up_process(elem->tsk);
   list_del(&elem->list);
   kfree(elem);
  }
 }
}
void pstrace_add(struct task_struct *p)
{
 struct pstrace cur_pstrace;
 struct pstrace_record *cur_record;
 int index;
 /* construct current pstrace struct */
 get_task_comm((&cur_pstrace)->comm, p);
 (&cur_pstrace)->pid = task_pid_vnr(p);
 (&cur_pstrace)->state = p->state;
 /* deal with __TASK_STOPPED */
 if (p->state == TASK_STOPPED)
  (&cur_pstrace)->state = __TASK_STOPPED;
 /* deal with EXIT_ZOMBIE and EXIT_DEAD */
 if ((p->exit_state == EXIT_ZOMBIE)
   || (p->exit_state == EXIT_DEAD))
  (&cur_pstrace)->state = p->exit_state;
 /* lock ringbuf */
 spin_lock_irqsave(&pstrace_ringbuf_lock, flag_ringbuf);
 /* construct current record */
 /* get the current index in ringbuf */
 index = pstrace_counter % PSTRACE_BUF_SIZE;
 cur_record = &ringbuf[index];
 cur_record->entry = cur_pstrace;  /* not sure about pointer issue */
 cur_record->num = pstrace_counter;
 /* increment counter after adding a function*/
 pstrace_counter_inc();
 /* unlock ringbuf */
 spin_unlock_irqrestore(&pstrace_ringbuf_lock, flag_ringbuf);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 int result;
 if (pid == -1) {
  pstrace_enable_all_map();
  return 0;
 }
 result = pstrace_add_to_map(pid);
 if (result == -1)
  return -EINVAL;
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 if (pid == -1)
  pstrace_clear_map();
 if (pstrace_remove_from_map(pid) == -1)
  return -EINVAL;
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
 long __user *, counter)
{
 long kcounter;
 struct pstrace *kbuf;
 int num_copied;
 /* copy the user pointer into the kernel */
 if (copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
 spin_lock_irqsave(&pstrace_ringbuf_lock, flag_ringbuf);
 if (kcounter < 0)
  return -EINVAL;
 if (kcounter < pstrace_counter-2*PSTRACE_BUF_SIZE) {
  /* case where records no longer in ringbuf, return 0 */
  spin_unlock_irqrestore(&pstrace_ringbuf_lock, flag_ringbuf);
  return 0;
 } else if (kcounter > pstrace_counter-PSTRACE_BUF_SIZE) {
  /* case where process needs to sleep */
  kbuf = kmalloc(PSTRACE_BUF_SIZE*sizeof(struct pstrace),
    GFP_KERNEL);
  if (kbuf == NULL)
   return -1;
  set_current_state(TASK_INTERRUPTIBLE);
  if (pstrace_add_sleep(current, pid, kcounter,
     kbuf, &num_copied) == -1)
   return -1;
  spin_unlock_irqrestore(&pstrace_ringbuf_lock, flag_ringbuf);
  schedule();
  if (copy_to_user(buf, kbuf,
    num_copied*sizeof(struct pstrace))) {
   return -EFAULT;
  }
  kfree(kbuf);
  return num_copied;
 }
 /* case where can return without sleeping */
 kbuf = kmalloc(PSTRACE_BUF_SIZE*sizeof(struct pstrace),
   GFP_KERNEL);
 num_copied = pstrace_buf_copy(kbuf, pid,
   kcounter+2*PSTRACE_BUF_SIZE-pstrace_counter-1);
 spin_unlock_irqrestore(&pstrace_ringbuf_lock, flag_ringbuf);
 if (copy_to_user(buf, kbuf,
   num_copied*sizeof(struct pstrace))) {
  return -EFAULT;
 }
 kfree(kbuf);
 return num_copied;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 struct pstrace_sleep_elem *elem;
 struct pstrace_sleep_elem *next;
 /* to start 'clear' the ringbuf, just reset the counter to 0 */
 spin_lock_irqsave(&pstrace_ringbuf_lock, flag_ringbuf);
 pstrace_counter = 0;
 spin_unlock_irqrestore(&pstrace_ringbuf_lock, flag_ringbuf);
 /* wake up sleeping processes */
 list_for_each_entry_safe(elem, next, &pstrace_sleep_list, list) {
  if (pid == -1) {
   list_del(&elem->list);
   wake_up_process(elem->tsk);
   kfree(elem);
  } else if (elem->pid == pid) {
   list_del(&elem->list);
   wake_up_process(elem->tsk);
   kfree(elem);
  }
 }
 return 0;
}