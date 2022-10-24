#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/pstrace.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/completion.h>
static DEFINE_SPINLOCK(pstrace_lock);
static unsigned long pstrace_irq_state;
static DECLARE_WAIT_QUEUE_HEAD(pstrace_wait_q);
/* pstrace_lock should be held before accessing any of the following global
 * variables.
 */
static size_t g_pstrace_counter;
static size_t g_pstrace_counter_min;
static pid_t g_pstrace_traced_pid = -1; /* -1: trace all pids */
static struct pstrace g_pstrace_ringbuffer[PSTRACE_BUF_SIZE];
static int g_pstrace_enabled; /* 1: enabled, 0: disabled */
static LIST_HEAD(g_pstrace_queue_list_head);
static int entry_is_cleared(int index, const struct pstrace *buff);
static void prepare_to_wakeup_all_sleepers(void);
static int prepare_to_wakeup_at_index(size_t index);
static int pstrace_get_copy_to_user(long counter_start,
 long counter_start_index, long counter_stop_index,
 struct pstrace *local_ringbuffer, struct pstrace __user *buf,
 long local_counter, long __user *counter, size_t local_counter_min);
static int pstrace_get_blocking(long counter_start,
 struct pstrace *local_ringbuffer,
 long *counter_stop_index, long *local_counter, size_t *local_min);
static void record_process_state_change(struct pstrace *dst,
  struct task_struct *p, long state);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if (pid < -1)
  return -EINVAL;
 spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
 g_pstrace_enabled = 1;
 g_pstrace_traced_pid = pid;
 spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
 g_pstrace_enabled = 0;
 spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 return 0;
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
 int errno = -EFAULT;
 long counter_start = 0;
 long counter_start_index = 0;
 long counter_stop_index = 0;
 size_t local_counter_min = 0;
 /* Thread local value of the global counter, to copy to user space */
 long local_counter;
 struct pstrace *local_ringbuffer = NULL;
 local_ringbuffer = kmalloc(sizeof(*local_ringbuffer)
  * PSTRACE_BUF_SIZE, GFP_KERNEL);
 if (!local_ringbuffer) {
  errno = -EFAULT;
  goto error;
 }
 memset(local_ringbuffer, 0,
  sizeof(*local_ringbuffer) * PSTRACE_BUF_SIZE);
 if (!buf || !counter) {
  errno = -EINVAL;
  goto error;
 }
 if (copy_from_user(&counter_start, counter,
  sizeof(counter_start)) != 0) {
  errno = -EFAULT;
  goto error;
 }
 counter_start_index = counter_start;
 counter_stop_index = counter_start + PSTRACE_BUF_SIZE;
 if (counter_start < 0) {
  errno = -EINVAL;
  goto error;
 }
 if (counter_start > 0) {
  errno = pstrace_get_blocking(counter_start, local_ringbuffer,
   &counter_stop_index, &local_counter,
   &local_counter_min);
  if (errno < 0)
   goto error;
 } else { /* counter_start == 0 */
  spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
  counter_stop_index = g_pstrace_counter;
  counter_start_index = g_pstrace_counter - PSTRACE_BUF_SIZE;
  if (counter_start_index < 0)
   counter_start_index = 0;
  memcpy(local_ringbuffer, g_pstrace_ringbuffer,
   sizeof(*local_ringbuffer) * PSTRACE_BUF_SIZE);
  if (g_pstrace_counter <= LONG_MAX)
   local_counter = g_pstrace_counter;
  else
   local_counter = 0;
  local_counter_min = g_pstrace_counter_min;
  spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 }
 errno = pstrace_get_copy_to_user(counter_start, counter_start_index,
  counter_stop_index, local_ringbuffer, buf,
  local_counter, counter, local_counter_min);
 if (signal_pending(current))
  errno = -EINTR;
error:
 kfree(local_ringbuffer);
 return errno;
}
static int pstrace_get_copy_to_user(long counter_start,
 long counter_start_index, long counter_stop_index,
 struct pstrace *local_ringbuffer, struct pstrace __user *buf,
 long local_counter, long __user *counter, size_t local_counter_min)
{
 int  entries_to_copy = 0;
 long entries_copied = 0;
 int  errno = -EFAULT;
 int  copy_start = 0;
 int  first_copy_count = 0;
 int  second_copy_count = 0;
 /* a blocking call got woken up too early */
 if (counter_start_index > counter_stop_index)
  goto done;
 /* don't return cleared entries */
 if (counter_start_index < local_counter_min)
  counter_start_index = local_counter_min;
 /* another method to not return cleared entries */
 while (counter_start_index < counter_stop_index
 && entry_is_cleared(counter_start_index % PSTRACE_BUF_SIZE,
 local_ringbuffer) == 1)
  counter_start_index++;
 if (counter_start_index > counter_stop_index)
  counter_start_index = counter_stop_index;
 /* entries_to_copy will be <= PSTRACE_BUF_SIZE */
 entries_to_copy = counter_stop_index - counter_start_index;
 /* occurs when entire buffered is cleared */
 if (entries_to_copy == 0)
  goto done;
 /* get index in ring buffer to start copy */
 copy_start = counter_start_index % PSTRACE_BUF_SIZE;
 /* determine number of bytes to copy on first pass */
 first_copy_count = PSTRACE_BUF_SIZE - copy_start;
 if (first_copy_count > entries_to_copy)
  first_copy_count = entries_to_copy;
 second_copy_count = entries_to_copy - first_copy_count;
 if (copy_to_user(buf, &local_ringbuffer[copy_start],
   sizeof(*local_ringbuffer)
   * first_copy_count) != 0) {
  errno = -EFAULT;
  goto error;
 }
 if (second_copy_count > 0 &&
  (copy_to_user(&buf[first_copy_count], local_ringbuffer,
   sizeof(*local_ringbuffer)
   * second_copy_count) != 0)) {
  errno = -EFAULT;
  goto error;
 }
done:
 if (copy_to_user(counter, &local_counter,
   sizeof(local_counter)) != 0) {
  errno = -EFAULT;
  goto error;
 }
 entries_copied = first_copy_count + second_copy_count;
 errno = entries_copied;
error:
 return errno;
}
static int pstrace_get_blocking(long counter_start,
 struct pstrace *local_ringbuffer,
 long *counter_stop_index, long *local_counter, size_t *local_min)
{
 int errno = 0;
 struct pstrace_queue_list *q_node = NULL;
 q_node = kmalloc(sizeof(*q_node), GFP_KERNEL);
 if (!q_node) {
  errno = -EFAULT;
  goto error;
 }
 q_node->g_counter_min = 0;
 INIT_LIST_HEAD(&q_node->list);
 spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
 *local_min = g_pstrace_counter_min;
 if (*counter_stop_index > g_pstrace_counter) {
  /* blocking case */
  q_node->index = *counter_stop_index;
  list_add_tail(&q_node->list, &g_pstrace_queue_list_head);
  q_node->g_counter_value = g_pstrace_counter;
  while (*counter_stop_index > q_node->g_counter_value
  && q_node->wakeup_early == 0) {
   q_node->told_to_wakeup = 0;
   q_node->awoken = 0;
   spin_unlock_irqrestore(&pstrace_lock,
    pstrace_irq_state);
   errno = wait_event_interruptible(pstrace_wait_q,
    (*counter_stop_index <= q_node->g_counter_value
    || q_node->wakeup_early == 0));
   if (signal_pending(current)) {
    q_node->wakeup_early = 1;
    errno = -EINTR;
    spin_lock_irqsave(&pstrace_lock,
     pstrace_irq_state);
    break;
   }
   spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
  }
  q_node->awoken = 1;
  list_del(&q_node->list);
  *local_min = q_node->g_counter_min;
  memcpy(local_ringbuffer, q_node->buff,
   sizeof(*local_ringbuffer) * PSTRACE_BUF_SIZE);
  if (q_node->wakeup_early > 0)
   *counter_stop_index = q_node->g_counter_value;
  if (q_node->g_counter_value <= LONG_MAX)
   *local_counter = q_node->g_counter_value;
  else
   *local_counter = 0;
  spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 } else if (*counter_stop_index <= g_pstrace_counter
  && !(g_pstrace_counter -
  *counter_stop_index > PSTRACE_BUF_SIZE)) {
  /* not blocking case */
  memcpy(local_ringbuffer, g_pstrace_ringbuffer,
   sizeof(*local_ringbuffer) * PSTRACE_BUF_SIZE);
  if (g_pstrace_counter <= LONG_MAX)
   *local_counter = g_pstrace_counter;
  else
   *local_counter = 0;
  spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 } else {
  memcpy(local_ringbuffer, g_pstrace_ringbuffer,
   sizeof(*local_ringbuffer) * PSTRACE_BUF_SIZE);
  if (g_pstrace_counter <= LONG_MAX)
   *local_counter = g_pstrace_counter;
  else
   *local_counter = 0;
  spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 }
error:
 kfree(q_node);
 return errno;
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
 spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
 prepare_to_wakeup_all_sleepers();
 memset(g_pstrace_ringbuffer, 0,
  sizeof(*g_pstrace_ringbuffer) * PSTRACE_BUF_SIZE);
 g_pstrace_counter_min = g_pstrace_counter;
 spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 wake_up(&pstrace_wait_q);
 return 0;
}
void pstrace_add(struct task_struct *p, long state)
{
 size_t i;
 size_t wakeup_index = 0;
 int need_to_wakeup = 0;
 int need_to_reset_counter = 0;
 /* if p is NULL, move on */
 if (p == NULL)
  return;
 /* Only record a process state change if tracing is enabled */
 if (!g_pstrace_enabled)
  return;
 /* Only record a process state change if tracing is enabled for all
  * processes, or if tracing is enabled for the specific process (thread
  * group).
  */
 if (g_pstrace_traced_pid != -1 &&
   g_pstrace_traced_pid != p->tgid)
  return;
 /* Only record states in the approved list of states. */
 if (state != TASK_RUNNING && state != TASK_RUNNABLE
   && state != TASK_INTERRUPTIBLE
   && state != TASK_UNINTERRUPTIBLE
   && state != __TASK_STOPPED && state != EXIT_ZOMBIE
   && state != EXIT_DEAD)
  return;
 spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
 i = g_pstrace_counter % PSTRACE_BUF_SIZE;
 record_process_state_change(&g_pstrace_ringbuffer[i], p, state);
 g_pstrace_counter++;
 if (g_pstrace_counter > PSTRACE_BUF_SIZE)
  g_pstrace_counter_min = g_pstrace_counter - PSTRACE_BUF_SIZE;
 wakeup_index = g_pstrace_counter;
 need_to_wakeup = prepare_to_wakeup_at_index(wakeup_index);
 if (g_pstrace_counter == LONG_MAX) {
  need_to_wakeup = 1;
  need_to_reset_counter = 1;
  prepare_to_wakeup_all_sleepers();
 }
 spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 if (need_to_wakeup)
  wake_up(&pstrace_wait_q);
 if (need_to_reset_counter) {
  spin_lock_irqsave(&pstrace_lock, pstrace_irq_state);
  g_pstrace_counter = 0;
  spin_unlock_irqrestore(&pstrace_lock, pstrace_irq_state);
 }
}
static void record_process_state_change(struct pstrace *dst,
  struct task_struct *p, long state)
{
 strncpy(dst->comm, p->comm, sizeof(dst->comm));
 dst->state = state;
 dst->pid = p->tgid;
 dst->tid = p->pid;
}
static void prepare_to_wakeup_all_sleepers(void)
{
 struct pstrace_queue_list *node = NULL;
 list_for_each_entry(node, &g_pstrace_queue_list_head, list) {
  if (node->index != 0) {
   memcpy(node->buff, g_pstrace_ringbuffer,
    sizeof(*g_pstrace_ringbuffer)
    * PSTRACE_BUF_SIZE);
   node->wakeup_early = 1;
   node->g_counter_value = g_pstrace_counter;
   node->g_counter_min = g_pstrace_counter_min;
  }
 }
}
static int prepare_to_wakeup_at_index(size_t index)
{
 int need_to_wakeup = 0;
 struct pstrace_queue_list *node = NULL;
 struct pstrace_queue_list *temp = NULL;
 list_for_each_entry_safe(node, temp, &g_pstrace_queue_list_head, list) {
  if (node->index == index
    && node->told_to_wakeup == 0
    && node->awoken == 0) {
   need_to_wakeup = 1;
   node->told_to_wakeup = 1;
   node->g_counter_value = index;
   node->g_counter_min = g_pstrace_counter_min;
   memcpy(node->buff, g_pstrace_ringbuffer,
   sizeof(*g_pstrace_ringbuffer) * PSTRACE_BUF_SIZE);
  }
 }
 return need_to_wakeup;
}
static int entry_is_cleared(int index, const struct pstrace *buff)
{
 if (index >=  PSTRACE_BUF_SIZE)
  return -1;
 return (buff[index].pid == 0
  && buff[index].tid == 0
  && buff[index].state == 0
  && buff[index].comm[0] == 0);
}