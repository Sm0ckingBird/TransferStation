#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/list.h>
static DEFINE_SPINLOCK(pstrace_lock);
static DECLARE_WAIT_QUEUE_HEAD(pstrace_wait);
struct pstrace pstrace_buf[PSTRACE_BUF_SIZE];
long pstrace_count = 0;
pid_t pstrace_pid = -2;
long local_count = 0;
int tail = 0;
struct list_head *head = NULL;
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
struct queue {
 struct list_head queue_list;
 bool flag;
 pid_t pid;
 long counter;
};
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace pst;
 unsigned long flags;
 struct list_head *pos;
 struct list_head *temp;
 struct queue *entry;
 bool wakeup = false;
 spin_lock_irqsave(&pstrace_lock, flags);
   if (pstrace_pid == -2 || (pstrace_pid >= 0 && pstrace_pid != p->pid)) {
  spin_unlock_irqrestore(&pstrace_lock, flags);
  return;
 }
 strcpy(pst.comm, p->comm);
 pst.pid = p->pid;
 pst.tid = p->tgid;
 pst.state = state;
 pstrace_buf[tail++] = pst;
 pr_err("No.%ld pstrace: %s, %d, %d, %ld\n", pstrace_count,
        pstrace_buf[tail - 1].comm, pstrace_buf[tail - 1].pid,
        pstrace_buf[tail - 1].tid, pstrace_buf[tail - 1].state);
 pstrace_count++;
 local_count++;
 if (tail >= PSTRACE_BUF_SIZE)
  tail = 0;
 spin_unlock_irqrestore(&pstrace_lock, flags);
 if (head == NULL) {
  head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
  INIT_LIST_HEAD(head);
 }
 spin_lock_irqsave(&pstrace_lock, flags);
 list_for_each_safe(pos, temp, head) {
  entry = list_entry(pos, struct queue, queue_list);
  if (entry->counter + PSTRACE_BUF_SIZE <= pstrace_count) {
   entry->flag = true;
   list_del(&entry->queue_list);
   wakeup = true;
  }
 }
 spin_unlock_irqrestore(&pstrace_lock, flags);
 if (wakeup)
  wake_up_all(&pstrace_wait);
 return;
}
/*
 * Syscall No. 441
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 unsigned long flags;
 int ret = 0;
 spin_lock_irqsave(&pstrace_lock, flags);
 if (pid < -1) {
  pr_err("pstrace_enable(): Invalid argument.\n");
  ret = -EINVAL;
  goto out;
 }
 if (pid != -1 && !get_root(pid)) {
  pr_err("get_root(): No task %d\n", pid);
  ret = -ESRCH;
  goto out;
 }
 pstrace_pid = pid;
 pr_err("Current pstrace_pid: %d\n", pstrace_pid);
 out:
 spin_unlock_irqrestore(&pstrace_lock, flags);
 return ret;
}
/*
 * Syscall No. 442
 * Disable tracing.
*/
SYSCALL_DEFINE0(pstrace_disable)
{
 unsigned long flags;
 spin_lock_irqsave(&pstrace_lock, flags);
 pstrace_pid = -2;
 pr_err("Current pstrace_pid: %d\n", pstrace_pid);
 spin_unlock_irqrestore(&pstrace_lock, flags);
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
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 long kcounter;
 int ret = 0;
 unsigned long flags;
 int curr = 0;
 int i;
 int j;
 struct pstrace *temp_buf = kmalloc(PSTRACE_BUF_SIZE * sizeof(struct pstrace), GFP_KERNEL);
 if (copy_from_user(&kcounter, counter, sizeof(long))) {
  pr_err("copy from user error\n");
  ret = -EFAULT;
  goto out;
 }
 if (kcounter < 0) {
  pr_err("invalid counter value\n");
  ret = -EINVAL;
  goto out;
 } else if (kcounter == 0) {
  if (local_count <= PSTRACE_BUF_SIZE) {
   spin_lock_irqsave(&pstrace_lock, flags);
   for (i = 0; i < local_count; i++)
    temp_buf[curr++] = pstrace_buf[i];
   ret = local_count;
   spin_unlock_irqrestore(&pstrace_lock, flags);
   if (copy_to_user(buf, temp_buf, local_count * sizeof(struct pstrace)) || copy_to_user(counter, &pstrace_count, sizeof(long))) {
    pr_err("copy to user error\n");
    ret = -EFAULT;
    goto out;
   }
  } else {
   long length = PSTRACE_BUF_SIZE;
   spin_lock_irqsave(&pstrace_lock, flags);
   for (i = tail; i < PSTRACE_BUF_SIZE; i++)
    temp_buf[curr++] = pstrace_buf[i];
   for (j = 0; j < tail; j++)
    temp_buf[curr++] = pstrace_buf[j];
   ret = length;
   spin_unlock_irqrestore(&pstrace_lock, flags);
   if (copy_to_user(buf, temp_buf, length * sizeof(struct pstrace)) || copy_to_user(counter, &pstrace_count, sizeof(long))) {
    pr_err("copy to user error\n");
    ret = -EFAULT;
    goto out;
   }
  }
 } else {
  long start;
  long end;
  long length;
  struct queue *q;
  if (kcounter + PSTRACE_BUF_SIZE > pstrace_count) {
   // use wait queue
   if (head == NULL) {
    head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(head);
   }
   q = kmalloc(sizeof(struct queue), GFP_KERNEL);
   q->pid = current->pid;
   q->counter = kcounter;
   q->flag = false;
   spin_lock_irqsave(&pstrace_lock, flags);
   list_add_tail(&q->queue_list, head);
   spin_unlock_irqrestore(&pstrace_lock, flags);
   pr_err("add task to the wait queue");
   wait_event_interruptible(pstrace_wait, q->flag);
   kfree(q);
  }
  spin_lock_irqsave(&pstrace_lock, flags);
  if (kcounter + PSTRACE_BUF_SIZE > pstrace_count) {
   start = kcounter;
   end = pstrace_count;
  } else {
   start = pstrace_count - PSTRACE_BUF_SIZE;
   end = kcounter + PSTRACE_BUF_SIZE;
  }
  length = end - start;
  if ((length > 0) && (tail - length >= 0)) {
   for (i = tail - length; i < tail; i++)
    temp_buf[curr++] = pstrace_buf[i];
  } else if ((length > 0) && (tail - length < 0)) {
   for (i = PSTRACE_BUF_SIZE - (length - tail); i < PSTRACE_BUF_SIZE; i++)
    temp_buf[curr++] = pstrace_buf[i];
   for (j = 0; j < tail; j++)
    temp_buf[curr++] = pstrace_buf[j];
  } else {
   length = 0;
   end = pstrace_count;
  }
  ret = length;
  spin_unlock_irqrestore(&pstrace_lock, flags);
  if (copy_to_user(buf, temp_buf, length * sizeof(struct pstrace)) || copy_to_user(counter, &end, sizeof(long))) {
   pr_err("copy to user error\n");
   ret = -EFAULT;
   goto out;
  }
 }
 out:
 kfree(temp_buf);
 return ret;
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
 struct list_head *pos;
 struct list_head *temp;
 struct queue *entry;
 if (head == NULL) {
  head = kmalloc(sizeof(struct list_head), GFP_KERNEL);
  INIT_LIST_HEAD(head);
 }
 spin_lock_irqsave(&pstrace_lock, flags);
 list_for_each_safe(pos, temp, head) {
  entry = list_entry(pos, struct queue, queue_list);
  entry->flag = true;
  list_del(&entry->queue_list);
 }
 local_count = 0;
 tail = 0;
 spin_unlock_irqrestore(&pstrace_lock, flags);
 wake_up_all(&pstrace_wait);
 return 0;
}