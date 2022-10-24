#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/printk.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/pstrace.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
struct ring *pstrace_rb;
int notify_clock;
DEFINE_HASHTABLE(pstrace_ptbl, 5);
DEFINE_SPINLOCK(pstrace_ptbl_lock);
DEFINE_SPINLOCK(pstrace_rb_lock);
DEFINE_HASHTABLE(pstrace_get_notify, 5);
DEFINE_SPINLOCK(pstrace_get_notify_lock);
/* Init the global ring buffer if not initialized yet. */
long init_ring_buffer(void)
{
 unsigned long flags;
 struct ring *rb;
 spin_lock_irqsave(&pstrace_rb_lock, flags);
 if (pstrace_rb) {
  spin_unlock_irqrestore(&pstrace_rb_lock, flags);
  /* already initialized  */
  return 0;
 }
 rb = kcalloc(1, sizeof(struct ring), GFP_KERNEL);
 if (!rb) {
  spin_unlock_irqrestore(&pstrace_rb_lock, flags);
  return -ENOMEM;
 }
 rb->front = 0;
 rb->back = -1;
 rb->size = 0;
 pstrace_rb = rb;
 spin_unlock_irqrestore(&pstrace_rb_lock, flags);
 return 0;
}
/* check if a process is in the ptbl */
int is_pid_in_tbl(pid_t pid)
{
 unsigned long flags;
 struct ptbl_node *n = NULL;
 spin_lock_irqsave(&pstrace_ptbl_lock, flags);
 hash_for_each_possible(pstrace_ptbl, n, hlist_node, (u32)-1) {
  if (n->pid == -1)
   goto found;
 }
 hash_for_each_possible(pstrace_ptbl, n, hlist_node, (u32)pid) {
  if (n->pid == pid)
   goto found;
 }
 spin_unlock_irqrestore(&pstrace_ptbl_lock, flags);
 return 0;
found:
 spin_unlock_irqrestore(&pstrace_ptbl_lock, flags);
 return 1;
}
/* copy all available records to the buf
 * return number of copied records
 * Caller holds the lock
 */
long copy_records(struct pstrace *result, pid_t pid, long record_begin_from);
void pstrace_try_notify(void)
{
 unsigned long irq_flags_gn;
 int bkt;
 struct get_notify_hnode *gn_hnode;
 struct get_notify *gn_entry;
 spin_lock_irqsave(&pstrace_get_notify_lock, irq_flags_gn);
 notify_clock += 1;
 if (notify_clock < 100)
  goto out;
 hash_for_each(pstrace_get_notify, bkt, gn_hnode, hlist_node) {
  gn_entry = &gn_hnode->get_notify;
  if (gn_entry->finished)
   wake_up_process(gn_entry->task);
 }
 notify_clock = 0;
out:
 spin_unlock_irqrestore(&pstrace_get_notify_lock, irq_flags_gn);
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 struct pstrace pt;
 unsigned long irq_flags_rb;
 unsigned long irq_flags;
 int bkt = 0;
 struct get_notify_hnode *gn_hnode = NULL;
 struct get_notify *gn_entry = NULL;
 /* check whether we are listening this pid */
 if (!is_pid_in_tbl(p->pid))
  return;
 /* check if this state should be tracked */
 get_task_comm(pt.comm, p);
 pt.pid = p->pid;
 pt.state = p->state | p->exit_state;
 pt.state &= EXIT_DEAD | EXIT_ZOMBIE |
      TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE | __TASK_STOPPED;
 if (pt.state == TASK_RUNNING && p->state != TASK_WAKING)
  return;
 pr_info("=============add started: pid: %d===============\n", p->pid);
 if (init_ring_buffer() != 0)
  return;
 spin_lock_irqsave(&pstrace_rb_lock, irq_flags_rb);
 if (pstrace_rb->size == PSTRACE_BUF_SIZE) {
  /*  buffer full, overriding... */
  pstrace_rb->offset++;
  pstrace_rb->front = (pstrace_rb->front + 1) % PSTRACE_BUF_SIZE;
  pstrace_rb->back = (pstrace_rb->back + 1) % PSTRACE_BUF_SIZE;
  pstrace_rb->states[pstrace_rb->back] = pt;
 } else {
  pstrace_rb->back = (pstrace_rb->back + 1) % PSTRACE_BUF_SIZE;
  pstrace_rb->size++;
  pstrace_rb->states[pstrace_rb->back] = pt;
 }
 pr_info("record added: {pid=%d, state=%ld, comm=%s}\n",
   pt.pid, pt.state, pt.comm);
 pr_info("after add: offset=%d, front=%d, back=%d, size=%d\n",
   pstrace_rb->offset, pstrace_rb->front,
   pstrace_rb->back, pstrace_rb->size);
 spin_lock_irqsave(&pstrace_get_notify_lock, irq_flags);
 hash_for_each(pstrace_get_notify, bkt, gn_hnode, hlist_node) {
  gn_entry = &gn_hnode->get_notify;
  if (pstrace_rb->size + pstrace_rb->offset >=
    gn_entry->record_begin_from +
    PSTRACE_BUF_SIZE &&
    gn_entry->finished == false) {
   copy_records(gn_entry->states, -1,
     gn_entry->record_begin_from);
   gn_entry->finished = true;
  }
 }
 spin_unlock_irqrestore(&pstrace_get_notify_lock, irq_flags);
 spin_unlock_irqrestore(&pstrace_rb_lock, irq_flags_rb);
 pr_info("=============add ended===============\n");
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct ptbl_node *n = NULL;
 unsigned long flags;
 if (is_pid_in_tbl(pid))
  return 0;
 n = kcalloc(1, sizeof(struct ptbl_node), GFP_KERNEL);
 if (!n)
  return -ENOMEM;
 n->pid = pid;
 spin_lock_irqsave(&pstrace_ptbl_lock, flags);
 hash_add(pstrace_ptbl, &n->hlist_node, (u32)pid);
 spin_unlock_irqrestore(&pstrace_ptbl_lock, flags);
 pr_info("pid %d enabled\n", pid);
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 unsigned long flags;
 struct ptbl_node *n = NULL;
 int bkt;
 spin_lock_irqsave(&pstrace_ptbl_lock, flags);
 if (pid != -1) {
  hash_for_each_possible(pstrace_ptbl, n, hlist_node, (u32)pid) {
   if (n->pid == pid) {
    hash_del(&n->hlist_node);
    kfree(n);
   }
  }
 } else {
  hash_for_each(pstrace_ptbl, bkt, n, hlist_node) {
   hash_del(&n->hlist_node);
   kfree(n);
  }
 }
 spin_unlock_irqrestore(&pstrace_ptbl_lock, flags);
 pr_info("pid %d disabled\n", pid);
 return 0;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 unsigned long flags;
 struct pstrace *pt = NULL;
 int i;
 spin_lock_irqsave(&pstrace_rb_lock, flags);
 if (pstrace_rb == NULL) {
  spin_unlock_irqrestore(&pstrace_rb_lock, flags);
  return 0;
 }
 for (i = 0; i < PSTRACE_BUF_SIZE; ++i) {
  pt = &pstrace_rb->states[i];
  if (pid == -1 || pt->pid == pid)
   memset(pt, 0, sizeof(struct pstrace));
 }
 spin_unlock_irqrestore(&pstrace_rb_lock, flags);
 return 0;
}
/* copy all available records to the buf
 * return number of copied records
 * Caller holds the lock
 */
long copy_records(struct pstrace *result, pid_t pid, long record_begin_from)
{
 long i;
 struct pstrace pt;
 int write_ptr = 0;
 long begin_i;
 long j;
 long max_count = -1;
 if (record_begin_from >= pstrace_rb->offset + PSTRACE_BUF_SIZE)
  return 0;
 if (record_begin_from < pstrace_rb->offset) {
  max_count = pstrace_rb->size -
   (pstrace_rb->offset - record_begin_from);
  record_begin_from = pstrace_rb->offset;
 } else {
  max_count = pstrace_rb->size -
   (record_begin_from - pstrace_rb->offset);
 }
 if (max_count <= 0)
  return 0;
 begin_i = record_begin_from - pstrace_rb->offset;
 if (begin_i < 0)
  return 0;
 begin_i += pstrace_rb->front;
 begin_i %= PSTRACE_BUF_SIZE;
 i = begin_i;
 for (j = 0; j < max_count; j++) {
  pt = pstrace_rb->states[i];
  if (pt.comm[0] != '\0' && (pid == -1 || pid == pt.pid))
   result[write_ptr++] = pt;
  if (i == (pstrace_rb->back))
   break;
  i = (i + 1) % PSTRACE_BUF_SIZE;
 }
 return write_ptr;
}
int __pstrace_get_wait(struct pstrace *result, pid_t pid,
  long record_begin_from)
{
 int ii;
 unsigned long irq_flags;
 int write_ptr = 0;
 struct pstrace *pstrace_entry;
 struct get_notify_hnode *new_notify_hnode = NULL;
 new_notify_hnode =
  kcalloc(1, sizeof(struct get_notify_hnode), GFP_KERNEL);
 if (!new_notify_hnode)
  return -ENOMEM;
 new_notify_hnode->get_notify.record_begin_from = record_begin_from;
 new_notify_hnode->get_notify.task = current;
 set_current_state(TASK_UNINTERRUPTIBLE);
 spin_lock_irqsave(&pstrace_get_notify_lock, irq_flags);
 hash_add(pstrace_get_notify, &new_notify_hnode->hlist_node,
   (u32)current->pid);
 /*  release lock and go sleep   */
 spin_unlock_irqrestore(&pstrace_get_notify_lock, irq_flags);
 schedule();
 set_current_state(TASK_RUNNING);
 /*  gather result  */
 for (ii = 0; ii < PSTRACE_BUF_SIZE; ii++) {
  pstrace_entry = &new_notify_hnode->get_notify.states[ii];
  if (pstrace_entry->comm[0] != '\0' &&
   (pid == -1 || pstrace_entry->pid == pid))
   result[write_ptr++] = *pstrace_entry;
 }
 hash_del(&new_notify_hnode->hlist_node);
 kfree(new_notify_hnode);
 return write_ptr;
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *,
  buf, long __user *, counter)
{
 int wait_result = 0;
 long k_counter = 0;
 long init_result = 0;
 unsigned long irq_flags;
 long record_begin_from = 0;
 struct pstrace *result = NULL;
 long num_copied = 0;
 pr_info("========pstrace_get started========\n");
 if (pid < -1)
  return -EINVAL;
 if (get_user(k_counter, counter))
  return -EFAULT;
 result = kcalloc(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (!result)
  return -ENOMEM;
 init_result = init_ring_buffer();
 if (init_result) {
  kfree(result);
  return init_result;
 }
 record_begin_from = k_counter + 1;
 pr_info("inited: k_counter=%ld, record_begin_from=%ld\n",
  k_counter, record_begin_from);
 if (k_counter > 0) {
  spin_lock_irqsave(&pstrace_rb_lock, irq_flags);
  /* is current size enough for return? */
  /* current buffer counter >= user counter + BUF_SIZE ?*/
  if (pstrace_rb->size + pstrace_rb->offset >=
    record_begin_from + PSTRACE_BUF_SIZE) {
   num_copied =
    copy_records(result, pid, record_begin_from);
   spin_unlock_irqrestore(&pstrace_rb_lock, irq_flags);
  } else {
   /* wait for the condition to fulfill. */
   /* we are holding the lock of rb here, release it */
   spin_unlock_irqrestore(&pstrace_rb_lock, irq_flags);
   wait_result = __pstrace_get_wait(
     result, pid, record_begin_from);
   if (wait_result < 0) {
    kfree(result);
    return wait_result;
   }
   num_copied = wait_result;
  }
  k_counter += PSTRACE_BUF_SIZE;
 } else {
  /* return immediately  */
  spin_lock_irqsave(&pstrace_rb_lock, irq_flags);
  if (pstrace_rb == NULL) {
   /*  no records  */
   pr_info("no records\n");
   spin_unlock_irqrestore(&pstrace_rb_lock, irq_flags);
   kfree(result);
   return 0;
  }
  num_copied = copy_records(result, pid, pstrace_rb->offset);
  k_counter = pstrace_rb->offset + pstrace_rb->size;
  spin_unlock_irqrestore(&pstrace_rb_lock, irq_flags);
 }
 if (copy_to_user(buf, result,
  sizeof(struct pstrace) * PSTRACE_BUF_SIZE)) {
  kfree(result);
  return -EFAULT;
 }
 if (put_user(k_counter, counter)) {
  kfree(result);
  return -EFAULT;
 }
 kfree(result);
 pr_info("========pstrace_get ended========\n");
 return num_copied;
}