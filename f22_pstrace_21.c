// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched/task.h> /* @TODO: nit */
#include <linux/pstrace.h>
#define PSTRACE_BUF_SIZE 500
#define ALL_PROCS -1
#define NO_PROCS INT_MIN
/*
 * Shared invariant:
 *
 * Never check anything on this struct without first adding yourself
 * to the refcount. When you know you are done with this, dec yourself
 * from the refcount and check whether you have to delete it.
 *
 * Accessing without being ref_counted will lead to a segfault
 *
 * The exception to this is that waited_counters on the waited_counters
 * queue need the lock to modify that list, and thus, cannot free their
 * mem until they are list_del'd and removed = 1. So, if a proc holds the
 * pstrace_lock and finds a proc with refcount = 0 on the waited_counters
 * queue, it can list_del it and set removed = 1, while holding the lock.
 *
 * If removed = 0, the list_del will also happen in the delete_shared routine
 */
struct waited_counter {
 long targ_counter; /* counter val to wake this at */
 atomic_t ref_count; /* number of refs to this */
 int removed; /* 0 if still on global list, 1 if not */
 struct wait_queue_head waiters;
 struct list_head list;
};
LIST_HEAD(waited_counters);
struct pstrace pstrace_buf[PSTRACE_BUF_SIZE];
long n_cleared, counter, cleared_epoch;
DEFINE_SPINLOCK(pstrace_lock);
/* @TODO: lock or lock_irqsave? */
/* -1 == ALL_PROCS : all processes tracked
 *    NO_PROCS     : no processes tracked
 */
atomic_t tracked_pid = ATOMIC_INIT(NO_PROCS);
/*
 * Write as many entries as possible starting at max(n_overwritten, cleared_end)
 * ending at min(counter_end, counter)
 *
 * Returns the number of elements actually copied
 *
 * REQUIRES: pstrace_lock held, dst has n valid slots
 */
inline int dump_circular(struct pstrace *dst, long cleared_end, long counter_end)
{
 int begin_idx, end_idx, end_sz, n;
 long begin = max(counter - PSTRACE_BUF_SIZE, cleared_end);
 long end = min(counter, counter_end);
 n = end - begin;
 if (n <= 0)
  return 0;
 begin_idx = begin % PSTRACE_BUF_SIZE;
 end_idx = end % PSTRACE_BUF_SIZE;
 if (end_idx <= begin_idx) {
  end_sz = PSTRACE_BUF_SIZE - begin_idx;
  memcpy(
   dst,
   pstrace_buf + begin_idx,
   end_sz * sizeof(struct pstrace)
  );
  memcpy(
   dst + end_sz,
   pstrace_buf,
   end_idx * sizeof(struct pstrace)
  );
 } else {
  memcpy(
   dst,
   pstrace_buf + begin_idx,
   (end_idx - begin_idx) * sizeof(struct pstrace)
  );
 }
 return n;
}
/*
 * Checks if this waited_counter is safe to delete
 *
 * Once ref_count == 0, this entry WILL be deleted and is basically invalid
 * Modifying the waited_counters requires holding the pstrace_lock, but we
 * can check if that's already happened before going through the expensive
 * operation of getting the lock
 *
 * Do NOT use waiter->removed to check whether this has been deleted
 * outside of this function
 *
 * pstrace_lock must NOT be held
 */
void delete_shared_waiter(struct waited_counter *waiter)
{
 unsigned long flags;
 if (atomic_dec_and_test(&waiter->ref_count)) {
  if (!waiter->removed) {
   spin_lock_irqsave(&pstrace_lock, flags);
   if (!waiter->removed)
    list_del(&waiter->list);
   spin_unlock_irqrestore(&pstrace_lock, flags);
  }
  kfree(waiter);
 }
}
void delete_shared_waiter_locked(struct waited_counter *waiter)
{
 if (atomic_dec_and_test(&waiter->ref_count)) {
  if (!waiter->removed)
   list_del(&waiter->list);
  kfree(waiter);
 }
}
/*
 * Checks if current value of counter should wake some threads
 *
 * Returns list of waited counters that can be woken. Once a waiter is ret'd
 * from here, it is removed from the waited_counters list and removed = 1, so
 * it is unreachable. We save a ref, so you need to run shared_delete on each.
 *
 * Adds us as a reference, so shared_delete must be called by whoever calls this
 * That call is guaranteed not to block, as we're setting removed to 1 here
 *
 * REQUIRES: pstrace_lock is held
 */
void check_if_notify(struct list_head *woken)
{
 struct waited_counter *curr, *next;
 if (list_empty(&waited_counters))
  return;
 /* Find first valid entry, remove deleted entries along the way */
 list_for_each_entry_safe(curr, next, &waited_counters, list) {
  if (!atomic_inc_not_zero(&curr->ref_count)) {
   list_del(&curr->list);
   curr->removed = 1;
  } else if (counter >= curr->targ_counter) {
   list_del(&curr->list);
   list_add(&curr->list, woken);
   curr->removed = 1;
  } else {
   delete_shared_waiter_locked(curr);
   return;
  }
 }
}
/*
 * Adds this waiter to global queue
 *
 * Returns the pointer to the actual list entry in the global queue, for later cleanup
 * Handles when a targ_counter is already being waited on
 *
 * REQUIRES: pstrace_lock is held
 * me has targ_counter is set correctly, ref_count = 1, removed = 1
 */
struct waited_counter *reg_waited(struct waited_counter *me)
{
 struct waited_counter *spot, *next;
 me->removed = 0;
 list_for_each_entry_safe(spot, next, &waited_counters, list) {
  if (!atomic_inc_not_zero(&spot->ref_count)) {
   /* aggressively clean up list whenever we can */
   list_del(&spot->list);
   spot->removed = 1;
  } else if (spot->targ_counter == me->targ_counter) {
   kfree(me);
   /* keep ref to spot */
   return spot;
  } else if (spot->targ_counter <= me->targ_counter) {
   /* found valid entry but counter too low, continue */
   delete_shared_waiter_locked(spot);
  } else {
   list_add_tail(&me->list, &spot->list);
   delete_shared_waiter_locked(spot);
   return me;
  }
 }
 list_add_tail(&me->list, &waited_counters);
 return me;
}
/*
 * returns true if this pid is being tracked,
 * false otherwise
 */
inline int pid_is_tracked(pid_t pid)
{
 pid_t tracked = atomic_read(&tracked_pid);
 return tracked == ALL_PROCS || tracked == pid;
}
void pstrace_update(void)
{
 unsigned long flags;
 LIST_HEAD(woken);
 struct waited_counter *wc, *next;
 spin_lock_irqsave(&pstrace_lock, flags);
 check_if_notify(&woken);
 spin_unlock_irqrestore(&pstrace_lock, flags);
 list_for_each_entry_safe(wc, next, &woken, list) {
  wake_up_interruptible_all(&wc->waiters);
  /* will never grab lock as removed = 1 in check_if_notify */
  delete_shared_waiter(wc);
 }
}
/*
 * Add this state to the trace ring buf
 *
 * If p is a process being tracked
 * And state is a state of interest
 */
void pstrace_add(struct task_struct *p, long state)
{
 unsigned long flags;
 int write_idx;
 pid_t pid, tid;
 /* @TODO: is this necessary? */
 if (!p)
  return;
 pid = task_tgid_nr(p);
 tid = task_pid_nr(p);
 if (!pid_is_tracked(pid))
  return;
 spin_lock_irqsave(&pstrace_lock, flags);
 write_idx = counter++ % PSTRACE_BUF_SIZE;
 memcpy(pstrace_buf[write_idx].comm, p->comm, 16);
 pstrace_buf[write_idx].state = state;
 pstrace_buf[write_idx].pid = pid;
 pstrace_buf[write_idx].tid = tid;
 spin_unlock_irqrestore(&pstrace_lock, flags);
}
/*
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 *
 * @TODO: should we check pid exists?
 */
long __pstrace_enable_impl(pid_t pid)
{
 if (pid < -1)
  return -EINVAL;
 atomic_set(&tracked_pid, pid);
 return 0;
}
/*
 * Disable tracing for all pids
 */
long __pstrace_disable_impl(void)
{
 atomic_set(&tracked_pid, NO_PROCS);
 return 0;
}
/*
 * Copy the pstrace ring buffer into @buf.
 * If @counter >0, the caller process will wait until a full buffer can
 * be returned after record @counter (i.e. return record @counter + 1 to
 * @counter + PSTRACE_BUF_SIZE), otherwise, return immediately.
 *
 * Returns the number of records copied.
 */
long __pstrace_get_impl(struct pstrace *buf, long *user_counter_ptr)
{
 unsigned long flags;
 long n_found, user_counter, targ_counter, end_counter;
 long cleared_end, epoch;
 struct pstrace *snapshot_buf;
 struct waited_counter *me;
 if (buf == NULL || user_counter_ptr == NULL)
  return -EINVAL;
 if (copy_from_user(&user_counter, user_counter_ptr, sizeof(long)))
  return -EFAULT;
 if (user_counter < 0)
  return -EINVAL;
 targ_counter = user_counter ? user_counter + PSTRACE_BUF_SIZE : counter;
 /* Need to kmalloc due to limited kernel stack size */
 snapshot_buf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (snapshot_buf == NULL)
  return -ENOMEM;
 me = kmalloc(sizeof(struct waited_counter), GFP_KERNEL);
 if (me == NULL) {
  kfree(snapshot_buf);
  return -ENOMEM;
 }
 atomic_set(&me->ref_count, 1);
 me->removed = 1;
 init_waitqueue_head(&me->waiters);
 spin_lock_irqsave(&pstrace_lock, flags);
 cleared_end = n_cleared;
 if (targ_counter > counter) {
  /* blocking case */
  epoch = cleared_epoch;
  me->targ_counter = targ_counter;
  me = reg_waited(me);
  spin_unlock_irqrestore(&pstrace_lock, flags);
  if (wait_event_interruptible(me->waiters, (counter >= targ_counter || cleared_epoch > epoch))) {
   kfree(snapshot_buf);
   delete_shared_waiter(me);
   return -EINTR; /* is this proper errnum @TODO */
  }
  spin_lock_irqsave(&pstrace_lock, flags);
 }
 n_found = dump_circular(snapshot_buf, cleared_end, targ_counter);
 end_counter = counter;
 delete_shared_waiter_locked(me);
 spin_unlock_irqrestore(&pstrace_lock, flags);
 if (n_found && copy_to_user(buf, snapshot_buf, n_found * sizeof(struct pstrace))) {
  kfree(snapshot_buf);
  return -EFAULT;
 }
 kfree(snapshot_buf);
 if (end_counter != user_counter &&
  copy_to_user(user_counter_ptr, &end_counter, sizeof(long)))
  return -EFAULT;
 return n_found;
}
/*
 * Clear the pstrace ring buffer, counter remains unchanged
 *
 * Clear might be called wo counter changing, but all the getters should
 * be cleared, so we need to separate n_cleared from cleared_epoch
 * and have getters check the epoch
 */
long __pstrace_clear_impl(void)
{
 struct waited_counter *curr, *next;
 unsigned long flags;
 struct list_head notify_list;
 spin_lock_irqsave(&pstrace_lock, flags);
 n_cleared = counter;
 cleared_epoch++;
 /* move everything waiting to notify list */
 list_cut_before(&notify_list, &waited_counters, &waited_counters);
 /* we need to list_del entries to ensure they aren't deleted
  * before we traverse and notify everyone when we don't hold the lock
  */
 list_for_each_entry_safe(curr, next, &notify_list, list) {
  if (!atomic_inc_not_zero(&curr->ref_count))
   list_del(&curr->list);
  curr->removed = 1;
 }
 spin_unlock_irqrestore(&pstrace_lock, flags);
 list_for_each_entry(curr, &notify_list, list) {
  wake_up_interruptible_all(&curr->waiters);
  /* will never grab lock as we just set removed = 1 */
  delete_shared_waiter(curr);
 }
 return 0;
}
/*
 * Syscall 441
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 return __pstrace_enable_impl(pid);
}
/*
 * Syscall 442
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 return __pstrace_disable_impl();
}
/*
 * Syscall 443
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
 counter)
{
 return __pstrace_get_impl(buf, counter);
}
/*
 * Syscall 444
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 return __pstrace_clear_impl();
}