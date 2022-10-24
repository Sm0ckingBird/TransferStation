// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/pstrace.c
 *
 *  Copyright (C) 2022, 2022 Abhilash, Ajay, Sai Teja
 */
/*
 * These syscalls are used to record the process state changes.
 */
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/dcookies.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include <linux/time_namespace.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/sched/cputime.h>
#include <linux/rcupdate.h>
#include <linux/uidgid.h>
#include <linux/cred.h>
#include <linux/nospec.h>
#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include "uid16.h"
// New includes
#include <linux/printk.h>
#include <linux/init_task.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/pstrace.h>
#include <linux/semaphore.h>
// WAIT QUEUE IMPLEMENTATION
struct wq_proc {
 struct semaphore sleep_sem;
 long target_count;
 struct pstrace *kbuf;
 int copied;
 struct list_head list;
};
static LIST_HEAD(wq_list_head);
static int wq_size;
// PSTRACE_CLEAR
static int pstc_num_sleeping_procs;
static int pstc_need_wake_up;
static struct semaphore pstc_sleep_sem =
 __SEMAPHORE_INITIALIZER(pstc_sleep_sem, 0);
// RING BUFFER IMPLEMENTATION
static struct pstrace rb_array[PSTRACE_BUF_SIZE];
static int rb_front = -1, rb_end = -1;
static int rb_cur_size;
static long rb_count;
static DEFINE_SPINLOCK(rb_lock);
static unsigned long rb_lock_flags;
inline int __rb_is_empty(void)
{
 return (rb_cur_size == 0);
}
inline int __rb_is_full(void)
{
 return (rb_cur_size == PSTRACE_BUF_SIZE);
}
inline void __rb_clear(void)
{
 rb_cur_size = 0;
 rb_front = -1;
 rb_end = -1;
}
inline void __rb_del(struct pstrace *buf)
{
 struct pstrace *ret = NULL;
 if (rb_cur_size < 1)
  return;
 ret = &(rb_array[rb_front]);
 rb_cur_size--;
 rb_front = (rb_front + 1) % PSTRACE_BUF_SIZE;
 if (__rb_is_empty()) {
  rb_front = -1;
  rb_end = -1;
 }
 if (buf) {
  strcpy(buf->comm, ret->comm);
  buf->state = ret->state;
  buf->pid = ret->pid;
  buf->tid = ret->tid;
 }
}
inline void rb_peek(struct pstrace *buf)
{
 struct pstrace *ret = NULL;
 if (!buf)
  return;
 spin_lock_irqsave(&rb_lock, rb_lock_flags);
 if (rb_cur_size < 1) {
  spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
  return;
 }
 ret = &(rb_array[rb_front]);
 spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
 strcpy(buf->comm, ret->comm);
 buf->state = ret->state;
 buf->pid = ret->pid;
 buf->tid = ret->tid;
}
inline void __rb_populate(int pos, struct task_struct *task, long state)
{
 strcpy(rb_array[pos].comm, task->comm);
 rb_array[pos].state = state;
 rb_array[pos].pid = task->tgid;
 rb_array[pos].tid = task->pid;
}
inline int __copy_to_kbuf(struct pstrace *kbuf, long target_count)
{
 int true_copy = 0, copy_count = 0, front = rb_front;
 long tmp_count = rb_count - PSTRACE_BUF_SIZE;
 // rb_count = 1500, count = 1000 and target_count = 1500, 1000-1500, 1000-1500
 while (copy_count < rb_cur_size) {
  if (tmp_count <= target_count)
   kbuf[true_copy++] = rb_array[front];
  front = (front + 1) % PSTRACE_BUF_SIZE;
  tmp_count++;
  copy_count++;
 }
 return true_copy;
}
inline void rb_add(struct task_struct *task, long state)
{
 struct wq_proc *node, *tmp_node;
 int size = 0, del_count = 0;
 spin_lock_irqsave(&rb_lock, rb_lock_flags);
 if (!pid_should_log(task->tgid)) {
  spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
  return;
 }
 if (rb_cur_size < 1) {
  rb_cur_size = 1;
  rb_front = 0;
  rb_end = 0;
  __rb_populate(rb_end, task, state);
  rb_count++;
 } else {
  if (__rb_is_full())
   __rb_del(NULL);
  rb_cur_size++;
  rb_end = (rb_end + 1) % PSTRACE_BUF_SIZE;
  __rb_populate(rb_end, task, state);
  rb_count++;
 }
 if (wq_size) {
  node = list_first_entry(&wq_list_head, struct wq_proc, list);
  while (size < wq_size) {
   tmp_node = list_first_entry(&(node->list),
          struct wq_proc, list);
   if (rb_count == node->target_count) {
    // printk(KERN_DEBUG
    //        "rb_count (%ld) is atleast target_count %ld - proceeding to copy ",
    //        rb_count, node->target_count);
    node->copied = __copy_to_kbuf(
     node->kbuf, node->target_count);
    spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
    up(&(node->sleep_sem));
    spin_lock_irqsave(&rb_lock, rb_lock_flags);
    list_del(&(node->list));
    del_count++;
   }
   node = tmp_node;
   size++;
  }
  wq_size -= del_count;
 }
 // printk(KERN_DEBUG "RB_ADD p:%d t:%d f:%d e:%d c:%ld si:%d st:%ld",
 //        task->tgid, task->pid, rb_front, rb_end, rb_count, rb_cur_size,
 //        state);
 spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
}
/*
 * PID PSTRACE ENABLE DISABLE LOGIC:
 * -1: Disabled
 *  -2: Enabled for all PIDs
 * >0: Enabled for a particular PID
 */
static pid_t pid_cur_pid = -1;
static DEFINE_SPINLOCK(pid_lock);
static unsigned long pid_lock_flags;
inline int pid_should_log(pid_t pid)
{
 int ret = 0;
 // spin_lock_irqsave(&pid_lock, pid_lock_flags);
 ret = ((pid_cur_pid == -2) || (pid_cur_pid == pid));
 // spin_unlock_irqrestore(&pid_lock, pid_lock_flags);
 return ret;
}
inline void pid_enable_all(void)
{
 spin_lock_irqsave(&pid_lock, pid_lock_flags);
 // printk(KERN_DEBUG "Enabled tracing for all pids");
 pid_cur_pid = -2;
 spin_unlock_irqrestore(&pid_lock, pid_lock_flags);
}
inline void pid_enable_one(pid_t pid)
{
 spin_lock_irqsave(&pid_lock, pid_lock_flags);
 // printk(KERN_DEBUG "Enabled tracing for pid %d", pid);
 pid_cur_pid = pid;
 spin_unlock_irqrestore(&pid_lock, pid_lock_flags);
}
inline void pid_disable_all(void)
{
 spin_lock_irqsave(&pid_lock, pid_lock_flags);
 // printk(KERN_DEBUG "Disabled tracing!");
 pid_cur_pid = -1;
 spin_unlock_irqrestore(&pid_lock, pid_lock_flags);
}
// THIS IS THE FUNCTION THAT NEEDS TO BE CALLED EVERYWHERE!
inline void pstrace_add(struct task_struct *task, long state)
{
 // if (pid_should_log(task->tgid))
 rb_add(task, state);
}
static struct task_struct *get_task_struct_from_pid(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if (pid < -1)
  return -EINVAL;
 if (pid == -1) {
  pid_enable_all();
  return 0;
 }
 if (get_task_struct_from_pid((int)pid) == NULL)
  return -EINVAL;
 pid_enable_one(pid);
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 pid_disable_all();
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *,
  counter)
{
 /*
  * Check buf and counter for non null values.
  * Create kernel buf and counter.
  * Copy from user counter to kernel counter.
  * Get rb_lock.
  * Check rb_counter is the correct value (If counter+500 < rb_counter,
  * release the lock and return -EINVAL).
  * Release the lock and sleep on a condition if rb_counter is not yet
  * at the correct value. Wake up and get the lock.
  * Read data from rb_front to rb_end into kernel buffer.
  * Store rb_counter value.
  * Release the lock.
  * Copy from kernel buffer to user buffer.
  * Copy from rb_counter to user counter.
  * Return number of records copied.
  */
 struct pstrace *kbuf;
 long tmp_count, count, target_count = -1;
 int front, copy_count = 0, true_copy = 0, should_sleep = 0;
 struct wq_proc queue_elem = {
  .list = LIST_HEAD_INIT(queue_elem.list),
 };
 if (!buf || !counter)
  return -EINVAL;
 if (copy_from_user(&count, counter, sizeof(long)))
  return -EFAULT;
 if (count < 0)
  return -EINVAL;
 sema_init(&(queue_elem.sleep_sem), 0);
 kbuf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 // kbuf = kmalloc(PSTRACE_BUF_SIZE * sizeof(struct pstrace), GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
 queue_elem.kbuf = kbuf;
 queue_elem.copied = 0;
 spin_lock_irqsave(&rb_lock, rb_lock_flags);
 target_count = count + PSTRACE_BUF_SIZE;
 if (count > 0 && rb_count < target_count) {
  // printk(KERN_DEBUG
  //        "Need to wait for buffer to be filled as rb_count: %ld < target_count: %ld",
  //        rb_count, target_count);
  queue_elem.target_count = target_count;
  should_sleep = 1;
  pstc_num_sleeping_procs++;
  while (rb_count < target_count) {
   list_add_tail(&(queue_elem.list), &wq_list_head);
   wq_size++;
   spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
   if (down_interruptible(&(queue_elem.sleep_sem))) {
    spin_lock_irqsave(&rb_lock, rb_lock_flags);
    // printk(KERN_DEBUG "Woken up pstrace_get!");
    list_del(&(queue_elem.list));
    wq_size--;
    // pr_err("pstrace: interrupted in sleep");
    spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
    kfree(kbuf);
    return -EINTR;
   }
   spin_lock_irqsave(&rb_lock, rb_lock_flags);
   if (pstc_need_wake_up == 1)
    break;
  }
 }
 // printk(KERN_DEBUG
 //        "In pstrace_get count:%ld rb_count:%ld target_count:%ld queue_elem.copied:%d",
 //        count, rb_count, target_count, queue_elem.copied);
 if (queue_elem.copied) {
  // printk(KERN_DEBUG "Already copied the elements!");
  true_copy = queue_elem.copied;
 } else if ((count > 0) && (rb_count > target_count)) {
  // rb_count = 1600, count = 1000 and target_count = 1500, 1100-1600, 1100-1500
  // printk(KERN_DEBUG "Copying buffer until target_count %ld ",
  //        target_count);
  tmp_count = rb_count - PSTRACE_BUF_SIZE;
  front = rb_front;
  while (copy_count < rb_cur_size) {
   if (tmp_count <= target_count)
    kbuf[true_copy++] = rb_array[front];
   front = (front + 1) % PSTRACE_BUF_SIZE;
   tmp_count++;
   copy_count++;
  }
 } else if (rb_count > count) {
  // rb_count = 1495, count = 1000 and target_count = 1500, 995 - 1495, 1000-1495
  // printk(KERN_DEBUG "Copying valid entries post count %ld ",
  //        count);
  tmp_count = (rb_count - PSTRACE_BUF_SIZE) >= 0 ?
        rb_count - PSTRACE_BUF_SIZE :
        0;
  front = rb_front;
  while (copy_count < rb_cur_size) {
   if (tmp_count >= count)
    kbuf[true_copy++] = rb_array[front];
   front = (front + 1) % PSTRACE_BUF_SIZE;
   tmp_count++;
   copy_count++;
  }
 }
 count = rb_count;
 if (should_sleep) {
  // printk(KERN_DEBUG "Decrementing sleeping procs!");
  pstc_num_sleeping_procs--;
  if (pstc_num_sleeping_procs == 0 && pstc_need_wake_up == 1) {
   // printk(KERN_DEBUG "Waking up clear func!");
   spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
   up(&pstc_sleep_sem);
   spin_lock_irqsave(&rb_lock, rb_lock_flags);
  }
 }
 spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
 if (true_copy)
  if (copy_to_user(buf, kbuf,
     true_copy * sizeof(struct pstrace))) {
   kfree(kbuf);
   return -EFAULT;
  }
 kfree(kbuf);
 if (copy_to_user(counter, &count, sizeof(long)))
  return -EFAULT;
 return true_copy;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 struct wq_proc *node, *tmp_node;
 int size = 0;
 // printk(KERN_DEBUG "In pstrace clear!");
 spin_lock_irqsave(&rb_lock, rb_lock_flags);
 if (wq_size > 0) {
  node = list_first_entry(&wq_list_head, struct wq_proc, list);
  while (size < wq_size) {
   tmp_node = list_first_entry(&(node->list),
          struct wq_proc, list);
   spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
   up(&(node->sleep_sem));
   spin_lock_irqsave(&rb_lock, rb_lock_flags);
   list_del(&(node->list));
   node = tmp_node;
   size++;
  }
  wq_size = 0;
  while (pstc_num_sleeping_procs > 0) {
   pstc_need_wake_up = 1;
   spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
   // printk(KERN_DEBUG
   //        "pstrace clear waiting for blocked get procs to wakeup!");
   if (down_interruptible(&pstc_sleep_sem)) {
    // pr_err("pstrace_clear: interrupted in sleep");
    return -EINTR;
   }
   // printk(KERN_DEBUG "pstrace clear woke up!");
   spin_lock_irqsave(&rb_lock, rb_lock_flags);
  }
  pstc_need_wake_up = 0;
 }
 __rb_clear();
 spin_unlock_irqrestore(&rb_lock, rb_lock_flags);
 // printk(KERN_DEBUG "Success pstrace clear!");
 return 0;
}