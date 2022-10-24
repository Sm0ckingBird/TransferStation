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
#include <linux/list.h>
#include <linux/pstrace.h>
#include "uid16.h"
/* flag for tracing all task struct */
int trace_all = 0;
/* current traced pids if trace_all == 0*/
struct traced_pid current_pids = {
 .size = 0
};
LIST_HEAD(head);
int get_id = 1;
int add_flag = 0;
struct ring_element ring[PSTRACE_BUF_SIZE];
int buf_counter = 0;  // how many state changes in total. (only increases)
int write_index = 0; // what is the index to write next.
int r_flag = 0;  // for recursive locks
DEFINE_SPINLOCK(r_flag_lock);
DEFINE_SPINLOCK(trace_lock);
DECLARE_WAIT_QUEUE_HEAD(q);
void pstrace_add(struct task_struct *p){
 unsigned long flags;
 int exist = 0;
 int i;
 unsigned long p_state;
 if (p->exit_state == EXIT_ZOMBIE || p->exit_state == EXIT_DEAD){
  p_state = p->exit_state;
 } else if (p->state == TASK_RUNNING || p->state == TASK_INTERRUPTIBLE || p->state == TASK_UNINTERRUPTIBLE || p->state == __TASK_STOPPED){
  p_state = p->state;
 } else {
  return;
 }
 spin_lock_irqsave(&trace_lock, flags);
 for (i = 0; i< current_pids.size; i++) {
  if (current_pids.content[i] == p->pid )
   exist = 1;
 }
 if(trace_all)
  exist = 1;
 if (!exist) {
  spin_unlock_irqrestore(&trace_lock, flags);
  return;
 }
 // printk(KERN_INFO "PID %d, %s, %ld %ld %ld put in ring buffer\n", p->pid, p->comm, p->state, p->exit_state, p->real_parent->pid);
 ring[write_index].ps.pid = p->pid;
 ring[write_index].ps.state = p_state;
 memcpy(ring[write_index].ps.comm, p->comm, sizeof(char)*16);
 ring[write_index].counter = ++buf_counter;
 if (++write_index == PSTRACE_BUF_SIZE)
  write_index = 0;
 struct list_head *ptr;
 struct snapshot *s;
 list_for_each(ptr, &head) {
  s = list_entry(ptr, struct snapshot, list);
  if (s->getid <= 0)
   break;
  if (s->counter + PSTRACE_BUF_SIZE == buf_counter) {
   memcpy(s->buf, ring, sizeof(struct ring_element) * PSTRACE_BUF_SIZE);
  }
 }
 spin_unlock_irqrestore(&trace_lock, flags);
 printk(KERN_INFO "r_flag is = %d\n", r_flag);
  if (!r_flag)
   wake_up_all(&q);
}
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid){
 int i;
 struct list_head *j;
 spin_lock(&trace_lock);
 if (pid == -1){
  trace_all = 1;
  spin_unlock(&trace_lock);
  return 0;
 }
 for (i = 0; i < current_pids.size; i++){
  if (pid == current_pids.content[i]) {
   spin_unlock(&trace_lock);
   return -EINVAL;
  }
 }
 current_pids.content[current_pids.size++] = pid;
 spin_unlock(&trace_lock);
 printk(KERN_INFO "size=%d\n", current_pids.size);
 for (i = 0; i < current_pids.size; i++) {
  printk(KERN_INFO "%d\n", current_pids.content[i]);
 }
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
*/
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid){
 unsigned long flags;
 spin_lock_irqsave(&trace_lock, flags);
 if (pid == -1){
  /* stop tracing all processes*/
  trace_all = 0;
  current_pids.size = 0;
 }
 else {
  int i;
  for (i = 0; i < current_pids.size; i++) {
   if (current_pids.content[i] == pid)
    break;
  }
  if (i == current_pids.size) {
   // pid not exist
   spin_unlock_irqrestore(&trace_lock, flags);
   return -1;
  }
  int j;
  for (j = i; j < current_pids.size - 1; j++) {
   current_pids.content[j] = current_pids.content[j + 1];
  }
  current_pids.size--;
 }
 spin_unlock_irqrestore(&trace_lock, flags);
 return -1;
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
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace *, buf, int *, counter ){
 int ring_counter;
 int copied_entries = 0;
 int return_counter = -1;
 int i;
 unsigned long flags;
 if (counter == NULL) {
  return -EINVAL;
 }
 if (copy_from_user(&ring_counter, counter, sizeof(int)))
  return -EFAULT;
 printk(KERN_INFO "pstrace_get is called\n");
 if (ring_counter <= 0) {
  spin_lock_irqsave(&trace_lock, flags);
  if (buf_counter > PSTRACE_BUF_SIZE) {
   // this means the ring buffer is full
   for (i = write_index; i < PSTRACE_BUF_SIZE; i++) {
    if (ring[i].ps.pid == pid || pid == -1) {
     if (copy_to_user(buf + copied_entries, &ring[i].ps, sizeof(struct pstrace))) {
      spin_unlock_irqrestore(&trace_lock, flags);
      return -EFAULT;
     }
     copied_entries += 1;
     return_counter = ring[i].counter;
    }
   }
   for (i = 0; i < write_index; i++) {
    if (ring[i].ps.pid == pid || pid == -1) {
     if (copy_to_user(buf + copied_entries, &ring[i].ps, sizeof(struct pstrace))) {
      spin_unlock_irqrestore(&trace_lock, flags);
      return -EFAULT;
     }
     copied_entries += 1;
     return_counter = ring[i].counter;
    }
   }
  } else {
   for (i = 0; i < buf_counter; i++) {
    if (ring[i].ps.pid == pid || pid == -1) {
     if (copy_to_user(buf + copied_entries, &ring[i].ps, sizeof(struct pstrace))) {
      spin_unlock_irqrestore(&trace_lock, flags);
      return -EFAULT;
     }
     copied_entries += 1;
     return_counter = ring[i].counter;
    }
   }
  }
  if (copy_to_user(counter, &return_counter, sizeof(int))) {
   spin_unlock_irqrestore(&trace_lock, flags);
   return -EFAULT;
  }
  spin_unlock_irqrestore(&trace_lock, flags);
  return 0;
 } else {
  spin_lock_irqsave(&trace_lock, flags);
  printk(KERN_INFO "Internal buf counter = %d\n", buf_counter);
  if (buf_counter >= ring_counter + 2*PSTRACE_BUF_SIZE) {
   printk(KERN_INFO "The first if\n");
   if (copy_to_user(counter, &buf_counter, sizeof(int))) {
    spin_unlock_irqrestore(&trace_lock, flags);
    return -EFAULT;
   }
   spin_unlock_irqrestore(&trace_lock, flags);
   return 0;
  }
  if (buf_counter >= ring_counter + PSTRACE_BUF_SIZE) {
   printk(KERN_INFO "The second if\n");
   // copy part of the buffer to user
   // copy ring_counter + 1 -- ring_coutner + 500
   for (i = write_index; i < PSTRACE_BUF_SIZE; i++) {
    if (ring[i].counter > ring_counter + PSTRACE_BUF_SIZE)
     break;
    if (ring[i].ps.pid == pid || pid == -1) {
     if (copy_to_user(buf + copied_entries, &ring[i].ps, sizeof(struct pstrace))) {
      spin_unlock_irqrestore(&trace_lock, flags);
      return -EFAULT;
     }
     copied_entries++;
     return_counter = ring[i].counter;
    }
   }
   for (i = 0; i < write_index; i++) {
    if (ring[i].counter > ring_counter + PSTRACE_BUF_SIZE)
     break;
    if (ring[i].ps.pid == pid || pid == -1) {
     if (copy_to_user(buf + copied_entries, &ring[i].ps, sizeof(struct pstrace))) {
      spin_unlock_irqrestore(&trace_lock, flags);
      return -EFAULT;
     }
     copied_entries++;
     return_counter = ring[i].counter;
    }
   }
   if (copy_to_user(counter, &return_counter, sizeof(int))) {
    spin_unlock_irqrestore(&trace_lock, flags);
    return -EFAULT;
   }
   spin_unlock_irqrestore(&trace_lock, flags);
   return 0;
  }
  int myid = ++get_id;
  DEFINE_WAIT(wait);
  struct snapshot *entry = (struct snapshot *)kmalloc(sizeof(struct snapshot), GFP_KERNEL);
  if (entry == NULL) {
   return -ENOMEM;
  }
  entry->counter = ring_counter;
  entry->getid = myid;
  // entry->list = LIST_HEAD_INIT(entry->list);
  list_add_tail(&entry->list, &head);
  add_wait_queue(&q, &wait);
  while (buf_counter < ring_counter + PSTRACE_BUF_SIZE) {
   spin_unlock_irqrestore(&trace_lock, flags);
   prepare_to_wait(&q, &wait, TASK_INTERRUPTIBLE);
   printk(KERN_INFO "go to schedule()\n");
   schedule();
   printk(KERN_INFO "back from schedule()\n");
   spin_lock_irqsave(&trace_lock, flags);
  }
  finish_wait(&q, &wait);
  printk(KERN_INFO "finished wait\n");
  // loop through the snapshot list
  struct list_head *p;
  struct snapshot *s;
  list_for_each(p, &head) {
   s = list_entry(p, struct snapshot, list);
   if (s->getid == myid)
    break;
  }
  int start_index = -1;
  int min_counter = s->buf[0].counter;
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
   if (min_counter > s->buf[i].counter) {
    min_counter = s->buf[i].counter;
    start_index = i;
   }
  }
  for (i = start_index; i < PSTRACE_BUF_SIZE; i++) {
   if (s->buf[i].ps.pid == pid || pid == -1) {
    if (copy_to_user(buf + copied_entries, &s->buf[i].ps, sizeof(struct pstrace))) {
     spin_unlock_irqrestore(&trace_lock, flags);
     return -EFAULT;
    }
    copied_entries++;
    return_counter = s->buf[i].counter;
   }
  }
  for (i = 0; i < start_index; i++) {
   if (s->buf[i].ps.pid == pid || pid == -1) {
    if (copy_to_user(buf + copied_entries, &s->buf[i].ps, sizeof(struct pstrace))) {
     spin_unlock_irqrestore(&trace_lock, flags);
     return -EFAULT;
    }
    copied_entries++;
    return_counter = s->buf[i].counter;
   }
  }
  if (copy_to_user(counter, &return_counter, sizeof(int))) {
   spin_unlock_irqrestore(&trace_lock, flags);
   return -EFAULT;
  }
  spin_unlock_irqrestore(&trace_lock, flags);
  return 0;
 }
 return 0;
}
/*
 * Syscall No.439
 *
 * Clear the pstrace buffer. If @pid == -1, clear all records in the buffer,
 * otherwise, only clear records for the give pid.  Cleared records should
 * never be returned to pstrace_get.
 */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid){
 unsigned long flags;
 spin_lock_irqsave(&trace_lock, flags);
 if (pid == -1) {
  buf_counter = 0;
  spin_unlock_irqrestore(&trace_lock, flags);
  wake_up_all(&q);
  return 0;
 }
  else {
  }
 spin_unlock_irqrestore(&trace_lock, flags);
 return -1;
}