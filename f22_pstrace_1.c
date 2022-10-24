// SPDX-License-Identifier: MIT
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
#include <asm-generic/atomic-instrumented.h>
#include <linux/nospec.h>
#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include "uid16.h"
#include "linux/pstrace.h"
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
/*
 * trace when a process switches from being on the run queue
 * to actually running on the CPU, even though Linux denotes
 * both of those states as TASK_RUNNING
 */
#define TASK_RUNNABLE 3
struct event {
 long counter;
 wait_queue_head_t wq;
 struct list_head node;
};
/* define global wait list for struct events */
LIST_HEAD(head);
struct pstrace ring_buffer[PSTRACE_BUF_SIZE];
int bool_buffer[PSTRACE_BUF_SIZE];
DEFINE_SPINLOCK(main_lock);
DEFINE_SPINLOCK(wait_lock);
unsigned long flags;
unsigned long wait_flags;
/* set this to -2 first, -2 mean disabled */
atomic_t global_pid = ATOMIC_INIT(-2);
atomic_t buf_counter = ATOMIC_INIT(0);
atomic_t clear = ATOMIC_INIT(0);
atomic_t wait_count = ATOMIC_INIT(0);
int init_pid = -2;
static struct task_struct *access_pid(int specific_pid)
{
 if (specific_pid == 0)
  return &init_task;
 return find_task_by_vpid(specific_pid);
}
void check_wait_queue(void)
{
 /*
  * check linked list struct here, if condition fits
  * wake up the waitqueue in the struct
  */
 struct event *content;
 struct list_head *cur = &head;
 cur = cur->next;
 while (cur != &head) {
  content = container_of(cur, struct event, node);
  cur = cur->next;
  if (content == NULL)
   continue;
  if (
   atomic_read(&buf_counter)
   >= content->counter + PSTRACE_BUF_SIZE
   || atomic_read(&clear)
   ) {
   wake_up_all(&content->wq);
   list_del(cur->prev);
  }
 }
}
void add_to_buffer(struct pstrace temp)
{
 int index = 0;
 atomic_inc(&buf_counter);
 index = atomic_read(&buf_counter) % PSTRACE_BUF_SIZE;
 ring_buffer[index] = temp;
 bool_buffer[index] = 1;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p, long state)
{
 struct pstrace temp;
 if (atomic_read(&global_pid) == -2)
  return;
 strcpy(temp.comm, p->comm);
 temp.state = state % 1000;
 /* sys_getpid - return the thread group id of the current process */
 temp.pid = p->tgid;
 /* Thread ID - the internal kernel "pid" */
 temp.tid = p->pid;
 if (atomic_read(&global_pid) == -1
  || temp.pid == atomic_read(&global_pid)) {
  /* this part is critical, need to be put under lock
   * if state is -1, we will only check wait queue
   * if state is between 0 to 1000,
   * we add to buffer and check wait queue
   * if state is greater than 1000, we only add to buffer
   */
  if (state != -1) {
   spin_lock_irqsave(&main_lock, flags);
   add_to_buffer(temp);
   spin_unlock_irqrestore(&main_lock, flags);
  }
  /*
   * if it is not in __schedule before context_switch
   * and it is not in the
   * process of trying to wake up, call check_wakeup
   */
  if (state < 1000) {
   spin_lock_irqsave(&wait_lock, wait_flags);
   check_wait_queue();
   spin_unlock_irqrestore(&wait_lock, wait_flags);
  }
 }
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *temp;
 /*
  * Error checking for valid pid.
  * -1 is allowed as it enables tracing of all processes
  * If pstrace is already enabled, enable it again
  * will reset the two pointers counter and head
  * so that we can replace ring_buffer with new data
  */
 if (pid == -1) {
  atomic_set(&global_pid, pid);
 } else {
  temp = access_pid(pid);
  if (temp == NULL)
   return -ESRCH;
  atomic_set(&global_pid, pid);
 }
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 atomic_set(&global_pid, init_pid);
 return 0;
}
int copy_ring_buf_to_user(struct pstrace *buf, long *counter,
 int lower, int upper)
{
 int c;
 int buf_i = 0;
 int counter_index = lower;
 int ring_buf_i = 0;
 if (copy_from_user(&c, counter, sizeof(int)))
  return -EFAULT;
 while (counter_index >= lower && counter_index <= upper) {
  ring_buf_i = counter_index % PSTRACE_BUF_SIZE;
  /* if the entry is invalid, we will skip it*/
  if (bool_buffer[ring_buf_i] == 1) {
   if (copy_to_user(buf + buf_i,
    &ring_buffer[ring_buf_i],
    sizeof(struct pstrace)))
    return -EFAULT;
   ++buf_i;
  }
  counter_index += 1;
 }
 /*
  * if there are no records to copy or counter = 0,
  * return with the current buf_counter
  * since upper bound will be upper < buf_counter - PSTRACE_BUF_SIZE
  * else return upper bound as counter
  */
 counter_index = upper + PSTRACE_BUF_SIZE <= atomic_read(&buf_counter)
     ? atomic_read(&buf_counter)
     : upper;
 if (copy_to_user(counter, &counter_index, sizeof(int)))
  return -EFAULT;
 return buf_i;
}
int pstrace_get(struct pstrace *buf, long *counter)
{
 long c;
 int res = 0;
 int lower = 0;
 int upper = 0;
 struct event e;
 DEFINE_WAIT(w);
 init_waitqueue_head(&e.wq);
 if (copy_from_user(&c, counter, sizeof(long)))
  return -EFAULT;
 if (buf == NULL || counter == NULL || c < 0)
  return -EINVAL;
 /*
  * get all the currently valid entries,
  * set counter to buf_counter
  */
 if (c == 0) {
  spin_lock_irqsave(&main_lock, flags);
  lower = atomic_read(&buf_counter) < PSTRACE_BUF_SIZE
    ? 1
    : atomic_read(&buf_counter)
     - PSTRACE_BUF_SIZE + 1;
  upper = atomic_read(&buf_counter);
  res = copy_ring_buf_to_user(buf, counter, lower, upper);
  spin_unlock_irqrestore(&main_lock, flags);
  return res;
 }
 /*
  * the buf_counter already large enough, don't wait,
  * return valid entries in buffer
  * in case ring_buf_counter = 700, we pass counter = 100, we get
  * entries from 700 - 500 + 1 = 201 to 600, update counter to 600
  * if ring_buf_counter is 1200, we cann't get entries between 701 to 600
  * set counter to buf_counter
  */
 if (c + PSTRACE_BUF_SIZE <= atomic_read(&buf_counter)) {
  spin_lock_irqsave(&main_lock, flags);
  lower = atomic_read(&buf_counter) - PSTRACE_BUF_SIZE + 1;
  upper = c + PSTRACE_BUF_SIZE;
  res = copy_ring_buf_to_user(buf, counter, lower, upper);
  spin_unlock_irqrestore(&main_lock, flags);
  return res;
 }
 /*
  * create a wait queue, connect it with global list head
  * so we can call wake up all later
  * when buf_counter reaches c + PSTRACE_BUF_SIZE
  */
 e.counter = c;
 spin_lock_irqsave(&wait_lock, wait_flags);
 list_add_tail(&(e.node), &(head));
 spin_unlock_irqrestore(&wait_lock, wait_flags);
 for (;;) {
  prepare_to_wait(&e.wq, &w, TASK_INTERRUPTIBLE);
  if (atomic_read(&buf_counter) >= c + PSTRACE_BUF_SIZE
   || atomic_read(&clear)) {
   spin_lock_irqsave(&main_lock, flags);
   lower = c + 1;
   /*
    * if clear wakes up the process then it also means that
    * the buf_counter is not reaching
    * e.counter + PSTRACE_BUF_SIZE
    * so we want to record from lower bound up
    * to buf_counter
    */
   upper = atomic_read(&clear) ?
   atomic_read(&buf_counter) :
   c + PSTRACE_BUF_SIZE;
   res = copy_ring_buf_to_user(buf, counter, lower, upper);
   atomic_dec(&wait_count);
   spin_unlock_irqrestore(&main_lock, flags);
   break;
  }
  if (!signal_pending(current)) {
   atomic_inc(&wait_count);
   schedule();
   continue;
  }
  res = -EINTR;
  list_del(&e.node);
  break;
 }
 finish_wait(&e.wq, &w);
 return res;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf,
 long __user *, counter)
{
 return pstrace_get(buf, counter);
}
SYSCALL_DEFINE0(pstrace_clear)
{
 int i = 0;
 int pid = atomic_read(&global_pid);
 /* force all processes to wake up */
 atomic_set(&clear, 1);
 atomic_set(&global_pid, init_pid);
 spin_lock_irqsave(&wait_lock, wait_flags);
 check_wait_queue();
 spin_unlock_irqrestore(&wait_lock, wait_flags);
 /* wait until all processes wakes up */
 while (atomic_read(&wait_count))
  i = 0;
 /*
  * Clear the ring buffer by checking off bool_buffer.
  * Clear does not reset buffer counter
  */
 spin_lock_irqsave(&main_lock, flags);
 while (i < PSTRACE_BUF_SIZE) {
  bool_buffer[i] = 0;
  i += 1;
 }
 spin_unlock_irqrestore(&main_lock, flags);
 atomic_set(&global_pid, pid);
 atomic_set(&clear, 0);
 return 0;
}