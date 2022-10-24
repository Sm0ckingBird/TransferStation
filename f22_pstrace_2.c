// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h> // includes __user macro
#include <linux/syscalls.h> // includes SYSCALL_DEFINEX macro
#include <linux/pstrace.h>
#include <linux/pid.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#define PSTRACE_BUF_SIZE 500
// Define own data structure that store more info than pstrace struct, add more field later if needed
struct buffer_entry {
 struct pstrace ps;
};
// Definition of the ring buffer and its size
//struct pstrace trace_ring_buffer[PSTRACE_BUF_SIZE];
//int trace_ring_buffer_size;
// Define ring buffer of size PSTRACE_BUF_SIZE, define head and tail of the ring buffer
struct buffer_entry ring_buffer[PSTRACE_BUF_SIZE];
struct buffer_entry *rb_head = ring_buffer;
struct buffer_entry *rb_tail = ring_buffer;
// Defind ring buffer counter, use long for safe
long rb_counter;
long total_counter;
// Define a global struct to track process being traced
int trace_enable;
int trace_all;
struct task_struct *traced_process;
pid_t traced_pid;
// the ring buffer
DEFINE_SPINLOCK(ring_buffer_lock);
/* Imlementation of pstrace_add declared in include/linux/pstrace.h */
void pstrace_add(struct task_struct *p, long state)
{
 pid_t cur_pid;
 int index;
 spin_lock(&ring_buffer_lock);
 if (!trace_enable) {
  spin_unlock(&ring_buffer_lock);
  return;
 }
 cur_pid = task_pid_nr(p);
 if (cur_pid  == traced_pid || trace_all) {
  if (state == 0 || state == 1 || state == 2 || state == 3 || state == 4 || state == 16 || state == 32) {
   struct buffer_entry cur_entry;
   get_task_comm(cur_entry.ps.comm, p);
   cur_entry.ps.state = state;
   cur_entry.ps.pid = cur_pid;
   cur_entry.ps.tid = p->pid;
   index = (rb_counter) % PSTRACE_BUF_SIZE;
   ring_buffer[index] = cur_entry;
   rb_counter++;
   total_counter++;
   rb_head++;
  }
 }
 spin_unlock(&ring_buffer_lock);
}
/* Implementation of syscall 441 pstrace_enable
 *
 * Expanded function header:
 *
 * long pstrace_enable(pid_t pid);
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if (pid == -1) {
  spin_lock(&ring_buffer_lock);
  trace_enable = 1;
  trace_all = 1;
  rb_counter = 0;
  total_counter = 0;
  spin_unlock(&ring_buffer_lock);
 } else if ((trace_enable && pid != traced_pid) || (!trace_enable)) {
  // find task_struct by pid, error handle on invalid pid
  traced_process = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
  if (traced_process == NULL)
   return -EINVAL;
  spin_lock(&ring_buffer_lock);
  trace_enable = 1;
  trace_all = 0;
  traced_pid = pid;
  rb_counter = 0;
  total_counter = 0;
  spin_unlock(&ring_buffer_lock);
 }
 return 0;
}
/* Implementation of syscall 442 pstrace_disable
 *
 * Expanded function header:
 *
 * long pstrace_disable();
 */
SYSCALL_DEFINE0(pstrace_disable)
{
 spin_lock(&ring_buffer_lock);
 trace_enable = 0;
 spin_unlock(&ring_buffer_lock);
 return 0;
}
/*
 * copy num elements to the user buffer
 * starting at index ring_buffer_start
 */
int _copy_tracing_buffer_to_user(struct pstrace *buf, int ring_buffer_start, int num)
{
 int i;
 int ring_buffer_loc;
 struct pstrace *user_buffer_loc;
 for (i = 0; i < num; ++i) {
  user_buffer_loc = buf + i;
  ring_buffer_loc = (ring_buffer_start+i) % PSTRACE_BUF_SIZE;
  if (copy_to_user(user_buffer_loc, &ring_buffer[ring_buffer_loc], sizeof(struct pstrace)))
   return -EINVAL;
 }
 return num;
}
/* Implementation of syscall 443 pstrace_get
 *
 * Expanded function header:
 *
 * long pstrace_get(struct pstrace *buf, long *counter);
 */
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter)
{
 long user_counter;
 int copy_ret_code;
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if (copy_from_user(&user_counter, counter, sizeof(long)))
  return -EFAULT;
 if (user_counter < 0)
  return -EINVAL;
 if (user_counter == 0) {
  if (rb_counter < PSTRACE_BUF_SIZE) {
   copy_ret_code = _copy_tracing_buffer_to_user(buf, 0, rb_counter);
   user_counter = total_counter;
  } else {
   copy_ret_code = _copy_tracing_buffer_to_user(buf, rb_counter, PSTRACE_BUF_SIZE);
   user_counter = total_counter;
  }
 } else if (user_counter > 0) {
  if (rb_counter < user_counter + 2 * PSTRACE_BUF_SIZE && rb_counter > user_counter + PSTRACE_BUF_SIZE) {
   copy_ret_code = _copy_tracing_buffer_to_user(buf, rb_counter, user_counter%PSTRACE_BUF_SIZE - rb_counter%PSTRACE_BUF_SIZE + PSTRACE_BUF_SIZE);
   user_counter = user_counter + PSTRACE_BUF_SIZE;
  } else if (rb_counter <= user_counter + PSTRACE_BUF_SIZE) {
   // TODO: wait until rb_counter >= user_counter +500
   copy_ret_code = 0;
   user_counter = total_counter;
  } else {
   copy_ret_code = 0;
   user_counter = total_counter;
  }
 }
 if (copy_to_user(counter, &user_counter, sizeof(int)))
  return -EINVAL;
 return copy_ret_code;
}
/* Implementation of syscall 444 pstrace_clear
 *
 * Expanded function header:
 *
 * long pstrace_clear();
 */
SYSCALL_DEFINE0(pstrace_clear)
{
 spin_lock(&ring_buffer_lock);
 rb_tail = rb_head;
 rb_counter = 0;
 spin_unlock(&ring_buffer_lock);
 return 0;
}