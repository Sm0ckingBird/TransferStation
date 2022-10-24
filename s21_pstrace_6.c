// SPDX-License-Identifier: GPL-2.0
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/pstrace.h>
#include <linux/slab.h>
#include <linux/wait.h>
struct ring_element {
 long counter;
 bool is_cleared;
 struct pstrace trace;
};
/* Define the global ring buffer, and write pointer */
atomic64_t buffer_counter = ATOMIC64_INIT(0);
struct ring_element ring_buffer[PSTRACE_BUF_SIZE];
DEFINE_RWLOCK(ring_buffer_lock);
/* Define the global structure to track traced processes */
pid_t traced_pids[PSTRACE_BUF_SIZE];
int traced_pid_last_index = -1;
bool not_trace_all = true;
DEFINE_RWLOCK(traced_pids_lock);
/* wait queue */
static DECLARE_WAIT_QUEUE_HEAD(ring_buffer_wait_queue);
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 int i;
 bool flag_existing_pid = false, flag_memory_full = false;
 write_lock(&traced_pids_lock);
 if (pid == -1) {
  not_trace_all = false;
 } else {
  for (i = 0; i <= traced_pid_last_index; i++) {
   if (traced_pids[i] == pid) {
    flag_existing_pid = true;
    break;
   }
  }
  if (traced_pid_last_index == PSTRACE_BUF_SIZE - 1)
   flag_memory_full = true;
  if (!flag_existing_pid && !flag_memory_full)
   traced_pids[++traced_pid_last_index] = pid;
 }
 write_unlock(&traced_pids_lock);
 if (flag_existing_pid)
  return 0;
 else if (flag_memory_full)
  return -ENOMEM;
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 int i, j;
 bool flag_pid_found = true;
 write_lock(&traced_pids_lock);
 if (pid == -1) {
  not_trace_all = true;
 } else {
  i = 0;
  while (i <= traced_pid_last_index) {
   if (traced_pids[i] != pid)
    i++;
   else
    break;
  }
  if (i > traced_pid_last_index)
   flag_pid_found = false;
  if (flag_pid_found) {
   traced_pids[i] = traced_pids[traced_pid_last_index];
   traced_pid_last_index--;
  }
 }
 write_unlock(&traced_pids_lock);
 if (!flag_pid_found)
  return -EINVAL;
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 bool flag_trace, flag_state;
 int i, ALLOWED_STATES[6] = {0, 1, 2, 4, 32, 128};
 long tmp_buffer_counter;
 long tmp_pos;
 read_lock(&traced_pids_lock);
 flag_trace = !not_trace_all;
 i = 0;
 while (!flag_trace && i <= traced_pid_last_index) {
  if (traced_pids[i] == task_pid_nr(p))
   flag_trace = true;
  i++;
 }
 read_unlock(&traced_pids_lock);
 flag_state = false;
 i = 0;
 while (i < 6) {
  if (ALLOWED_STATES[i] == p->state) {
   flag_state = true;
   break;
  }
  i++;
 }
 if (flag_trace && flag_state) {
  /* need to take a lock on ring buffer and write_head*/
  write_lock(&ring_buffer_lock);
  tmp_buffer_counter = atomic64_read(&buffer_counter);
  tmp_pos = tmp_buffer_counter % PSTRACE_BUF_SIZE;
  ring_buffer[tmp_pos].counter = tmp_buffer_counter;
  strcpy(ring_buffer[tmp_pos].trace.comm, p->comm);
  ring_buffer[tmp_pos].trace.pid = task_pid_nr(p);
  if (p->exit_state == 32 || p->exit_state == 128)
   ring_buffer[tmp_pos].trace.state = p->exit_state;
  else
   ring_buffer[tmp_pos].trace.state = p->state;
  ring_buffer[tmp_pos].is_cleared = false;
  atomic64_inc(&buffer_counter);
  /* release lock on ring buffer and write_head */
  write_unlock(&ring_buffer_lock);
  /* Try waking up waiting pstrace_get calls*/
  wake_up_interruptible(&ring_buffer_wait_queue);
 }
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *,
buf, long __user *, counter) {
 int start, end, i, k;
 long user_counter;
 struct pstrace *user_buf;
 long tmp_buffer_counter;
 // check if either of buf and nr is NULL
 if (buf == NULL || counter == NULL)
  return -EINVAL;
 if (copy_from_user(&user_counter, counter, sizeof(long)))
  return -EFAULT;
 user_buf = kmalloc_array(
  PSTRACE_BUF_SIZE,
  sizeof(struct pstrace),
  GFP_KERNEL
 );
 if (!user_buf)
  return -ENOMEM;
 if (
  copy_from_user(
   user_buf,
   buf,
   PSTRACE_BUF_SIZE * sizeof(struct pstrace)
  )
 )
  return -EFAULT;
 if (user_counter < 1)
  user_counter = 0;
 if (atomic64_read(&buffer_counter) < user_counter + PSTRACE_BUF_SIZE) {
  wait_event_interruptible(
   ring_buffer_wait_queue,
   (
    atomic64_read(&buffer_counter) >=
    user_counter + PSTRACE_BUF_SIZE
   )
  );
 }
 read_lock(&ring_buffer_lock);
 tmp_buffer_counter = atomic64_read(&buffer_counter);
 if (tmp_buffer_counter > 0) {
  if (user_counter < 1) {
   // return whatever is in the buffer
   if (tmp_buffer_counter < PSTRACE_BUF_SIZE) {
    // return from 0 - buffer_counter
    start = 0;
    end = tmp_buffer_counter - 1;
   } else {
    start = tmp_buffer_counter % PSTRACE_BUF_SIZE;
    end = (tmp_buffer_counter - 1) %
     PSTRACE_BUF_SIZE;
   }
  } else {
   start = (user_counter) % PSTRACE_BUF_SIZE;
   end = (user_counter - 1) % PSTRACE_BUF_SIZE;
  }
  i = start;
  k = 0;
  while (i != end) {
   if (
    (pid == -1 || pid == ring_buffer[i].trace.pid)
     && !ring_buffer[i].is_cleared) {
    user_buf[k].pid = ring_buffer[i].trace.pid;
    user_buf[k].state = ring_buffer[i].trace.state;
    strcpy(user_buf[k].comm,
     ring_buffer[i].trace.comm);
    k += 1;
   }
   i = (i + 1) % PSTRACE_BUF_SIZE;
  }
  if (
   (pid == -1 || pid == ring_buffer[i].trace.pid) &&
    !ring_buffer[i].is_cleared) {
   user_buf[k].pid = ring_buffer[i].trace.pid;
   user_buf[k].state = ring_buffer[i].trace.state;
   strcpy(user_buf[k].comm, ring_buffer[i].trace.comm);
  }
 } else
  k = 0;
 user_counter = tmp_buffer_counter;
 read_unlock(&ring_buffer_lock);
 if (copy_to_user(
  buf,
  user_buf,
  PSTRACE_BUF_SIZE * sizeof(struct pstrace)
 ))
  return -EFAULT;
 if (copy_to_user(counter, &user_counter, sizeof(long)))
  return -EFAULT;
 kfree(user_buf);
 return k;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 // acquire lock on tracing global structure
 int i;
 write_lock(&ring_buffer_lock);
 if (pid == -1) {
  // erase all data in the ring buffer
  for (i = 0; i < PSTRACE_BUF_SIZE; ++i)
   ring_buffer[i].is_cleared = true;
 } else {
  // find the position of pid and erase data
  for (i = 0; i < PSTRACE_BUF_SIZE; ++i) {
   if (ring_buffer[i].trace.pid == pid)
    ring_buffer[i].is_cleared = true;
  }
 }
 write_unlock(&ring_buffer_lock);
 return 0;
}