// SPDX-License-Identifier: GPL-2.0
#define PSTRACE_BUF_SIZE 500
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/rwsem.h>
static struct pstrace ring_buffer[PSTRACE_BUF_SIZE];
static pid_t tracked_pids[PSTRACE_BUF_SIZE];
static pid_t disabled_pids[PSTRACE_BUF_SIZE];
DECLARE_WAIT_QUEUE_HEAD(wait);
static int total_pids;
static int disabled_num;
static int TRACK_ALL;
static int buffer_size;
static long total_process_count;
static int oldest_process;
static int empty_slot;
static int matches[PSTRACE_BUF_SIZE];
static DEFINE_SPINLOCK(pid_track_lock);
static DECLARE_RWSEM(ring_buffer_lock);
void print_ring_buffer(void)
{
 int i = 500;
 int j = 0;
 int k = 0;
 down_read(&ring_buffer_lock);
 if (i > buffer_size)
  i = buffer_size;
 for (j = 0; j < i; j++) {
  pr_debug("task state: %ld", ring_buffer[j].state);
  pr_debug("task pid: %ld",  ring_buffer[j].pid);
  char comm_cpy[17];
  for (k = 0; k < 16; k++)
   comm_cpy[k] = ring_buffer[j].comm[k];
  comm_cpy[16] = '\0';
  pr_debug("task name: %s", comm_cpy);
 }
 j = 0;
 pr_debug("pids currently tracked (max 500): %d", total_pids);
 for (j = 0; j < total_pids; j++)
  pr_debug("tracked pid: %d, j=%d", tracked_pids[j], j);
 up_read(&ring_buffer_lock);
}
void ring_buffer_search(pid_t pid)
{
 struct pstrace *curr = ring_buffer;
 //struct pstrace matches[PSTRACE_BUF_SIZE];
 int i = 0;
 int matches_i = 0;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  if (curr != NULL && curr->pid == pid) {
   matches[matches_i] = i;
   matches_i++;
  }
  curr++;
 }
 matches[matches_i] = -1;
 //If you want to do it this way you have to pass in a buffer
 //and return the size
 //return matches;
}
int pid_is_tracked(pid_t pid)
{
 int i = 0;
 if (TRACK_ALL == 1) {
  for (i = 0; i < disabled_num; i++) {
   if (disabled_pids[i] == pid)
    return 0;
  }
  return 1;
 }
 for (i = 0; i < total_pids; i++) {
  if (tracked_pids[i] == pid)
   return 1;
 }
 return 0;
}
int is_tracked_state(long state)
{
 if ((state & TASK_RUNNING) != 0 ||
 (state & TASK_INTERRUPTIBLE) != 0 ||
 (state & TASK_UNINTERRUPTIBLE) != 0 ||
 (state & __TASK_STOPPED != 0))
  return 1;
 return 0;
}
void add_to_buffer(struct task_struct *p)
{
 down_write(&ring_buffer_lock);
 if ((p->exit_state & EXIT_DEAD != 0) ||
 (p->exit_state & EXIT_ZOMBIE != 0)) {
  struct pstrace i;
  strncpy(i.comm, p->comm, 16);
  i.pid = p->pid;
  i.state = p->exit_state;
  if (buffer_size < 500) {
   ring_buffer[empty_slot] = i;
   empty_slot++;
   empty_slot = empty_slot % 500;
   buffer_size++;
   total_process_count++;
  } else {
   ring_buffer[oldest_process] = i;
   oldest_process++;
   oldest_process = oldest_process % 500;
   total_process_count++;
  }
 } else if ((is_tracked_state(p->state) == 1)) {
  struct pstrace i;
  strncpy(i.comm, p->comm, 16);
  i.pid = p->pid;
  i.state = p->state;
  if (buffer_size < 500) {
   ring_buffer[empty_slot] = i;
   empty_slot++;
   empty_slot = empty_slot % 500;
   buffer_size++;
   total_process_count++;
  } else {
   ring_buffer[oldest_process] = i;
   oldest_process++;
   oldest_process = oldest_process % 500;
   total_process_count++;
  }
 }
 up_write(&ring_buffer_lock);
}
void pstrace_add(struct task_struct *p)
{
 //ADD LOCKING, -1 CASE
 //Might need to add a task_struct lock here? Not sure though.
 spin_lock(&pid_track_lock);
 if (p != NULL && pid_is_tracked(p->pid) == 1) {
  spin_unlock(&pid_track_lock);
  //still need to add locking for the ring buffer structure.
  add_to_buffer(p);
  print_ring_buffer();
 } else {
  spin_unlock(&pid_track_lock);
 }
 wake_up(&wait);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 spin_lock(&pid_track_lock);
 int copied = 0;
 int i;
 pid_t temp_buf[PSTRACE_BUF_SIZE];
 if (TRACK_ALL == 1) {
  for (i = 0; i < disabled_num; i++) {
   if (disabled_pids[i] != pid)
    temp_buf[copied++] = pid;
  }
  disabled_num = copied;
  for (i = 0; i < copied; i++)
   disabled_pids[i] = temp_buf[i];
  spin_unlock(&pid_track_lock);
  return 0;
 }
 if (pid < -1 || find_task_by_vpid(pid) == NULL)
  return -EINVAL;
 if (pid == -1) {
  TRACK_ALL = 1;
  print_ring_buffer();
  spin_unlock(&pid_track_lock);
  return 0;
 }
 if (pid_is_tracked(pid) == 0) {
  if (total_pids == PSTRACE_BUF_SIZE) {
   spin_unlock(&pid_track_lock);
   return -ENOBUFS;
  }
  tracked_pids[total_pids] = pid;
  total_pids++;
 }
 print_ring_buffer();
 spin_unlock(&pid_track_lock);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 spin_lock(&pid_track_lock);
 pid_t temp_buff[PSTRACE_BUF_SIZE];
 int i = 0;
 int copied = 0;
 if (pid < -1 || find_task_by_vpid(pid) == NULL)
  return -EINVAL;
 if (pid == -1) {
  total_pids = 0;
  TRACK_ALL = 0;
  spin_unlock(&pid_track_lock);
  return 0;
 }
 if (TRACK_ALL == 1) {
  if (disabled_num == PSTRACE_BUF_SIZE)
   return -ENOBUFS;
  disabled_pids[disabled_num++] = pid;
  return 0;
 }
 for (i = 0; i < total_pids; i++) {
  if (tracked_pids[i] != pid) {
   temp_buff[copied] = tracked_pids[i];
   copied++;
  }
 }
 for (i = 0; i < copied; i++)
  tracked_pids[i] = temp_buff[i];
 total_pids = copied;
 print_ring_buffer();
 spin_unlock(&pid_track_lock);
 return 0;
}
SYSCALL_DEFINE3(pstrace_get,
  pid_t,
  pid,
  struct pstrace *,
  buf,
  int *,
  counter)
{
 //TODO ADD NON-BLOCKING LOCKING
 //DECLARE_WAIT_QUEUE_HEAD(wait);
 //CHECK IF CONDITION IS MET
 if (pid < -1 || find_task_by_vpid(pid) == NULL)
  return -EINVAL;
 if (*counter + 500 >= total_process_count - 500 &&
   *counter + 500 <= total_process_count + 500) {
  int targ_count = 0;
  int targ_i = oldest_process;
  struct pstrace res[500];
  down_read(&ring_buffer_lock);
  while (targ_i != empty_slot) {
   if (ring_buffer[targ_i].pid == pid) {
    res[targ_count] = ring_buffer[targ_i];
    targ_count++;
   }
   targ_i++;
   targ_i = targ_i % 500;
  }
  up_read(&ring_buffer_lock);
  copy_to_user(buf, res, targ_count *
    sizeof(struct pstrace));
 } else if (*counter + 500 > total_process_count) {
  wait_event(wait, total_process_count == 500 + *counter);
 }
 return 0;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 if (pid < -1 || find_task_by_vpid(pid) == NULL)
  return -EINVAL;
 wake_up(&wait);
 //Wake up all pstrace_get processes
 down_write(&ring_buffer_lock);
 //get spin lock for buffer
 oldest_process = 0;
 buffer_size = 0;
 empty_slot = 0;
 //empty buffer
 up_write(&ring_buffer_lock);
 //unlock buffer
 //TODO ADD NON-BLOCKING LOCKING
 return 0;
}