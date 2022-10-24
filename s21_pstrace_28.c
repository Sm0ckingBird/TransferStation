#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/rwlock_types.h>
#include <linux/pstrace.h>
#include <linux/rwlock.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
static DECLARE_WAIT_QUEUE_HEAD(wq);
static DEFINE_RWLOCK(pstrace_lock1);
static DEFINE_RWLOCK(pstrace_lock2);
static bool global_trace;
static long global_counter;
static struct pstrace_internal global_buf[PSTRACE_BUF_SIZE];
static bool pid_trace[MAX_NUMBER_PID];
static bool pstrace_check(pid_t pid)
{
 bool res = false;
 read_lock(&pstrace_lock1);
 if (global_trace || pid_trace[pid])
  res = true;
 return res;
}
static bool skip_buffer_add(struct task_struct *p)
{
 long counter;
 long itr = (global_counter % PSTRACE_BUF_SIZE) - 1;
 for (counter = 0; counter < PSTRACE_BUF_SIZE; counter++) {
  if (global_buf[itr].used &&
   global_buf[itr].pst.pid == p->pid &&
   global_buf[itr].pst.state == p->state) {
   return true;
  }
  itr = (itr + PSTRACE_BUF_SIZE - 1) % PSTRACE_BUF_SIZE;
 }
 return false;
}
static void pstrace_delete(pid_t pid)
{
 if (pid == -1) {
  write_lock(&pstrace_lock2);
  int i;
  for (i = 0; i < PSTRACE_BUF_SIZE; i++)
   global_buf[i].used = false;
  write_unlock(&pstrace_lock2);
 } else {
  write_lock(&pstrace_lock2);
  int i;
  for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
   if (pid == global_buf[i].pst.pid)
    global_buf[i].used = false;
  }
  write_unlock(&pstrace_lock2);
 }
}
void pstrace_add(struct task_struct *p)  //to be added in header file.
{
 long counter;
 if (pstrace_check(p->pid)) {
  if (!skip_buffer_add(p)) {
   write_lock(&pstrace_lock2);
   counter = global_counter % PSTRACE_BUF_SIZE;
   global_buf[counter].pst.pid = p->pid;
   if (p->exit_state == EXIT_DEAD || p->exit_state == EXIT_ZOMBIE)
    global_buf[counter].pst.state = p->exit_state;
   else
    global_buf[counter].pst.state = p->state;
   strcpy(global_buf[counter].pst.comm, p->comm);
   global_buf[counter].used = true;
   global_counter++;
   wake_up(&wq);
   write_unlock(&pstrace_lock2);
  }
 }
 read_unlock(&pstrace_lock1);
}
static void copy_elements(struct pstrace *k_buf, int res, int idx)
{
 k_buf[res].pid = global_buf[idx].pst.pid;
 k_buf[res].state = global_buf[idx].pst.state;
 strcpy(k_buf[res].comm, global_buf[idx].pst.comm);
}
int copy_buffer(struct pstrace *k_buf, pid_t pid, long *last_record, bool flag)
{
 int i, res = 0, dummy_cnt = 0;
 int temp_last = (int)(*last_record);
 *last_record = 0;
 if (flag) {
  for (i = 0; i <= temp_last; i++) {
   if ((pid == -1 || pid == global_buf[i].pst.pid) && global_buf[i].used) {
    copy_elements(k_buf, res, i);
    *last_record = i;
    res++;
   }
  }
 } else {
  int end = (int)(global_counter % PSTRACE_BUF_SIZE);
  int temp = global_counter - PSTRACE_BUF_SIZE - 1;
  for (i = end; i < PSTRACE_BUF_SIZE; i++) {
   if ((pid == -1 || pid == global_buf[i].pst.pid) && global_buf[i].used) {
    copy_elements(k_buf, res, i);
    *last_record = temp + dummy_cnt;
    res++;
   }
   dummy_cnt++;
  }
  for (i = 0 ; i < end; i++) {
   if ((pid == -1 || pid == global_buf[i].pst.pid) && global_buf[i].used) {
    copy_elements(k_buf, res, i);
    *last_record = temp + dummy_cnt;
    res++;
   }
   dummy_cnt++;
  }
 }
 return res;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 if (pid < -1 || pid > MAX_NUMBER_PID)
  return -EINVAL;
 write_lock(&pstrace_lock1);
 if (pid == -1)
  global_trace = true;
 else if (!pid_trace[pid])
  pid_trace[pid] = true;
 write_unlock(&pstrace_lock1);
 return 0; //what it should return?
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 if (pid < -1 || pid > MAX_NUMBER_PID)
  return -EINVAL;
 write_lock(&pstrace_lock1);
 if (pid == -1) {
  global_trace = false;
  int i;
  for (i = 0; i < MAX_NUMBER_PID; i++)
   pid_trace[i] = false;
 } else
  pid_trace[pid] = false;
 write_unlock(&pstrace_lock1);
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf, long __user *, counter)
{
 long k_counter, last_record;
 int cnt = 0;
 struct pstrace *k_buf;
 if (copy_from_user(&k_counter, counter, sizeof(long)) != 0)
  return -EFAULT;
 if (pid < -1)
  return -EINVAL;
 k_buf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (!k_buf)
  return -ENOMEM;
 if (k_counter <= 0) {
  read_lock(&pstrace_lock2);
  cnt = copy_buffer(k_buf, pid, &last_record, false);
  read_unlock(&pstrace_lock2);
 } else {
  read_lock(&pstrace_lock2);
  if ((k_counter >= global_counter - 2 * PSTRACE_BUF_SIZE - 1) && (k_counter <= global_counter - PSTRACE_BUF_SIZE - 1)) {
   last_record = (k_counter + PSTRACE_BUF_SIZE) % PSTRACE_BUF_SIZE;
   cnt = copy_buffer(k_buf, pid, &last_record, true);
  } else if (k_counter > global_counter - PSTRACE_BUF_SIZE - 1) {
   read_unlock(&pstrace_lock2);
   wait_event(wq, ((k_counter + PSTRACE_BUF_SIZE + 1) <= global_counter));
   read_lock(&pstrace_lock2);
   cnt = copy_buffer(k_buf, pid, &last_record, false);
  }
  read_unlock(&pstrace_lock2);
 }
 if (copy_to_user(counter, &last_record, sizeof(long)) != 0)
  return -EINVAL;
 if (copy_to_user(buf, k_buf, sizeof(struct pstrace) * cnt) != 0)
  return -EINVAL;
 kfree(k_buf);
 return cnt;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 if (pid < -1)
  return -EINVAL;
 pstrace_delete(pid);
 return 0;
}