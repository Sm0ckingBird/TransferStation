/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/pstrace.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/errno.h>
#include <linux/sys.h>
#include <linux/wait.h>
#include <linux/irqflags.h>
#include <linux/spinlock.h>
#define rinc(x, y) (((x)+(y)+510)%510)
struct pstrace rb[510];
EXPORT_SYMBOL(rb);
struct ringbuffer_info ring = {0, 0, 0, 0, 0, -2};
EXPORT_SYMBOL(ring);
struct trlist {
 /* To see if it is tracing all processes */
 int enable_all;
 /*
  * if enable_all == 1: count the number of disable processes
  * if enable_all == 0: count the number of enable processes
  */
 int counter;
 pid_t list[500];
};
struct trlist ptlist;
EXPORT_SYMBOL(ptlist);
DEFINE_RWLOCK(buf_lock);
EXPORT_SYMBOL(buf_lock);
DEFINE_RWLOCK(trlock);
EXPORT_SYMBOL(trlock);
int recur_flag;
EXPORT_SYMBOL(recur_flag);
DEFINE_SPINLOCK(recur_lock);
EXPORT_SYMBOL(recur_lock);
DECLARE_WAIT_QUEUE_HEAD(ring_wait);
EXPORT_SYMBOL(ring_wait);
void pstrace_add(struct task_struct *p)
{
 pid_t pid;
 pid = task_pid_nr(p);
 read_lock(&trlock);
 if (!ptlist.enable_all && check_if_in_list(pid)) {
  read_unlock(&trlock);
  add_to_ring_buffer(pid, p);
  if (!recur_flag) {
   spin_lock(&recur_lock);
   recur_flag = 1;
   wake_up_all(&ring_wait);
   recur_flag = 0;
   spin_unlock(&recur_lock);
  }
 } else if (ptlist.enable_all && !check_if_in_list(pid)) {
  read_unlock(&trlock);
  add_to_ring_buffer(pid, p);
  if (!recur_flag) {
   spin_lock(&recur_lock);
   recur_flag = 1;
   wake_up_all(&ring_wait);
   recur_flag = 0;
   spin_unlock(&recur_lock);
  }
 } else {
  read_unlock(&trlock);
 }
}
EXPORT_SYMBOL(pstrace_add);
static int check_if_in_list(pid_t pid)
{
 int idx;
 if (ptlist.counter == 0)
  return 0;
 for (idx = 0; idx < PSTRACE_BUF_SIZE; idx++) {
  if ((pid == 0 && ptlist.list[idx] == -1) ||
  (pid != 0 && ptlist.list[idx] == pid)) {
   return 1;
  }
 }
 return 0;
}
static void clean_list(void)
{
 int idx;
 for (idx = 0; idx < PSTRACE_BUF_SIZE; idx++)
  ptlist.list[idx] = 0;
}
static inline void add_to(pid_t pid, int idx)
{
 if (pid == 0)
  ptlist.list[idx] = -1;
 else
  ptlist.list[idx] = pid;
}
static void add_to_list(pid_t pid)
{
 int idx;
 for (idx = 0; idx < PSTRACE_BUF_SIZE; idx++) {
  if (ptlist.list[idx] == 0) {
   add_to(pid, idx);
   ptlist.counter++;
   goto end;
  }
 }
end:
 return;
}
static void remove_from_list(pid_t pid)
{
 int idx;
 for (idx = 0; idx < PSTRACE_BUF_SIZE; idx++) {
  if ((pid == 0 && ptlist.list[idx] == -1) ||
  (pid != 0 && ptlist.list[idx] == pid)) {
   ptlist.list[idx] = 0;
   ptlist.counter--;
   goto end;
  }
 }
end:
 return;
}
SYSCALL_DEFINE1(pstrace_enable,
  pid_t, pid)
{
 struct task_struct *ts;
 /* if pid == -1, we should trace all processes */
 if (pid == -1) {
  write_lock(&trlock);
  clean_list();
  ptlist.enable_all = 1;
  ptlist.counter = 0;
  write_unlock(&trlock);
  return 0;
 }
 /* if the pid is invalid, return errno */
 ts = get_root(pid);
 if (ts == NULL)
  return -EINVAL;
 if (ptlist.enable_all == 1) {
  write_lock(&trlock);
  remove_from_list(pid);
  write_unlock(&trlock);
  return 0;
 }
 read_lock(&trlock);
 if (check_if_in_list(pid)) {
  read_unlock(&trlock);
  return 0;
 }
 if (ptlist.counter > PSTRACE_BUF_SIZE) {
  read_unlock(&trlock);
  return -EINVAL;
 }
 read_unlock(&trlock);
 write_lock(&trlock);
 add_to_list(pid);
 write_unlock(&trlock);
 return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
 */
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 struct task_struct *ts;
 /* if pid is -1, disable all processes */
 if (pid == -1) {
  write_lock(&trlock);
  clean_list();
  ptlist.enable_all = 0;
  ptlist.counter = 0;
  write_unlock(&trlock);
  return 0;
 }
 ts = get_root(pid);
 if (ts == NULL)
  return -ESRCH;
 read_lock(&trlock);
 if (ptlist.enable_all == 1) {
  /* current list and counter are for disable */
  /* check if the pid is already in disable list */
  if (check_if_in_list(pid)) {
   read_unlock(&trlock);
   return 0;
  }
  if (ptlist.counter > PSTRACE_BUF_SIZE) {
   read_unlock(&trlock);
   return -EINVAL;
  }
  read_unlock(&trlock);
  write_lock(&trlock);
  add_to_list(pid);
  write_unlock(&trlock);
 } else {
  /* current list and counter are for enable */
  read_unlock(&trlock);
  write_lock(&trlock);
  remove_from_list(pid);
  write_unlock(&trlock);
 }
 return 0;
}
static inline long copy_to_kbuf(struct pstrace *kbuf,
    pid_t pid,
    long st, long ed, long num,
    long lctr, long rctr)
{
 bool copy_all = false;
 long idx, j, k;
 idx = 0; /* also work as a number counter */
 if (pid == -1)
  copy_all = true;
 for (k = 0; k < num; k++) {
  j = rinc(st, k);
  if ((copy_all || rb[j].pid == pid) &&
  rb[j].counter <= rctr && rb[j].counter >= lctr){
   kbuf[idx].pid = rb[j].pid;
   kbuf[idx].state = rb[j].state;
   kbuf[idx].counter = rb[j].counter;
   strcpy(kbuf[idx].comm, rb[j].comm);
   idx++;
  }
 }
 return idx;
}
static inline void wait_buffer_or_clear(long kcounter, pid_t pid)
{
 DEFINE_WAIT(__wait);
 int local_flag;
 local_flag = 0;
 while (ring.clear_pid != -1 && ring.clear_pid != pid &&
 ring.ed_ctr < kcounter + 500) {
  read_unlock(&buf_lock);
  if (!recur_flag) {
   local_flag = 1;
   spin_lock(&recur_lock);
   recur_flag = 1;
  }
  prepare_to_wait(&ring_wait, &__wait, TASK_UNINTERRUPTIBLE);
  if (local_flag) {
   recur_flag = 0;
   spin_unlock(&recur_lock);
  }
  schedule();
  read_lock(&buf_lock);
 }
 read_unlock(&buf_lock);
 finish_wait(&ring_wait, &__wait);
 read_lock(&buf_lock);
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
SYSCALL_DEFINE3(pstrace_get,
  pid_t, pid,
  struct pstrace __user *, buf,
  long __user *, counter)
{
 long kcounter, total, num, st, ed;
 size_t size;
 struct pstrace *kbuf;
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 total = 0;
 size = 1 * sizeof(struct pstrace);
 kbuf = kmalloc(500 * size, GFP_KERNEL);
 if (kbuf == NULL)
  return -ENOMEM;
 if (kcounter <= 0) {
  read_lock(&buf_lock);
  st = ring.st;
  ed = ring.ed;
  num = ring.sum;
  if (unlikely(num == 0)) {
   read_unlock(&buf_lock);
   kfree(kbuf);
   return total;
  }
  total = copy_to_kbuf(kbuf, pid, st, ed, num,
     ring.st_ctr, ring.ed_ctr);
  read_unlock(&buf_lock);
  if (total > 0)
   kcounter = kbuf[total-1].counter;
  else
   kcounter = -1;
  if (copy_to_user(buf, kbuf, total * size) || put_user(kcounter,
  counter)) {
   kfree(kbuf);
   return -EFAULT;
  }
  kfree(kbuf);
  return total;
 }
 /* kcounter > 0 */
 read_lock(&buf_lock);
 if (kcounter + 500 > ring.ed_ctr)
  wait_buffer_or_clear(kcounter, pid);
 if (kcounter + 500 < ring.st_ctr) {
  read_unlock(&buf_lock);
  kfree(kbuf);
  return total;
 }
 st = ring.st;
 ed = ring.ed;
 num = ring.sum;
 total = copy_to_kbuf(kbuf, pid, st, ed, num, kcounter+1, kcounter+500);
 read_unlock(&buf_lock);
 if (total > 0)
  kcounter = kbuf[total-1].counter;
 else
  kcounter = -1;
 if (copy_to_user(buf, kbuf, total * size) || put_user(kcounter,
 counter)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return total;
}
void add_to_ring_buffer(pid_t pid, struct task_struct *p)
{
 long idx;
 write_lock(&buf_lock);
 if (ring.sum == 500) { /* buffer is full */
  ring.st = rinc(ring.st, 1);
  ring.st_ctr = rb[ring.st].counter;
 } else {
  ring.sum = rinc(ring.sum, 1);
 }
 idx = ring.ed;
 ring.ed = rinc(ring.ed, 1);
 /* update counters */
 ring.ed_ctr++; /* starts at 1? */
 rb[idx].counter = ring.ed_ctr;
 if (unlikely(ring.sum == 1))
  ring.st_ctr = ring.ed_ctr;
 __get_task_comm(rb[idx].comm, sizeof(rb[idx].comm), p);
 rb[idx].pid = pid;
 if (p->state == TASK_DEAD)
  rb[idx].state = p->exit_state;
 else
  rb[idx].state = p->state;
 write_unlock(&buf_lock);
}
/* Move ring buffer item from src to dst */
static inline void buf_move(long dst, long src)
{
 if (dst != src) {
  rb[dst].state = rb[src].state;
  rb[dst].pid = rb[src].pid;
  rb[dst].counter = rb[src].counter;
  strcpy(rb[dst].comm, rb[src].comm);
 }
}
static inline void buf_clear(pid_t pid)
{
 long idx, i, j, osum;
 if (ring.sum == 0)
  return;
 if (pid == -1) { /* clear all*/
  ring.sum = 0;
  ring.ed = ring.st;
  return;
 }
 /* clear specific pid */
 osum = ring.sum;
 idx = ring.st;
 for (i = 0; i < osum; i++) {
  j = rinc(ring.st, i);
  if (rb[j].pid != pid) {
   buf_move(idx, j);
   idx = rinc(idx, 1);
  } else {
   ring.sum--;
  }
 }
 ring.ed = idx;
 ring.st = rinc(idx, (-1)*ring.sum);
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
 write_lock(&buf_lock);
 ring.clear_pid = pid;
 write_unlock(&buf_lock);
 wake_up_all(&ring_wait);
 write_lock(&buf_lock);
 buf_clear(pid);
 ring.clear_pid = -2;
 write_unlock(&buf_lock);
 return 0;
}