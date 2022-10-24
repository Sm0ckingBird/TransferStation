#include <linux/pstrace.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/rwlock.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/irqflags.h>
static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static DEFINE_RWLOCK(pstracing_rwlock);
static struct ring_buf ring_buf;
static struct pstrace_buf enable_list;
static struct pstrace_buf disable_list;
int enable_all;
int disable_all;
static void create_pstrace(struct task_struct *p)
{
 get_task_comm(ring_buf.buf[ring_buf.end].comm, p);
 ring_buf.buf[ring_buf.end].pid = task_pid_nr(p);
 if (p->exit_state & (EXIT_TRACE))
  ring_buf.buf[ring_buf.end].state = p->exit_state;
 else
  ring_buf.buf[ring_buf.end].state = p->state & TASK_REPORT;
 ring_buf.end++;
 ring_buf.count++;
}
int find_p_in_tracing(pid_t pid, struct pstrace_buf *pstracing)
{
 int i;
 for (i = 0; i < pstracing->count; i++) {
  if (pstracing->buf[i] == pid)
   return i;
 }
 return -1;
}
static long find_last_available_tracing(struct pstrace_buf *pstracing)
{
 return pstracing->count;
}
static long remove_pid_from_buf(pid_t pid, struct pstrace_buf *pstracing)
{
 long error = 0;
 int pos;
 int last;
 pos = find_p_in_tracing(pid, pstracing);
 if (pos == -1)
  return error;
 last = find_last_available_tracing(pstracing);
 if (last > 0) {
  pstracing->buf[pos] = pstracing->buf[last-1];
  pstracing->buf[last-1] = 0;
  pstracing->count--;
 } else
  error = -1; //Not sure what error to return
 return error;
}
static long add_pid_into_buf(pid_t pid, struct pstrace_buf *pstracing)
{
 long pos;
 long error = 0;
 struct task_struct *pid_task = find_get_task_by_vpid(pid);
 if (!pid_task)
  return -ESRCH;
 if (find_p_in_tracing(pid, pstracing) > -1)
  return error;
 pos = find_last_available_tracing(pstracing);
 pstracing->buf[pos] = pid;
 pstracing->count++;
 return error;
}
/* Handles enabling or disabling of a single pid
 * pid: PID to insert into the pstrace_buf
 * all: Either disable all or enable all
 * remove_from: pstrace_buf to remove pid from
 * add_to: pstrace_buf to add pid into
 *
 * So if we want to disable a pid, we would call
 * pstrace_do_one(pid, disable_all, &enable_list, &disable_list)
 */
static long pstrace_do_one(pid_t pid, int all,
   struct pstrace_buf *remove_from,
   struct pstrace_buf *add_to)
{
 long error = 0;
 if (all) {
  error = remove_pid_from_buf(pid, remove_from);
 } else {
  if (add_to->count == PSTRACE_BUF_SIZE)
   return -1;
  error = remove_pid_from_buf(pid, remove_from);
  if (error)
   return error;
  error = add_pid_into_buf(pid, add_to);
 }
 return error;
}
void pstrace_add(struct task_struct *p)
{
 int enable_pos;
 int disable_pos;
 int flag;
 unsigned long lock_flags;
 enable_pos = find_p_in_tracing(p->pid, &enable_list);
 disable_pos = find_p_in_tracing(p->pid, &disable_list);
 if ((enable_all && disable_pos == -1) || enable_pos > -1) {
  flag = irqs_disabled();
  write_lock_irqsave(&pstracing_rwlock, lock_flags);
  if (ring_buf.end == PSTRACE_BUF_SIZE)
   ring_buf.end = 0;
  create_pstrace(p);
  if (flag)
   wake_up(&wait_queue);
  write_unlock_irqrestore(&pstracing_rwlock, lock_flags);
 }
}
static long pstrace_enable_one(pid_t pid)
{
 return pstrace_do_one(pid, enable_all, &disable_list, &enable_list);
}
long pstrace_enable(pid_t pid)
{
 long error = 0;
 write_lock(&pstracing_rwlock);
 if (pid == -1) {
  enable_all = 1;
  disable_all = 0;
 } else {
  error = pstrace_enable_one(pid);
 }
 write_unlock(&pstracing_rwlock);
 return error;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 long error;
 error = pstrace_enable(pid);
   return error;
};
static long pstrace_disable_one(pid_t pid)
{
 return pstrace_do_one(pid, disable_all, &enable_list, &disable_list);
}
long pstrace_disable(pid_t pid)
{
 long error = 0;
 write_lock(&pstracing_rwlock);
 if (pid == -1) {
  disable_all = 1;
  enable_all = 0;
 } else
  pstrace_disable_one(pid);
 write_unlock(&pstracing_rwlock);
 return error;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 long error;
 error = pstrace_disable(pid);
 return error;
}
long pstrace_get(pid_t pid, struct pstrace *buf, long *counter);
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter)
{
 long maxCount = PSTRACE_BUF_SIZE;
 struct pstrace *myBuf;
 long *kCounter = &maxCount;
 int max_iter;
 int size;
 int i;
 int j;
 int k;
 int enable_pos;
 int disable_pos;
 long presentRingCount;
 if (counter) {
  if (copy_from_user(kCounter, counter, sizeof(long)))
   return -EFAULT;
 }
 size = PSTRACE_BUF_SIZE * sizeof(struct pstrace);
 myBuf = kmalloc(size, GFP_KERNEL);
 j = 0;
 read_lock_irq(&pstracing_rwlock);
 if (*kCounter > 0) {
  if (ring_buf.count-PSTRACE_BUF_SIZE > (*kCounter+PSTRACE_BUF_SIZE)) {
   *kCounter = ring_buf.count;
   goto send_resp;
  } else {
   if (ring_buf.count-PSTRACE_BUF_SIZE > *kCounter) {
    i = ring_buf.end;
    max_iter = (*kCounter + PSTRACE_BUF_SIZE) - (ring_buf.count-PSTRACE_BUF_SIZE);
    goto process_wait;
   } else {
    i = ring_buf.end;
    max_iter = PSTRACE_BUF_SIZE;
    goto process_wait;
   }
  }
 } else {
  presentRingCount = ring_buf.end;
  if (pid == -1) {
   if (ring_buf.count <= PSTRACE_BUF_SIZE) {
    while (j < presentRingCount) {
     strcpy(myBuf[j].comm, ring_buf.buf[j].comm);
     myBuf[j].pid = ring_buf.buf[j].pid;
     myBuf[j].state = ring_buf.buf[j].state;
     j++;
    }
   } else {
    j = presentRingCount;
    while (j < PSTRACE_BUF_SIZE) {
     strcpy(myBuf[j].comm, ring_buf.buf[j].comm);
     myBuf[j].pid = ring_buf.buf[j].pid;
     myBuf[j].state = ring_buf.buf[j].state;
     j++;
     if (j == PSTRACE_BUF_SIZE)
      j = 0;
    }
   }
  } else {
   if (ring_buf.count <= PSTRACE_BUF_SIZE) {
    if (find_p_in_tracing(pid, &enable_list) > -1) {
     k = 0;
     while (j < presentRingCount) {
      if (ring_buf.buf[j].pid == pid) {
       strcpy(myBuf[k].comm, ring_buf.buf[j].comm);
       myBuf[k].pid = ring_buf.buf[j].pid;
       myBuf[k].state = ring_buf.buf[j].state;
       k++;
      }
      j++;
     }
    }
   } else {
    i = presentRingCount;
    enable_pos = find_p_in_tracing(pid, &enable_list);
    disable_pos = find_p_in_tracing(pid, &disable_list);
    if ((enable_all && disable_pos == -1) || enable_pos > -1) {
     k = 0;
     while (j < 500) {
      if (ring_buf.buf[i].pid == pid) {
       strcpy(myBuf[k].comm, ring_buf.buf[i].comm);
       myBuf[k].pid = ring_buf.buf[i].pid;
       myBuf[k].state = ring_buf.buf[i].state;
       k++;
      }
      i++;
      j++;
      if (i == PSTRACE_BUF_SIZE)
       i = 0;
     }
    }
   }
  }
 }
 goto send_resp;
 process_wait:
  wait_event(wait_queue, ring_buf.count >= (*kCounter + PSTRACE_BUF_SIZE));
  if (pid == -1) {
   j = 0;
   while (j < max_iter) {
    strcpy(myBuf[i].comm, ring_buf.buf[i].comm);
    myBuf[i].pid = ring_buf.buf[i].pid;
    myBuf[i].state = ring_buf.buf[i].state;
    i++;
    j++;
    if (i == PSTRACE_BUF_SIZE)
     i = 0;
   }
  } else {
   enable_pos = find_p_in_tracing(pid, &enable_list);
   disable_pos = find_p_in_tracing(pid, &disable_list);
   if ((enable_all && disable_pos == -1) || enable_pos > -1) {
    k = 0;
    while (j < max_iter) {
     if (ring_buf.buf[i].pid == pid) {
      strcpy(myBuf[k].comm, ring_buf.buf[i].comm);
      myBuf[k].pid = ring_buf.buf[i].pid;
      myBuf[k].state = ring_buf.buf[i].state;
      k++;
     }
     i++;
     j++;
     if (i == PSTRACE_BUF_SIZE)
      i = 0;
    }
   }
  }
  *kCounter = *kCounter + PSTRACE_BUF_SIZE;
  goto send_resp;
 send_resp:
  read_unlock_irq(&pstracing_rwlock);
  if (copy_to_user(buf, myBuf, size))
   return -EFAULT;
  if (copy_to_user(counter, kCounter, sizeof(long)))
   return -EFAULT;
  kfree(myBuf);
  return 0;
}
/*
static long remove_record(long idx)
{
 if (idx >= ring_buf.end)
  return -1;
 while(idx < ring_buf.end) {
  ring_buf.buf[idx] = ring_buf.buf[idx+1];
  idx = idx + 1 
 }
 ring_buf.end--;
}
    static int del_record_buffer(pid_t pid)
{
 int total = 0;
 long i = 0;
        while (i < ring_buf.end) {
  if (ring_buf.buf[i].pid = pid) {
   remove_record(i);
   total++;
  }
  i++;
 }
 return total;
}
void del_all_buffer()
{
 ring_buf.end = 0;
}
long pstrace_clear(pid_t pid);
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 unsigned long lock_flags;
 write_lock_irqsave(&pstracing_rwlock, lock_flags);
 if (pid >= 0) {
  if (del_record_buffer(pid) <= 0) {
   write_lock_irqsave(&pstracing_rwlock, lock_flags);
   return -EFAULT;
  }
  write_lock_irqsave(&pstracing_rwlock, lock_flags);
 }
 else if (pid == -1) {
  del_all_buffer();
  wake_up(&wait_queue);
 }
} */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 return 0;
}