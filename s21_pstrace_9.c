/*
 * pstrace.c
 * HW3
 *
 */
#include <linux/pstrace.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500
DEFINE_SPINLOCK(lock);
unsigned long flags;
DECLARE_WAIT_QUEUE_HEAD(q);
struct pstrace ringBuf[PSTRACE_BUF_SIZE];
struct track *follow[PSTRACE_BUF_SIZE];
struct pstrace holder[PSTRACE_BUF_SIZE];
int eventual[PSTRACE_BUF_SIZE];
int position;
int count_all;
int inited;
int waiting;
int writer;
void pstrace_add(struct task_struct *p)
{
 int i = 0;
 int tracking = 0;
 int place;
 while (i < PSTRACE_BUF_SIZE) {
  if (follow[i] && follow[i]->pid == p->pid)
   tracking = 1;
  i++;
 }
 if (tracking == 1 || count_all == 1) {
  int j = 0;
  spin_lock_irqsave(&lock, flags);
  place = position % PSTRACE_BUF_SIZE;
  position++;
  ringBuf[place].pid = p->pid;
  if (p->exit_state != 0)
   ringBuf[place].state = p->exit_state;
  else
   ringBuf[place].state = p->state;
  if (p->comm) {
   while (j < sizeof(p->comm)) {
    ringBuf[place].comm[j] = p->comm[j];
    j++;
   }
  } else
   ringBuf[place].comm[0] = '\0';
  if (eventual[waiting] == position) {
   int c = 0;
   while (c < PSTRACE_BUF_SIZE) {
    holder[c] = ringBuf[c];
    c++;
   }
   wake_up(&q);
   waiting++;
  }
  spin_unlock_irqrestore(&lock, flags);
 }
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid) {
 int first = -1;
 int seen = 0;
 int i = 0;
 if (inited == 0) {
  int z = 0;
  while (z < PSTRACE_BUF_SIZE) {
   ringBuf[z].pid = -1;
   z++;
  }
  inited = 1;
 }
 if (pid == -1) {
  count_all = 1;
  return 0;
 }
 while (i < PSTRACE_BUF_SIZE) {
  if (!follow[i]) {
   first = i;
   break;
  } else if (follow[i]->pid == pid) {
   seen = 1;
   break;
  }
  i++;
 }
 if (first == -1)
  return -ENOBUFS;
 if (seen == 0) {
  struct track *tmp = kmalloc(sizeof(struct track), GFP_KERNEL);
  if (!tmp)
   return -ENOMEM;
  tmp->pid = pid;
  follow[first] = tmp;
 }
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid) {
 int i = 0;
 if (pid == -1) {
  count_all = 0;
  return 0;
 }
 while (i < PSTRACE_BUF_SIZE) {
  if (follow[i] && follow[i]->pid == pid) {
   kfree(follow[i]);
   follow[i] = NULL;
   break;
  }
  i++;
 }
 return ringBuf[0].pid;
}
/* pstrace_get */
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
  long __user *, counter) {
 long count;
 int i;
 long ccounter;
 struct pstrace *newBuf;
 struct pstrace newPstrace;
 int j = 0;
 if (!buf || !counter)
  return -EINVAL;
 if (copy_from_user(&ccounter, counter, sizeof(long)))
  return -EFAULT;
 if (ccounter > 0) {
  DEFINE_WAIT(wait);
  eventual[writer] = ccounter+PSTRACE_BUF_SIZE;
  writer++;
  add_wait_queue(&q, &wait);
  while ((ccounter+PSTRACE_BUF_SIZE) > position) {
   prepare_to_wait(&q, &wait, TASK_INTERRUPTIBLE);
   schedule();
  }
  finish_wait(&q, &wait);
 } else {
  int c = 0;
  while (c < PSTRACE_BUF_SIZE) {
   holder[c] = ringBuf[c];
   c++;
  }
 }
 count = 0;
 i = 0;
 newBuf = kmalloc_array(PSTRACE_BUF_SIZE,
   sizeof(struct pstrace), GFP_KERNEL);
 if (!newBuf)
  return -ENOMEM;
 if (pid == -1) {
  while (i < PSTRACE_BUF_SIZE) {
   if (holder[i].pid != -1) {
    newPstrace.pid = holder[i].pid;
    newPstrace.state = holder[i].state;
    if (holder[i].comm) {
     while (j < sizeof(holder[i].comm)) {
      newPstrace.comm[j] =
       holder[i].comm[j];
      j++;
     }
    } else
     newPstrace.comm[0] = '\0';
    newBuf[count] = newPstrace;
    count++;
   }
   i++;
  }
 } else {
  while (i < PSTRACE_BUF_SIZE) {
   if (holder[i].pid == pid) {
    newPstrace.pid = holder[i].pid;
    newPstrace.state = holder[i].state;
    if (holder[i].comm) {
     while (j < sizeof(holder[i].comm)) {
      newPstrace.comm[j] =
       holder[i].comm[j];
      j++;
     }
    } else
     newPstrace.comm[0] = '\0';
    newBuf[count] = newPstrace;
    count++;
   }
   i++;
   }
  }
 if (copy_to_user(buf, newBuf, sizeof(struct pstrace)*count)) {
  kfree(newBuf);
  return -EFAULT;
 }
 kfree(newBuf);
 return count;
}
/* pstrace_clear */
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid) {
 int i = 0;
 if (pid == -1) {
  while (i < PSTRACE_BUF_SIZE) {
   ringBuf[i].pid = -1;
   i++;
  }
 } else {
  while (i < PSTRACE_BUF_SIZE) {
   if (ringBuf[i].pid == pid)
    ringBuf[i].pid = -1;
   i++;
  }
 }
 return 0;
}