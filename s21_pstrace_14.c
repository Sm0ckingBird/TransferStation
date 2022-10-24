#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/pstrace.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/slab.h>
#define PSTRACE_BUF_SIZE 500 /* The maximum size of the ring buffer */
struct gets_node {
 long start_counter;
 long target_counter;
 long end;
 pid_t pid;
 int is_complete;
 int num_copied;
 struct pstrace buf[PSTRACE_BUF_SIZE];
 struct gets_node *prev;
 struct gets_node *next;
};
int traced_p_buf[PSTRACE_BUF_SIZE]; /* Track traced processes */
struct pstrace ring_buf[PSTRACE_BUF_SIZE]; /* Track state changes */
int traced_count;
int states_count;
int traced_incl = 1;
int firstTimeFlag = 1;
int recursionFlag;
DEFINE_SPINLOCK(ring_lock); /* initialize ring_lock */
DEFINE_SPINLOCK(traced_p_lock); /* initialize traced_p_lock */
DEFINE_SPINLOCK(list_lock); /* initialize list_lock */
DEFINE_SPINLOCK(recursion_lock); /* initialize lock for recursion flag */
DECLARE_WAIT_QUEUE_HEAD(ptrace_gets_q); /* initialize wait_queue_head */
unsigned long flags;
struct gets_node *gets_node_head;
struct gets_node *gets_node_tail;
void add_to_ptrace_tail(struct gets_node *current_node)
{
 if (gets_node_head == NULL || gets_node_tail == NULL) {
  gets_node_head = current_node;
  gets_node_tail = current_node;
  return;
 }
 gets_node_tail->next = current_node;
 current_node->prev = gets_node_tail;
 gets_node_tail = current_node;
}
void remove_from_ptrace_list(struct gets_node *current_node)
{
 if (current_node == gets_node_head)
  gets_node_head = current_node->next;
 if (current_node == gets_node_tail)
  gets_node_tail = current_node->prev;
 if (current_node->next != NULL)
  current_node->next->prev = current_node->prev;
 if (current_node->prev != NULL)
  current_node->prev->next = current_node->next;
}
void set_recursion_flag(int val)
{
 spin_lock_irqsave(&recursion_lock, flags);
 recursionFlag = val;
 spin_unlock_irqrestore(&recursion_lock, flags);
}
int get_recursion_flag(void)
{
 int x;
 spin_lock_irqsave(&recursion_lock, flags);
 x = recursionFlag;
 spin_unlock_irqrestore(&recursion_lock, flags);
 return x;
}
void set_to_val(int *arr, int max, int val)
{
 int i = 0;
 while (i < max) {
  arr[i] = val;
  i++;
 }
}
void set_first_time(void)
{
 spin_lock_irqsave(&traced_p_lock, flags);
 if (firstTimeFlag == 1) {
  set_to_val(traced_p_buf, PSTRACE_BUF_SIZE, -1);
  firstTimeFlag = 0;
 }
 spin_unlock_irqrestore(&traced_p_lock, flags);
}
int is_valid_pid(pid_t pid)
{
 if (pid == -1)
  return 1;
 return find_task_by_vpid(pid) != NULL;
}
int copy_buffer(struct pstrace *kbuf, pid_t pid, int start_index, int max)
{
 int i, kb_index, rb_index;
 if (max <= 0)
  return 0;
 i = kb_index = 0;
 while (i < max) {
  rb_index = (start_index + i) % PSTRACE_BUF_SIZE;
  i++;
  if (ring_buf[rb_index].pid != pid && pid != -1)
   continue;
  if (ring_buf[rb_index].pid == -1)
   continue;
  kbuf[kb_index].count = ring_buf[rb_index].count;
  kbuf[kb_index].pid = ring_buf[rb_index].pid;
  kbuf[kb_index].state = ring_buf[rb_index].state;
  strncpy(kbuf[kb_index].comm, ring_buf[rb_index].comm, 16);
  kb_index++;
 }
 return kb_index;
}
int in_arr(int *arr, int max, int val)
{
 int i = 0;
 while (i < max) {
  if (arr[i] == val)
   return 1;
  i++;
 }
 return 0;
}
/* Add a record of the state change into the ring buffer. */
void pstrace_add(struct task_struct *p)
{
 int is_in_buf, rb_index, si, has_wake_up;
 struct gets_node *cnode;
 if (p == NULL)
  WARN_ON(true);
 spin_lock_irqsave(&ring_lock, flags);
 spin_lock_irqsave(&traced_p_lock, flags);
 is_in_buf = in_arr(traced_p_buf, PSTRACE_BUF_SIZE, (int) p->pid);
 if ((traced_incl == 1 && !is_in_buf)
   || (traced_incl == 0 && is_in_buf)) {
  spin_unlock_irqrestore(&traced_p_lock, flags);
  spin_unlock_irqrestore(&ring_lock, flags);
  return;
 }
 spin_unlock_irqrestore(&traced_p_lock, flags);
 rb_index = states_count % PSTRACE_BUF_SIZE;
 strncpy(ring_buf[rb_index].comm, p->comm, 16);
 ring_buf[rb_index].pid = p->pid;
 ring_buf[rb_index].count = states_count;
 if (p->exit_state != 0)
  ring_buf[rb_index].state = p->exit_state;
 else
  ring_buf[rb_index].state = p->state;
 spin_lock_irqsave(&list_lock, flags);
 has_wake_up = 0;
 cnode = gets_node_head;
 while (cnode != NULL) {
  if (cnode->target_counter == states_count) {
   si = (cnode->start_counter+1) % PSTRACE_BUF_SIZE;
   cnode->num_copied = copy_buffer(cnode->buf,
   cnode->pid, si, PSTRACE_BUF_SIZE);
   cnode->end = states_count;
   cnode->is_complete = 1;
   has_wake_up = 1;
  }
  cnode = cnode->next;
 }
 spin_unlock_irqrestore(&list_lock, flags);
 states_count = states_count + 1;
 spin_unlock_irqrestore(&ring_lock, flags);
 if (has_wake_up && !get_recursion_flag()) {
  set_recursion_flag(1);
  wake_up_all(&ptrace_gets_q);
  set_recursion_flag(0);
 }
}
int replace_first_val(int *arr, int max, int before, int after)
{
 int i = 0;
 while (i < max) {
  if (arr[i] == before) {
   arr[i] = after;
   return 0;
  }
  i++;
 }
 return -1;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 /* Add pid to traced_p_buf */
 set_first_time();
 // Invalid PID
 if (!is_valid_pid(pid))
  return -ESRCH;
 spin_lock_irqsave(&traced_p_lock, flags);
 // Enable tracing all
 if (pid == -1) {
  traced_incl = 0;
  set_to_val(traced_p_buf, PSTRACE_BUF_SIZE, -1);
  traced_count = 0;
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0;
 }
 // We are tracking pids to exclude
 if (traced_incl == 0) {
  if (!replace_first_val(traced_p_buf,
      PSTRACE_BUF_SIZE, pid, -1))
   traced_count--;
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0; /* MAKE RIGHT ERROR CODE*/
 }
 // PID limit reached
 if (traced_count == PSTRACE_BUF_SIZE) {
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return -ENOMEM;
 }
 if (in_arr(traced_p_buf, PSTRACE_BUF_SIZE, pid)) {
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0;
 }
 if (!replace_first_val(traced_p_buf, PSTRACE_BUF_SIZE, -1, pid)) {
  traced_count++;
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0;
 }
 spin_unlock_irqrestore(&traced_p_lock, flags);
 return -ENOMEM;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 set_first_time();
 // Invalid PID
 if (!is_valid_pid(pid))
  return -ESRCH;
 spin_lock_irqsave(&traced_p_lock, flags);
 if (pid == -1) {
  traced_incl = 1;
  set_to_val(traced_p_buf, PSTRACE_BUF_SIZE, -1);
  traced_count = 0;
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0;
 }
 // We are tracking pids to include
 if (traced_incl == 1) {
  if (!replace_first_val(traced_p_buf,
       PSTRACE_BUF_SIZE, pid, -1))
   traced_count--;
  spin_unlock_irqrestore(&traced_p_lock, flags);
  // Do nothing
  return 0; /* MAKE RIGHT ERROR CODE*/
 }
 if (traced_count == PSTRACE_BUF_SIZE) {
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return -ENOMEM;
 }
 if (in_arr(traced_p_buf, PSTRACE_BUF_SIZE, pid)) {
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0;
 }
 if (!replace_first_val(traced_p_buf, PSTRACE_BUF_SIZE, -1, pid)) {
  traced_count++;
  spin_unlock_irqrestore(&traced_p_lock, flags);
  return 0;
 }
 spin_unlock_irqrestore(&traced_p_lock, flags);
 return -ENOMEM;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
       long __user *, counter)
{
 long kcounter = 0;
 int num_returned;
 struct pstrace *kbuf;
 struct gets_node *current_node;
 DEFINE_WAIT(wait);
 if (!buf || !counter)
  return -EINVAL;
 if (get_user(kcounter, counter))
  return -EFAULT;
 kbuf = kmalloc(PSTRACE_BUF_SIZE * sizeof(struct pstrace), GFP_KERNEL);
 spin_lock_irqsave(&ring_lock, flags);
 if (kcounter <= 0) {
  num_returned = 0;
  if (states_count > PSTRACE_BUF_SIZE)
   num_returned = copy_buffer(kbuf,
    pid, 0, PSTRACE_BUF_SIZE);
  else
   num_returned = copy_buffer(kbuf,
    pid, 0, states_count);
  kcounter = states_count;
  if (put_user(kcounter, counter) || copy_to_user(buf, kbuf,
    sizeof(struct pstrace) * PSTRACE_BUF_SIZE)) {
   spin_unlock_irqrestore(&ring_lock, flags);
   kfree(kbuf);
   return -EFAULT;
  }
  spin_unlock_irqrestore(&ring_lock, flags);
  kfree(kbuf);
  return num_returned;
 }
 if (states_count > kcounter + PSTRACE_BUF_SIZE) {
  spin_unlock_irqrestore(&ring_lock, flags);
  kfree(kbuf);
  return 0; // make sure it's correct
 }
 spin_unlock_irqrestore(&ring_lock, flags);
 current_node = kmalloc(sizeof(struct gets_node), GFP_KERNEL);
 current_node->pid = pid;
 current_node->is_complete = 0;
 current_node->start_counter = kcounter;
 current_node->target_counter = kcounter + PSTRACE_BUF_SIZE;
 spin_lock_irqsave(&list_lock, flags);
 add_to_ptrace_tail(current_node);
 spin_unlock_irqrestore(&list_lock, flags);
 add_wait_queue(&ptrace_gets_q, &wait);
 /* condition is the event that we are waiting for */
 while (!current_node->is_complete) {
  prepare_to_wait(&ptrace_gets_q, &wait, TASK_INTERRUPTIBLE);
  if (signal_pending(current)) {
   kfree(kbuf);
   return -ERESTARTSYS;
  }
  schedule();
 }
 finish_wait(&ptrace_gets_q, &wait);
 spin_lock_irqsave(&list_lock, flags);
 remove_from_ptrace_list(current_node);
 spin_unlock_irqrestore(&list_lock, flags);
 kcounter = current_node->end;
 num_returned = current_node->num_copied;
 if (put_user(kcounter, counter) ||
   copy_to_user(buf, current_node->buf,
   sizeof(struct pstrace) * current_node->num_copied)) {
  kfree(kbuf);
  kfree(current_node);
  return -EFAULT;
 }
 kfree(current_node);
 kfree(kbuf);
 return num_returned;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i, si, has_wake_up;
 struct gets_node *cnode;
 spin_lock_irqsave(&ring_lock, flags);
 spin_lock_irqsave(&list_lock, flags);
 cnode = gets_node_head;
 has_wake_up = 0;
 while (cnode != NULL) {
  if (cnode->pid != pid && pid != -1) {
   cnode = cnode->next;
   continue;
  }
  si = (cnode->start_counter + 1) % PSTRACE_BUF_SIZE;
  cnode->num_copied =
   copy_buffer(cnode->buf, cnode->pid, si,
    states_count - cnode->start_counter);
  cnode->end = states_count;
  cnode->is_complete = 1;
  cnode = cnode->next;
  has_wake_up = 1;
 }
 spin_unlock_irqrestore(&list_lock, flags);
 i = 0;
 while (i < PSTRACE_BUF_SIZE) {
  if (ring_buf[i].pid != pid && pid != -1) {
   i++;
   continue;
  }
  ring_buf[i].pid = -1;
  ring_buf[i].state = 0;
  memset(ring_buf[i].comm, '\0', 16);
  i++;
 }
 spin_unlock_irqrestore(&ring_lock, flags);
 if (has_wake_up)
  wake_up_all(&ptrace_gets_q);
 return 0;
}