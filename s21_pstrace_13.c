// SPDX-License-Identifier: MIT
#include <linux/sched.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
atomic_t node_counter = ATOMIC_INIT(0);
atomic_t buffer_counter = ATOMIC_INIT(0);
atomic_t snap_counter = ATOMIC_INIT(0);
atomic_t clear_snap_counter = ATOMIC_INIT(0);
atomic_t trace_all_processes = ATOMIC_INIT(0);
atomic_t recursion_flag = ATOMIC_INIT(0);
pid_t clear_pid;
int event = 1; //clear:0, add:1
int clear_counter;
struct rb_root root = RB_ROOT;
struct rb_root root_clear = RB_ROOT;
struct _pstrace pstrace_buffer[PSTRACE_BUF_SIZE];
struct _pstrace snapshot[PSTRACE_BUF_SIZE];
// for simplicity, otherwise, add -> get(read)
//                                 clear(write)
// then the snapshot of add is overwritten by clear
struct _pstrace clear_snapshot[PSTRACE_BUF_SIZE];
DEFINE_RWLOCK(map_rwlock);
DEFINE_RWLOCK(buffer_rwlock);
DEFINE_RWLOCK(wq_rwlock);
DEFINE_SPINLOCK(wakeup_lock);
DEFINE_MUTEX(protect_event_mutex);
DECLARE_WAIT_QUEUE_HEAD(pstrace_wq);
struct custom_node *search_key(struct rb_root *root, pid_t pid)
{
 struct rb_node *node;
 struct custom_node *data;
 node = root->rb_node;
 while (node) {
  data = container_of(node, struct custom_node, node);
  if (data->pid > pid)
   node = node->rb_left;
  else if (data->pid < pid)
   node = node->rb_right;
  else
   return data;
 }
 return NULL;
}
int insert_key(struct rb_root *root, struct custom_node *data)
{
 struct rb_node **new;
 struct rb_node *parent;
 struct custom_node *cur;
 new = &(root->rb_node);
 parent = NULL;
 while (*new) {
  cur = container_of(*new, struct custom_node, node);
  parent = *new;
  if (data->pid < cur->pid)
   new = &((*new)->rb_left);
  else if (data->pid > cur->pid)
   new = &((*new)->rb_right);
  else
   return 0;
 }
 rb_link_node(&data->node, parent, new);
 rb_insert_color(&data->node, root);
 return 1;
}
int delete_key(struct rb_root *root, pid_t pid)
{
 struct custom_node *data = search_key(root, pid);
 if (data) {
  rb_erase(&(data->node), root);
 } else {
  //printk(KERN_ERR "couldn't delete key in tree clear\n");
  return -1;
 }
 return 0;
}
void insert_pid(struct rb_root *root, pid_t *pid)
{
 int ret;
 struct custom_node *p_data;
 p_data = kcalloc(1, sizeof(struct custom_node), GFP_KERNEL);
 p_data->pid = current->pid;
 ret = insert_key(root, p_data);
 if (!ret) {
  kfree(p_data);
  p_data = NULL;
  //printk(KERN_ERR "key already exists\n");
 }
}
long get_start_end_index(long *kcounter, long *start_num,
  long *end_num, int event)
{
 long buffer_start = atomic_read(&buffer_counter) - PSTRACE_BUF_SIZE;
 long buffer_end = atomic_read(&buffer_counter) - 1;
 long counter_start = *kcounter;
 long counter_end = *kcounter + PSTRACE_BUF_SIZE - 1;
 if (event == 0) {
  buffer_start = atomic_read(&clear_snap_counter) -
   PSTRACE_BUF_SIZE;
  buffer_end = atomic_read(&clear_snap_counter) - 1;
 } else if (atomic_read(&recursion_flag)) {
  buffer_start = atomic_read(&snap_counter) - PSTRACE_BUF_SIZE;
  buffer_end = atomic_read(&snap_counter) - 1;
 }
 if (*kcounter < 1) {
  *start_num = buffer_start;
  *end_num = buffer_end;
  return 1;
 }
 if (counter_end < buffer_start || buffer_end < counter_start)
  return 0;
 *start_num = max(buffer_start, counter_start);
 *end_num = min(buffer_end, counter_end);
 return 1;
}
void make_snapshot(struct _pstrace *snapshot, atomic_t *snap_counter)
{
 int i;
 for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
  strncpy(snapshot[i].comm,
   pstrace_buffer[i].comm,
   sizeof(snapshot[i].comm));
  snapshot[i].pid = pstrace_buffer[i].pid;
  snapshot[i].state = pstrace_buffer[i].state;
  atomic_set(&(snapshot[i].removed),
    atomic_read(&(pstrace_buffer[i].removed)));
 }
 atomic_set(snap_counter, atomic_read(&buffer_counter));
}
// TODO need LOCK and many deadlock prevention
void pstrace_add(struct task_struct *p)
{
 // WORKFLOW HINTS
 // 1. don't call wake_up if being in a "recursion"
 // 2. don't allow interrupt when holding exclusive locks
 // Done
 // 1. global flag for recursion detection
 // 2. global ring buffer snapshot
 // 3. add_flags should be a local variable
 pid_t pid = p->pid;
 int insert_location;
 unsigned long irq_flag;
 local_irq_save(irq_flag);
 read_lock(&map_rwlock);
 if (atomic_read(&trace_all_processes) ||
  search_key(&root, pid)) {
  write_lock(&buffer_rwlock);
  insert_location = atomic_read(&buffer_counter)
   % PSTRACE_BUF_SIZE;
  atomic_inc(&buffer_counter);
  strncpy(pstrace_buffer[insert_location].comm,
   p->comm,
   sizeof(pstrace_buffer[insert_location].comm));
  pstrace_buffer[insert_location].pid = pid;
  if (p->exit_state == 0x0010 || p->exit_state == 0x0020)
   pstrace_buffer[insert_location].state = p->exit_state;
  else
   pstrace_buffer[insert_location].state = p->state;
  atomic_set(&pstrace_buffer[insert_location].removed, 0);
  // if in a recursion, don't write to the snapshot
  // else write into the snapshot
  // write_lock(&flag_rwlock);
  if (!atomic_read(&recursion_flag))
   make_snapshot(snapshot, &snap_counter);
  write_unlock(&buffer_rwlock);
 } else {
  read_unlock(&map_rwlock);
  local_irq_restore(irq_flag);
  return;
 }
 read_unlock(&map_rwlock);
 //check recursion flag, if true don't wake_up() otherwise set the flag
 //to be true and then wake_up()
 if (!atomic_read(&recursion_flag)) {
  // set the recursion flag to be true
  atomic_set(&recursion_flag, 1);
  spin_lock(&wakeup_lock);
  event = 1;
  wake_up(&pstrace_wq);
  spin_unlock(&wakeup_lock);
  // set the recursion flag to be false
  atomic_set(&recursion_flag, 0);
 } else {
  //printk(KERN_INFO "in recursion mode, don't wake_up!\n");
 }
 local_irq_restore(irq_flag);
}
void deal_with_wait(long *kcounter, pid_t *pid)
{
 int condition = (*kcounter + PSTRACE_BUF_SIZE <=
   atomic_read(&buffer_counter));
 //TODO the above condition is problematic
 //printk(KERN_INFO "condition: %d\n", condition);
 if (!condition) {
  while (1) {
   DEFINE_WAIT(wait);
   // prevent _get while run _clear
   read_lock(&wq_rwlock);
   prepare_to_wait(&pstrace_wq, &wait, TASK_INTERRUPTIBLE);
   //printk(KERN_INFO "prepare_to_wait pid: %d\n",
   //  current->pid);
   read_unlock(&wq_rwlock);
   read_unlock(&buffer_rwlock);
   //printk(KERN_INFO "schedule\n");
   schedule();
   if (event == 0) {
    //printk(KERN_INFO "event: %d\n", 0);
    //printk(KERN_INFO
    //"clear_pid:%d, get pid:%d, current->pid:%d\n"
    //, clear_pid, *pid, current->pid);
    if (clear_pid == -1 || *pid == -1 ||
      *pid == clear_pid) {
     insert_pid(&root_clear, &current->pid);
     //printk(KERN_INFO "break\n");
     break;
    }
    continue;
   }
   //printk(KERN_INFO "scheduled\n");
   read_lock(&buffer_rwlock);
   if (*kcounter + PSTRACE_BUF_SIZE <=
     atomic_read(&buffer_counter)) {
    finish_wait(&pstrace_wq, &wait);
    break;
   }
  }
 }
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 int ret;
 struct custom_node *data;
 data = kcalloc(1, sizeof(struct custom_node), GFP_KERNEL);
 write_lock(&map_rwlock);
 if (atomic_read(&trace_all_processes) == 1) {
  write_unlock(&map_rwlock);
  kfree(data);
  //printk(KERN_ERR "Tracing all processes now.\n");
  return -EFAULT;
 } else if (pid == -1) {
  atomic_set(&trace_all_processes, 1);
  write_unlock(&map_rwlock);
  return 0;
 }
 data->pid = pid;
 if (atomic_read(&node_counter) >= PSTRACE_BUF_SIZE) {
  write_unlock(&map_rwlock);
  kfree(data);
  //printk(KERN_ERR "Exceed trace size limit, bye\n");
  return -EFAULT;
 }
 ret = insert_key(&root, data);
 if (ret) {
  atomic_inc(&node_counter);
  write_unlock(&map_rwlock);
 } else {
  write_unlock(&map_rwlock);
  kfree(data);
  data = NULL;
  //printk(KERN_ERR "key already exists\n");
  return -1;
 }
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 struct custom_node *data = NULL;
 if (atomic_read(&trace_all_processes) == 1) {
  if (pid != -1) {
   //printk(KERN_ERR "Tracing all processes now.\n");
   return -EFAULT;
  }
  atomic_set(&trace_all_processes, 0);
  return 0;
 } else if (pid == -1) {
  //printk(KERN_ERR "Not tracing all processes now.\n");
  return -EFAULT;
 }
 write_lock(&map_rwlock);
 data = search_key(&root, pid);
 if (data) {
  rb_erase(&(data->node), &root);
  atomic_dec(&node_counter);
  write_unlock(&map_rwlock);
  kfree(data);
 } else {
  write_unlock(&map_rwlock);
  //printk(KERN_ERR "search fails\n");
  return -1;
 }
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *,
  buf, long __user *, counter)
{
 long kcounter, start_num, end_num;
 int ret, i, idx = 0;
 int return_size = 0;
 struct pstrace *kbuf;
 struct _pstrace *ring_buffer;
 struct custom_node *p_data = NULL;
 if (copy_from_user(&kcounter, counter, sizeof(long)))
  return -EFAULT;
 //printk(KERN_INFO "kcounter: %ld\n", kcounter);
 //printk(KERN_INFO "Now trace: %d\n", pid);
 //printk(KERN_INFO "node_counter: %d\n", atomic_read(&node_counter));
 //printk(KERN_INFO "buffer_counter: %d\n",
 //atomic_read(&buffer_counter));
 //printk(KERN_INFO "current pid: %d\n", current->pid);
 kbuf = kcalloc(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (!kbuf)
  return -ENOMEM;
 read_lock(&buffer_rwlock);
 if (kcounter > 0)
  deal_with_wait(&kcounter, &pid);
 p_data = search_key(&root_clear, current->pid);
 if (p_data)
  ret = get_start_end_index(&kcounter, &start_num, &end_num, 0);
 else
  ret = get_start_end_index(&kcounter, &start_num, &end_num, 1);
 //printk(KERN_INFO "get start end index?: %d\n", ret);
 if (!ret) {
  kfree(kbuf);
  return 0;
 }
 if (p_data) {
  //printk(KERN_INFO "woken by clear, cur pid:%d, get pid:%d\n"
  //, p_data->pid, pid);
  ring_buffer = clear_snapshot;
 } else if (atomic_read(&recursion_flag))
  ring_buffer = snapshot;
 else {
  ring_buffer = pstrace_buffer;
 }
 if (start_num < 0)
  start_num = 0;
 //printk("start_num, end_num: %ld, %ld\n", start_num, end_num);
 for (i = start_num; i <= end_num; i++) {
  idx = i % PSTRACE_BUF_SIZE;
  //printk("idx: %d, buffer.pid: %d, buffer.rm: %d\n",
  //idx,
  //ring_buffer[idx].pid,atomic_read(&ring_buffer[idx].removed));
  if (!atomic_read(&(ring_buffer[idx].removed)) &&
   (pid == -1 || pid == ring_buffer[idx].pid)) {
   strncpy(kbuf[return_size].comm,
    ring_buffer[idx].comm,
    sizeof(kbuf[return_size].comm));
   kbuf[return_size].pid = ring_buffer[idx].pid;
   kbuf[return_size].state = ring_buffer[idx].state;
   return_size++;
  }
 }
 read_unlock(&buffer_rwlock);
 if (p_data) {
  kcounter = atomic_read(&clear_snap_counter);
  delete_key(&root_clear, p_data->pid);
  kfree(p_data);
 } else if (atomic_read(&recursion_flag))
  kcounter = atomic_read(&snap_counter);
 else
  kcounter = atomic_read(&buffer_counter);
 if (copy_to_user(counter, &kcounter, sizeof(int))) {
  kfree(kbuf);
  return -EFAULT;
 }
 if (copy_to_user(buf, kbuf, sizeof(struct pstrace) * return_size)) {
  kfree(kbuf);
  return -EFAULT;
 }
 kfree(kbuf);
 return return_size;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 int i;
 unsigned long irq_flag;
 //printk(KERN_ERR "start pstrace_clear, pid: %d\n", pid);
 clear_pid = pid;
 event = 0;
 //printk(KERN_ERR "spin lock\n");
 local_irq_save(irq_flag);
 spin_lock(&wakeup_lock);
 write_lock(&buffer_rwlock);
 //printk(KERN_ERR "make snapshot\n");
 make_snapshot(clear_snapshot, &clear_snap_counter);
 //printk(KERN_ERR "clear pstrace_buffer\n");
 for (i = 0; i <= PSTRACE_BUF_SIZE; i++) {
  if ((pid == -1 || pstrace_buffer[i].pid == pid))
   atomic_set(&(pstrace_buffer[i].removed), 1);
 }
 //printk(KERN_ERR "pstrace_buffer cleared\n");
 write_unlock(&buffer_rwlock);
 //printk(KERN_ERR "write unlock\n");
 // prevent other _get push events into wait_queue
 write_lock(&wq_rwlock);
 //printk(KERN_ERR "wake up all\n");
 atomic_set(&recursion_flag, 1);
 wake_up_all(&pstrace_wq);
 atomic_set(&recursion_flag, 0);
 //while (waitqueue_active(&pstrace_wq))
 //;
 write_unlock(&wq_rwlock);
 spin_unlock(&wakeup_lock);
 local_irq_restore(irq_flag);
 //printk(KERN_ERR "spin unlock\n");
 return 0;
}