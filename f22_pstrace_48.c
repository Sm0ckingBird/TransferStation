#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/pstrace.h>
#define PSTRACE_BUF_SIZE 500
long ring_counter;
struct pstrace *ring_buf;
bool tracing;
bool tracing_all;
struct task_struct *now_tracing;
long ring_center;
static struct task_struct *get_root(int root_pid)
{
 if (root_pid == 0)
  return &init_task;
 return find_task_by_vpid(root_pid);
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 DEFINE_SPINLOCK(lock);
 spin_lock(&lock);
 struct task_struct *root;
 if (!ring_buf) {
  ring_buf = kmalloc(PSTRACE_BUF_SIZE * sizeof(struct pstrace), GFP_KERNEL);
  ring_counter = 0;
  ring_center = 0;
  tracing = false;
  tracing_all = false;
 }
 if (pid == -1) {
  tracing_all = true;
 } else if (pid > 0) {
  tracing_all = false;
  root = get_root(pid);
  if (root == NULL)
   return -ESRCH;
  now_tracing = root;
 } else {
  return -EINVAL;
 }
 tracing = true;
 spin_unlock(&lock);
 //int i;
 //printk(KERN_INFO "*\n");
 //for (i=0; i <= (ring_counter-ring_center-1) % PSTRACE_BUF_SIZE; i++){
  //struct pstrace ring_test = ring_buf[(i+ring_center) % PSTRACE_BUF_SIZE];
  //printk(KERN_INFO "index: %ld\n", (i+ring_center));
  //printk(KERN_INFO "state: %ld\n", ring_test.state);
 //}
 //printk(KERN_INFO "*\n");
 return 0;
}
SYSCALL_DEFINE0(pstrace_disable)
{
 tracing = false;
 return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace *, buf, long *, counter)
{
 struct pstrace *kbuf;
 int kcounter;
 size_t size;
 //if (!buf || !counter)
 if (!buf)
  return -EINVAL;
 //if (get_user(kcounter, counter))
  //return -EFAULT;
 //if (kcounter < 0)
  //return -EINVAL;
 //if (kcounter > 0 && kcounter + PSTRACE_BUF_SIZE < ring_counter){
  // schedule()
  // return -1;
 //}
 DEFINE_SPINLOCK(lock);
 spin_lock(&lock);
 size = ((ring_counter-ring_center-1) % PSTRACE_BUF_SIZE + 1) * sizeof(struct pstrace);
 kbuf = kmalloc(size, GFP_KERNEL);
 int i;
 for (i = 0; i <= (ring_counter-ring_center-1) % PSTRACE_BUF_SIZE; i++) {
  struct pstrace get = ring_buf[(i+ring_center) % PSTRACE_BUF_SIZE];
  kbuf[i] = get;
 }
 copy_to_user(buf, kbuf, size);
 spin_unlock(&lock);
 return i;
}
SYSCALL_DEFINE0(pstrace_clear)
{
 //Wake up processes waiting on pstrace_get
 ring_center = ring_counter + 1;
 return 0;
}
void pstrace_add(struct task_struct *p, long state)
{
 if (tracing && (tracing_all || p->pid == now_tracing->pid)) {
  struct pstrace to_add;
  DEFINE_SPINLOCK(lock);
  spin_lock(&lock);
  get_task_comm(to_add.comm, p);
  to_add.state = state;
  to_add.pid = p->pid;
  to_add.tid = p->tgid;
  ring_buf[ring_counter % PSTRACE_BUF_SIZE] = to_add;
  ring_counter++;
  spin_unlock(&lock);
 }
}