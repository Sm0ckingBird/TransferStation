#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/pstrace.h>
#include <linux/types.h>
struct pstrace tracked[PSTRACE_BUF_SIZE];
static atomic_t tracked_counter = ATOMIC_INIT(0);
static atomic_t enabled_flag = ATOMIC_INIT(0);
static struct ring_buffer rbuf;
DEFINE_SPINLOCK(ringbuffer_lock);
static atomic_t ring_buffer_counter = ATOMIC_INIT(0);
struct ring_buffer {
 unsigned int size;
 unsigned int start;
 unsigned int end;
 struct pstrace *processes;
};
void init_ring_buffer(struct ring_buffer *rbuf, unsigned int size)
{
 rbuf->size = size;
 rbuf->start = 0;
 rbuf->end = 0;
 rbuf->processes =
  kmalloc(rbuf->size * sizeof(struct pstrace), GFP_KERNEL);
}
void free_ring_buffer(struct ring_buffer *rbuf)
{
 kfree(rbuf->processes);
 rbuf->processes = NULL;
}
void clear_ring_buffer(struct ring_buffer *rbuf)
{
 rbuf->start = 0;
 rbuf->end = 0;
}
int is_ring_buffer_full(struct ring_buffer *rbuf)
{
 return rbuf->end == (rbuf->start ^ rbuf->size);
}
void write_ring_buffer(struct ring_buffer *rbuf, struct pstrace *entry)
{
 rbuf->processes[rbuf->end & (rbuf->size - 1)] = *entry;
 if (is_ring_buffer_full(rbuf))
  rbuf->start = (rbuf->size + 1) & (2 * rbuf->size - 1);
 else
  rbuf->end = (rbuf->end + 1) & (2 * rbuf->size - 1);
}
void read_ring_buffer(struct ring_buffer *rbuf, struct pstrace *entry)
{
}
void pstrace_add(struct task_struct *p)
{
 int c, i;
 int should_track = 0;
 struct pstrace ps;
 if (atomic_read(&enabled_flag) == 0)
  return;
 c = atomic_read(&tracked_counter);
 for (i = 0; i < c; i++) {
  if (tracked[i].pid == p->pid) {
   ps = tracked[i];
   should_track = 1;
   break;
  }
 }
 if (should_track == 1) {
  atomic_inc(&ring_buffer_counter);
  ps.state = p->state;
  spin_lock(&ringbuffer_lock);
  write_ring_buffer(&rbuf, &ps);
  spin_unlock(&ringbuffer_lock);
 }
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
 struct task_struct *task_iter;
 int c;
 init_ring_buffer(&rbuf, PSTRACE_BUF_SIZE);
 if (pid == -1) {
  for_each_process(task_iter)
  {
   c = atomic_read(&tracked_counter);
   if (c < PSTRACE_BUF_SIZE) {
    tracked[c].pid = task_iter->pid;
    tracked[c].state = task_iter->state;
    get_task_comm(tracked[c].comm, task_iter);
    atomic_inc(&tracked_counter);
   }
  }
 } else {
  task_iter = find_task_by_vpid(pid);
  c = atomic_read(&tracked_counter);
  if (c < PSTRACE_BUF_SIZE) {
   tracked[c].pid = task_iter->pid;
   tracked[c].state = task_iter->state;
   get_task_comm(tracked[c].comm, task_iter);
   atomic_inc(&tracked_counter);
  }
 }
 atomic_set(&enabled_flag, 1);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
 atomic_set(&enabled_flag, 0);
 atomic_set(&tracked_counter, 0);
 free_ring_buffer(&rbuf);
 clear_ring_buffer(&rbuf);
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace *, buf, int *, counter)
{
 return 0;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 return 0;
}