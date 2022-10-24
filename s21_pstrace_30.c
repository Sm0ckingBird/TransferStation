#include <pstrace/util.c>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{ 
 start_flag = 1;
 printk("Enabling our call %d", pid);
 pstrace_enable(pid);
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
    printk("Disabling our call %d", pid);
 return 0;
}
SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
 printk("Clearing pid %d", pid);
    int i = 0;
          while(i < buffer.index) {
  if (pid == -1)  
   buffer.pstrace_array[i].deleted = 1;
  else {
   if(buffer.pstrace_array[i].pid == pid) 
    buffer.pstrace_array[i].deleted = 1;
  }
  i++;
 }
 return 0;
}
SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user*, buf, long*, counter)
{
 long copy_counter;
 struct pstrace *copy_buf;
 if (copy_from_user(&copy_counter, counter, sizeof(long)))
  return -EINVAL;
 copy_buf = kmalloc_array(PSTRACE_BUF_SIZE, sizeof(struct pstrace), GFP_KERNEL);
 if (copy_buf != NULL) {
  pstrace_get_help(pid, copy_buf, counter);
  if (copy_to_user(buf, copy_buf, PSTRACE_BUF_SIZE*sizeof(struct pstrace)))
   return -EFAULT;
  kfree(copy_buf); 
 } else {
  return -ENOMEM;
 } 
        return 0;
}