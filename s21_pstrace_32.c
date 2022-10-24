#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/pstrace.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <asm/spinlock.h>
#define PSTRACE_BUF_SIZE 500
trace_enable = 0;
buffer = kmalloc(sizeof(struct pstrace)*PSTRACE_BUF_SIZE, GFP_KERNEL);
DEFINE_SPINLOCK(mr_lock);
int buffer_counter = 0;
/*
 * Syscall No. 436
 * Enable the tracing for @pid. If -1 is given, trace all processes.
 */
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
    trace_enable = 1;
    printk("pstrace_enable\n");
    return 0;
}
/*
 * Syscall No. 437
 * Disable the tracing for @pid. If -1 is given, stop tracing all processes.
*/
SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
    trace_enable = 0;
    printk("pstrace_disable\n");
    return 0;
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
SYSCALL_DEFINE1(pstrace_get, pid_t, pid, struct pstrace __user *, buf, long __user *, counter)
{
         printk("pstrace_get\n");
    return 0;
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
    printk("pstrace_clear\n");
    return 0;
}
// add new records to buffer
void pstrace_add(struct task_struct *p)
{
    struct pstrace record;
    record.comm = p->comm;
    record.state = p->state;
    record.pid = p->tgid;
    spin_lock(&mr_lock);
    buffer[buffer_counter % 500] = record;
    buffer_counter++;
    spin_unlock(&mr_lock);
}