#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <stddef.h>
// #include <stdio.h>
#include <linux/string.h>
#include <linux/wait.h>
#define PSTRACE_BUF_SIZE 500
#define DISABLED_PID_NUM -2
#define TRACE_INIT_VALUE 0
#define TASK_COMM_LEN 16
struct pstrace pstraces[PSTRACE_BUF_SIZE];
long valid_count_start = 0;
pid_t tr_pid = DISABLED_PID_NUM;
long cur_index = TRACE_INIT_VALUE;
static DEFINE_SPINLOCK(tr_pid_lock);
static DEFINE_SPINLOCK(tr_add_lock);
unsigned long flags;
int global_kcounter = TRACE_INIT_VALUE;
int wait_task_count = 0;
DECLARE_WAIT_QUEUE_HEAD(my_queue);
static struct task_struct *get_root(int root_pid){
        if (root_pid == 0)
                return &init_task;
        return find_task_by_vpid(root_pid);
}
void pstrace_add(struct task_struct *p, long state, char *place, int add_flag, int wake_flag){
        long index = cur_index % PSTRACE_BUF_SIZE;
        if(tr_pid == DISABLED_PID_NUM){
                return;
        }
                 if(p->tgid == tr_pid || tr_pid == -1){
                        if(add_flag){
                                spin_lock_irqsave(&tr_add_lock, flags);
                                pstraces[index].pid = p->tgid;
                                pstraces[index].tid = p->pid;
                                pstraces[index].state = state;
                                strncpy(pstraces[index].comm, p->comm, TASK_COMM_LEN);          
                                                         printk(KERN_INFO "pstrace_add cur_index %d, %s, %d, %d, %d, %s \n", cur_index, place, pstraces[index].pid, pstraces[index].tid, pstraces[index].state, pstraces[index].comm);
                                cur_index++;
                                spin_unlock_irqrestore(&tr_add_lock, flags);
                                                         }
                        if (wake_flag && (cur_index >= (global_kcounter + PSTRACE_BUF_SIZE))){
                                        wake_up_all(&my_queue);
                                }
        }
                 return;
}
SYSCALL_DEFINE1(pstrace_enable, pid_t, pid) {    
        struct task_struct *task;
        printk(KERN_INFO "pstrace_enable %d\n", pid);
        if(pid == -1) {
                tr_pid = -1; 
                return 0;   
        }
        task = get_root(pid);
        if(task == NULL){
                printk(KERN_INFO "invalid pid %d\n", pid);
                return -ESRCH;
        }
        printk(KERN_INFO "after get root %d tgid\n", task->tgid);
        tr_pid = task->tgid;
        printk(KERN_INFO "pstrace_enable pid %d tr_pid %d\n", pid, tr_pid);
        return 0;
}
SYSCALL_DEFINE0(pstrace_disable) {
        printk(KERN_INFO "pstrace_disable \n");
        tr_pid = DISABLED_PID_NUM;
        return 0;
}
SYSCALL_DEFINE2(pstrace_get, struct pstrace __user *, buf, long __user *, counter) {
        long kcounter, start, end, kbuf_size, record_start, record_end, cur_record; 
        struct pstrace *kbuf;
        kbuf = kmalloc(sizeof(struct pstrace) * (PSTRACE_BUF_SIZE), GFP_KERNEL);
        long kbuf_i = 0, pstrace_i = 0;
        printk(KERN_INFO "-------pstrace_get call\n");
        spin_lock_irq(&tr_add_lock);
         
         if(copy_from_user(&kcounter, counter, sizeof(kcounter)))
                return -EFAULT;
                 printk(KERN_INFO "pstrace_get counter %lx\n", kcounter);
        global_kcounter = kcounter;
        printk("cur_index: %d", cur_index);
        if(kcounter < 0) {
                // error
                spin_unlock_irq(&tr_add_lock);
                return -EINVAL;
        }
        if(kcounter > 0 && cur_index <= kcounter + PSTRACE_BUF_SIZE){
                printk(" -------wait case------\n");
                DEFINE_WAIT(w);
                printk(" DEFINE_WAIT(w)\n");
                add_wait_queue(&my_queue, &w);
                printk(" add_wait_queue\n");
                wait_task_count++;
                while(cur_index <= kcounter + PSTRACE_BUF_SIZE) {
                                printk(KERN_INFO "start loop cur_index: %d, kcounter: %d, global_kcounter: %ld\n", cur_index, kcounter, global_kcounter);
                                if(kcounter < global_kcounter) {
                                        printk("before update global_kcounter: %ld", global_kcounter);
                                        global_kcounter = kcounter;
                                }
                                printk("global_kcounter in get: %d", global_kcounter); 
                                                                 prepare_to_wait(&my_queue, &w, TASK_UNINTERRUPTIBLE);
                                spin_unlock_irq(&tr_add_lock);
                                if (signal_pending(current)){
                                       //break;
                                       printk(KERN_INFO "signal pending\n");
                                       return -ERESTARTSYS;
                                }
                                printk(KERN_INFO "jump");
                                schedule();
                                printk(KERN_INFO "back. index: %d", cur_index);
                                spin_lock_irq(&tr_add_lock);
                                printk(KERN_INFO "back. index: %d, kcounter: %d", cur_index, kcounter);
                                // All task wake up, only one task met return condition
                                // Update global_kcounter to some other task that is going to stay in wait queue
                                if(cur_index <= kcounter + PSTRACE_BUF_SIZE){
                                        global_kcounter = kcounter;
                                        printk(KERN_INFO " update global_kcounter: %ld\n", global_kcounter);
                                }
                }
                printk(KERN_INFO " finish_wait, cur_index: %d\n", cur_index);
                finish_wait(&my_queue, &w);
                wait_task_count--;
                printk("finish_wait wait_task_count: %d\n", wait_task_count);
                if(wait_task_count == 0)
                        global_kcounter = LLONG_MAX - PSTRACE_BUF_SIZE;
        }
        if(cur_index == 0)
                cur_record = 0;
        else
                cur_record = cur_index - 1;
        if (kcounter > 0) {
                record_start = kcounter; 
                if(valid_count_start > record_start)
                        record_start = valid_count_start;
                if(cur_record - PSTRACE_BUF_SIZE + 1 > record_start)
                        record_start = cur_record - PSTRACE_BUF_SIZE + 1;
                record_end = kcounter + PSTRACE_BUF_SIZE;
                if(cur_record > record_end + PSTRACE_BUF_SIZE || record_start > record_end){
                        spin_unlock_irqrestore(&tr_add_lock, flags);
                        if(copy_to_user(counter, &cur_record, sizeof(long))){
                                spin_unlock_irqrestore(&tr_add_lock, flags);
                                return -EFAULT;
                        }
                        return 0;
                } 
        }
        if(kcounter == 0) {
                // immediate return 
                record_start = valid_count_start;
                record_end = cur_record;
                // [record_start, record_end]
                if(record_end - record_start + 1 > PSTRACE_BUF_SIZE)
                        record_start = record_end - PSTRACE_BUF_SIZE + 1;
                printk("----kcounter = 0 record_start %d record_end %d cur_record %d\n", record_start, record_end, cur_record);
                // Nothing can be returned
                if(record_start > record_end || cur_record == 0) {
                        printk("return counter to user\n");
                        spin_unlock_irqrestore(&tr_add_lock, flags);
                        if(copy_to_user(counter, &cur_record, sizeof(long))){
                                return -EFAULT;
                        }
                        return 0;
                }
        }  
        printk("----before copy and return print pstrace\n");
        printk("----print record_start %d record_end %d cur_record %d\n", record_start, record_end, cur_record);
        start = record_start % PSTRACE_BUF_SIZE; 
        end = record_end % PSTRACE_BUF_SIZE;
        // [start, end]
        if(start <= end) {
                printk("start <= end\n");
                kbuf_size = end - start + 1;
                printk("----print kbuf start %d end %d size %d\n", start, end, kbuf_size);
                kbuf = kmalloc(sizeof(struct pstrace) * (kbuf_size), GFP_KERNEL);
                if(kbuf == NULL) {
                        spin_unlock_irqrestore(&tr_add_lock, flags);
                        return -ENOMEM;
                }
                while(start <= end) {
                        kbuf[kbuf_i] = pstraces[start]; 
                        kbuf_i++;
                        start++;
                }
        } else {
                printk("start > end\n");
                kbuf_size = PSTRACE_BUF_SIZE - start + end + 1;
                printk("----print kbuf start %d end %d size %d\n", start, end, kbuf_size);
                // kbuf = kmalloc(sizeof(struct pstrace) * (kbuf_size), GFP_KERNEL);
                if(kbuf == NULL){
                        spin_unlock_irqrestore(&tr_add_lock, flags);
                        return -ENOMEM;
                }
                while(start < PSTRACE_BUF_SIZE) {
                       kbuf[kbuf_i] = pstraces[start];
                       kbuf_i++;
                       start++;
                }
                pstrace_i = 0;
                printk("copy 0 - end, kbuf_i=%d\n", kbuf_i);
                while( pstrace_i <= end) {
                     kbuf[kbuf_i] = pstraces[pstrace_i]; 
                     pstrace_i++;
                     kbuf_i++;
                }
        }
        spin_unlock_irqrestore(&tr_add_lock, flags);
        if(copy_to_user(buf, kbuf, sizeof(struct pstrace) * kbuf_size)) {
                kfree(kbuf);
                return -EFAULT;
        }
        //kcounter = kbuf_size;
        printk("kcounter: %d", kcounter);
        if(kcounter == 0){
                if(copy_to_user(counter, &cur_record, sizeof(long))) {
                        kfree(kbuf);
                        return -EFAULT;
                }
        }
        else{
                if(copy_to_user(counter, &record_end, sizeof(long))) {
                        kfree(kbuf);
                        return -EFAULT;
                }
        }
        kfree(kbuf);
        return kbuf_size;
}
SYSCALL_DEFINE0(pstrace_clear) {
        spin_lock_irq(&tr_add_lock);
        printk(KERN_INFO "pstrace_clear valid_count_start = %d\n", cur_index);
        valid_count_start = cur_index;
        wake_up_all(&my_queue);
        memset(pstraces, 0, sizeof(pstraces));
        spin_unlock_irq(&tr_add_lock);
        return 0;
}