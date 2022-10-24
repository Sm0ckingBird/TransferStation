#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/kfifo.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/psbuf.h>
#include <linux/semaphore.h>
#define CONFIG_PREEMPT 1
#define CONFIG_DEBUG_KERNEL 1
#define CONFIG_DEBUG_SPINLOCK_SLEEP 1
#define PSTRACE_BUF_SIZE 500
//Create global variables for the structure
struct globalStore store1;
EXPORT_SYMBOL(store1);
int pstraceActive = 0;
EXPORT_SYMBOL(pstraceActive);
struct semaphore sem1;
DEFINE_MUTEX(mutex1);
//struct trackedPid* y is a pointer to one of the struct trackedPid's that we're using in the list, and struct list_head* head1 is the head of the trackedPid list.
int isPidTracked(pid_t pid1,struct trackedPid* y, struct list_head* head1){
 struct trackedPid* pos2 = y;
 struct list_head* head2 = head1;
 list_for_each_entry(pos2,head2,node){
  if (pos2->pid == pid1){
   return 1;
  }
 }
 return 0;
}
struct ps_record** instantiateStore1(void){
 extern struct globalStore store1;
 int i;
 store1.buf1.number = 0;
 store1.buf1.head = kmalloc(sizeof(struct list_head),GFP_KERNEL);
 //Initialize the linked list
 INIT_LIST_HEAD(store1.buf1.head);
 store1.buf1.curr = store1.buf1.head;
 //Instantiate the buffer to have length 500
 struct ps_record** x = kmalloc(500 * sizeof(struct ps_record*),GFP_KERNEL);
 for (i=0; i < 500; i++){
  x[i] = kmalloc(sizeof(struct ps_record),GFP_KERNEL);
  x[i]->number = i;
  x[i]->record.pid = i;
  list_add(&x[i]->node,store1.buf1.curr);
  store1.buf1.curr = &x[i]->node; 
 }
 return x;
}
void printBufferLinkedList(struct ps_record* pos, struct list_head* head1){
 int j = 0;
 list_for_each_entry(pos,head1,node){
  printk("Node %i, number %li, pid %i",j,pos->number,pos->record.pid);
  j++;
 }
}
void instantiateTrackedPidsLinkedList(pid_t pid1){
 extern struct globalStore store1;
 store1.trackedHead = kmalloc(sizeof(struct list_head),GFP_KERNEL);
 INIT_LIST_HEAD(store1.trackedHead);
 struct trackedPid* y = kmalloc(sizeof(struct trackedPid),GFP_KERNEL); 
 struct trackedPid* z = kmalloc(sizeof(struct trackedPid),GFP_KERNEL);
 y->pid = pid1;
 z->pid = pid1+8;
 list_add(&y->node,store1.trackedHead);
 list_add(&z->node,store1.trackedHead);
}
void printTrackedPidsLinkedList(struct list_head* head1){
 struct trackedPid* pos2;
 struct list_head* head2 = head1;
 list_for_each_entry(pos2,head2,node){
  printk("trackedPid pid is %i\n",pos2->pid);
 }
}
SYSCALL_DEFINE1(pstrace_enable,pid_t,pid1){
 extern int pstraceActive;
 //If we're already active, then you don't
 //have to allocate everything
 //Pull store1 from global to local scope
 extern struct globalStore store1;
 //Instantiate store1
 struct ps_record** x = instantiateStore1();
 //Print the buffer linked list entries
 printBufferLinkedList(x[0],store1.buf1.head);
 //Instantiate the trackedPids linked list
 instantiateTrackedPidsLinkedList(pid1);
 //Print the enabled pids linked list entries
 printTrackedPidsLinkedList(store1.trackedHead);
 /*
 //test if isPidTracked works
 int test1 = isPidTracked(10,y,store1.trackedHead);
 int test2 = isPidTracked(18,y,store1.trackedHead);
 int test3 = isPidTracked(27,y,store1.trackedHead);
 printk("Tracked results for 10, 18, and 27 are %i, %i, and %i\n",test1,test2,test3);
  */
 //store1.set
 store1.set.head = kmalloc(sizeof(struct list_head),GFP_KERNEL);
 pstraceActive = 1;
 printk("pstrace_enable with no extern\n");
 return 0;
}
SYSCALL_DEFINE1(pstrace_disable,pid_t,pid1){
 extern struct globalStore store1;
 extern int pstraceActive;
 if (pstraceActive == 1){
  kfree(store1.buf1.head);
  kfree(store1.set.head);
 }
 //Need to also free the psbuf linked list
 pstraceActive = 0;
 printk("pstrace_disable: freed memory\n");
 return 0;
}
SYSCALL_DEFINE0(race1){
 printk("race1\n");
 /*
    printk("race1: begin\n");
    printk("race1: semaphore acquired\n");
    printk("race1: critical section code\n");
    up(&sem1); 
  */
 return 0;
}
SYSCALL_DEFINE0(race2){
 printk("race2\n");
 /*
    printk("race2: begin\n");
    if(down_interruptible(&sem1)){
    printk("race2: semaphore not acquired\n");
    return -1;
    }
    printk("race2: semaphore acquired\n");
    printk("race2: critical section code\n");
    up(&sem1);
    printk("race2: semaphore released\n");
  */
 return 0;
}