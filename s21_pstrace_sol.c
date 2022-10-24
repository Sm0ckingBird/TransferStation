#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/pstrace.h>
#include <linux/wait.h>

struct pstrace_kernel pstrace = {
	.head = 0,
	.tail = PSTRACE_BUF_SIZE - 1,
	.pstrace_lock = __SPIN_LOCK_UNLOCKED(pstrace_lock),
	.counter = ATOMIC_INIT(0),
	.del = {false},
	.trace_all = false,
};


atomic_t in_wake_up = ATOMIC_INIT(0);

LIST_HEAD(pstrace_list);
LIST_HEAD(pstrace_evt_list);
DEFINE_SPINLOCK(pstrace_list_lock);
DEFINE_SPINLOCK(pstrace_evt_list_lock);

static inline bool
pstrace_need_copy(struct pstrace_kernel *pst, int head, pid_t pid)
{
	return (!pst->del[head] && (pst->entry[head].pid == pid || pid == -1));
}

/* Assume pstrace_lock is hold */
static int pstrace_get_buf(struct pstrace_kernel *pst, struct pstrace *buf,
			   pid_t pid)
{
	int head, tail, i, nr_entries = 0;

	head = pst->head;
	tail = pst->tail;
	i = 0;

	for (;;) {
		if (pstrace_need_copy(pst, head, pid)) {
			memcpy(&buf[i], &pst->entry[head],
					sizeof(struct pstrace));
			nr_entries++;
			i++;
		}

		head++;
		if (head == PSTRACE_BUF_SIZE)
			head = 0;

		if (head == tail) {
			if (pstrace_need_copy(pst, head, pid)) {
				memcpy(&buf[i], &pst->entry[head],
						sizeof(struct pstrace));
				nr_entries++;
			}
			break;
		}
	}
	return nr_entries;
}

static bool task_is_pstraced(struct task_struct *p)
{
	struct list_head *pst_list;
	bool ret = false;
	unsigned long flags;

	local_irq_save(flags);
	spin_lock(&pstrace_list_lock);
	if (pstrace.trace_all) {
		ret = true;
		goto out;
	}

	list_for_each(pst_list, &pstrace_list) {
		struct pstrace_list *node = list_entry(pst_list,
				struct pstrace_list, head);

		rcu_read_lock();
		if (task_pid(p) && !ns_of_pid(task_pid(p)))
			printk(KERN_ERR "what the hell: %s\n", p->comm);
		rcu_read_unlock();
		if (task_pid_nr(p) == node->pid) {
			ret = true;
			break;
		}
	}
out:
	spin_unlock(&pstrace_list_lock);
	local_irq_restore(flags);
	return ret;
}

void pstrace_add(struct task_struct *p)
{
	struct pstrace_kernel *pst = &pstrace;
	int head, tail;
	struct list_head *evt_list;
	unsigned long flags;

	if (!p)
		return;
	if (p->group_leader != p)
		return;

	if (!task_is_pstraced(p))
		return;

	/* add an entry */
	local_irq_save(flags);
	spin_lock(&pst->pstrace_lock);
	head = pst->head;
	tail = pst->tail;

	if (tail == PSTRACE_BUF_SIZE - 1)
		tail = 0;
	else
		tail++;
	pst->tail = tail;

	if (likely(head == tail)) {
		head++;
		pst->head = head == PSTRACE_BUF_SIZE ? 0 : head;
	}

	if (p->exit_state == EXIT_ZOMBIE || p->exit_state == EXIT_DEAD)
		pst->entry[tail].state = p->exit_state;
	else
		pst->entry[tail].state = p->state;
	get_task_comm(pst->entry[tail].comm, p);
	pst->entry[tail].pid = p->pid;
	pst->del[tail] = false;
	atomic_add(1, &pst->counter);
	spin_unlock(&pst->pstrace_lock);

	if (atomic_read(&in_wake_up))
		goto out;

	spin_lock(&pstrace_evt_list_lock);
	list_for_each(evt_list, &pstrace_evt_list) {
		struct pstrace_evt *evt = list_entry(evt_list,
				struct pstrace_evt, head);

		if (evt->counter <= atomic_read(&pst->counter)) {
			int nr_entries;

			if (!evt->woken) {
				spin_lock(&pst->pstrace_lock);
				nr_entries = pstrace_get_buf(pst, evt->buf,
							     evt->pid);
				spin_unlock(&pst->pstrace_lock);
				evt->nr_entries = nr_entries;
			}
			evt->woken = true;

			atomic_add(1, &in_wake_up);
			wake_up_all(&evt->evt_waitq);
			atomic_sub(1, &in_wake_up);
		}
	}
	spin_unlock(&pstrace_evt_list_lock);
out:
	local_irq_restore(flags);
}

unsigned long pstrace_get_nowait(struct pstrace_kernel *pst, pid_t pid,
				 struct pstrace __user *buf,
				 unsigned long __user *counter)
{
	struct pstrace *kbuf;
	int nr_copied;
	unsigned long ret;
	unsigned long kcounter;
	unsigned long flags;

	kbuf = kmalloc(sizeof(struct pstrace) * PSTRACE_BUF_SIZE,
			GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		return ret;
	}

	local_irq_save(flags);
	spin_lock(&pstrace_list_lock);
	nr_copied = pstrace_get_buf(pst, kbuf, pid);
	spin_unlock(&pstrace_list_lock);
	local_irq_restore(flags);

	if (copy_to_user(buf, kbuf,
			 PSTRACE_BUF_SIZE * sizeof(struct pstrace))) {
		ret = -EINVAL;
		goto out;
	}

	kcounter = atomic_read(&pst->counter);
	if (put_user(kcounter, counter)) {
		ret = -EINVAL;
		goto out;
	}
	ret = nr_copied;
out:
	kfree(kbuf);
	return ret;
}

SYSCALL_DEFINE3(pstrace_get, pid_t, pid, struct pstrace __user *, buf,
		long __user *, counter)
{
	struct pstrace_evt *evt;
	unsigned long ret = 0;
	long kcounter;
	struct pstrace_kernel *pst = &pstrace;
	DEFINE_WAIT(wait);

	if (!access_ok(buf, sizeof(struct pstrace) * PSTRACE_BUF_SIZE))
		return -EINVAL;

	if (get_user(kcounter, counter))
		return -EINVAL;

	if (kcounter <= 0) {
		ret = pstrace_get_nowait(pst, pid, buf, counter);
		return ret;
	}

	evt = kmalloc(sizeof(struct pstrace_evt), GFP_KERNEL);
	if (!evt)
		return -ENOMEM;

	evt->pid = pid;
	evt->counter = kcounter + PSTRACE_BUF_SIZE - 1;
	evt->woken = false;
	init_waitqueue_head(&evt->evt_waitq);

	spin_lock(&pstrace_evt_list_lock);
	list_add(&evt->head, &pstrace_evt_list);
	spin_unlock(&pstrace_evt_list_lock);

	printk(KERN_ERR "pstrace_get: %d\n", pid);
	spin_lock(&evt->evt_waitq.lock);
	do {
		__add_wait_queue_entry_tail(&evt->evt_waitq, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&evt->evt_waitq.lock);
		/* Sleep */
		schedule();
		/* Finally, we are woken up. */
		spin_lock(&evt->evt_waitq.lock);
	} while (!evt->woken);

	__remove_wait_queue(&evt->evt_waitq, &wait);
	__set_current_state(TASK_RUNNING);
	ret = evt->nr_entries;
	spin_unlock(&evt->evt_waitq.lock);

	spin_lock(&pstrace_evt_list_lock);
	list_del(&evt->head);
	spin_unlock(&pstrace_evt_list_lock);

	if (copy_to_user(buf, evt->buf,
			 PSTRACE_BUF_SIZE * sizeof(struct pstrace)))
		ret = -EINVAL;

	kcounter = atomic_read(&pst->counter);
	if (put_user(kcounter, counter))
		return -EINVAL;

	kfree(evt);
	return ret;
}

SYSCALL_DEFINE1(pstrace_enable, pid_t, pid)
{
	struct pstrace_list *node;
	unsigned long flags;

	if (pid == -1) {
		spin_lock(&pstrace.pstrace_lock);
		pstrace.trace_all = true;
		spin_unlock(&pstrace.pstrace_lock);

		return 0;
	}

	if (pid != 0 && !find_task_by_vpid(pid))
		return -ESRCH;

	node = kmalloc(sizeof(struct pstrace_list), GFP_KERNEL);

	if (!node)
		return -ENOMEM;

	node->pid = pid;
	local_irq_save(flags);
	spin_lock(&pstrace_list_lock);
	list_add(&node->head, &pstrace_list);
	spin_unlock(&pstrace_list_lock);
	local_irq_restore(flags);

	return 0;
}

/* Assume pstrace_lock is hold */
static void pstrace_free_pid(pid_t pid)
{
	struct pstrace_list *node;

	while (!list_empty(&pstrace_list)) {
		node = list_first_entry(&pstrace_list,
					struct pstrace_list, head);
		if (node->pid == pid || pid == -1) {
			list_del(&node->head);
			kfree(node);
		}
	}
}

static void pstrace_free_all(void)
{
	pstrace_free_pid(-1);
}

SYSCALL_DEFINE1(pstrace_disable, pid_t, pid)
{
	unsigned long flags;

	if (pid == -1) {
		spin_lock(&pstrace.pstrace_lock);
		pstrace.trace_all = false;
		pstrace_free_all();
		spin_unlock(&pstrace.pstrace_lock);

		return 0;
	}

	local_irq_save(flags);
	spin_lock(&pstrace_list_lock);
	pstrace_free_pid(pid);
	spin_unlock(&pstrace_list_lock);
	local_irq_restore(flags);

	return 0;
}

SYSCALL_DEFINE1(pstrace_clear, pid_t, pid)
{
	int i;
	struct pstrace_kernel *pst = &pstrace;
	struct list_head *evt_list;

	printk(KERN_ERR "pstrace_clear: %d\n", pid);
	/* No re-entrance issue here */
	spin_lock(&pstrace_evt_list_lock);
	list_for_each(evt_list, &pstrace_evt_list) {
		struct pstrace_evt *evt = list_entry(evt_list,
				struct pstrace_evt, head);

		if (evt->pid == pid || pid == -1) {
			int nr_entries;

			if (!evt->woken) {
				spin_lock(&pst->pstrace_lock);
				nr_entries = pstrace_get_buf(pst, evt->buf,
							     evt->pid);
				spin_unlock(&pst->pstrace_lock);
				evt->nr_entries = nr_entries;
			}
			evt->woken = true;

			wake_up_all(&evt->evt_waitq);
		}
	}
	spin_unlock(&pstrace_evt_list_lock);

	spin_lock(&pst->pstrace_lock);
	for (i = 0; i < PSTRACE_BUF_SIZE; i++) {
		if (pst->entry[i].pid == pid || pid == -1)
			pst->del[i] = true;
	}
	spin_unlock(&pst->pstrace_lock);
	return 0;
}
