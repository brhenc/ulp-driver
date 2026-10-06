// SPDX-License-Identifier: GPL-2.0-only
/*
 * ulp-driver: x86_64 userspace livepatching driver (experimental)
 *
 * Writes function-entry trampolines into target processes, tracks applied
 * patches, re-applies them across fork/exec via persistent rules, and can
 * hand its state over across module reloads.
 *
 * Design notes:
 *   1. Tracking state is allocated before process memory is modified, so an
 *      allocation failure never leaves an untracked patch behind.
 *   2. Trampolines are written in 8-byte chunks (see ulp_atomic_direct_poke()
 *      for the ordering). The stores are not atomic as a whole: callers must
 *      stop the target's threads first (ulp_ctl does, via ptrace); see TODO.md.
 *   3. Records for exited processes are reaped to avoid PID-reuse confusion.
 *   4. List and thread traversals have explicit iteration bounds.
 *   5. VMA checks run under mmap_read_lock, released before access_process_vm().
 *   6. kernel.ulp_scope: 0 = disabled, 1 = same user, 2 = root only,
 *      3 = root only and locked until reboot.
 *   7. Reverts are authorized against the patch creator's UID.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/version.h>
#include <linux/elf.h>
#include <linux/file.h>
#include <linux/sched/coredump.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
#include <linux/sched/exec_state.h>
#endif
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmap_lock.h>
#include <linux/smp.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include <linux/sysctl.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/highmem.h>
#include <linux/task_work.h>
#include <linux/kfifo.h>
#include <linux/poll.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/moduleparam.h>
#include "ulp_uapi.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
#ifndef del_timer
#define del_timer(t) timer_delete(t)
#endif
#ifndef del_timer_sync
#define del_timer_sync(t) timer_delete_sync(t)
#endif
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ulp-driver <bhenc@ceresia.ch>");
MODULE_DESCRIPTION("x86_64 userspace livepatching driver (experimental)");
MODULE_VERSION("3.0.0");

#define ULP_MAX_LOOP_ITERS 10000

/* Telemetry event ring buffer, read from /dev/ulp */
static DEFINE_KFIFO(g_event_fifo, struct ulp_event, 256);
static DEFINE_SPINLOCK(g_event_lock);
static DECLARE_WAIT_QUEUE_HEAD(g_event_wq);

/* Fail-Closed Arming State Machine */
static enum ulp_driver_state g_driver_state = ULP_STATE_LOCKED;
static u32 g_arm_nonce;
static unsigned long g_armed_until;
static struct timer_list g_arm_timer;
static DEFINE_SPINLOCK(g_arm_lock);

static void ulp_push_event(enum ulp_event_type type, u32 pid, u32 uid, u64 vaddr,
						   const char *comm, const char *patch_name, const char *msg)
{
	struct ulp_event ev;
	unsigned long flags;

	memset(&ev, 0, sizeof(ev));
	ev.timestamp_ns = ktime_get_real_ns();
	ev.event_type = type;
	ev.pid = pid;
	ev.uid = uid;
	ev.vaddr = vaddr;
	if (comm)
		strscpy(ev.comm, comm, sizeof(ev.comm));
	if (patch_name)
		strscpy(ev.patch_name, patch_name, sizeof(ev.patch_name));
	if (msg)
		strscpy(ev.msg, msg, sizeof(ev.msg));

	spin_lock_irqsave(&g_event_lock, flags);
	kfifo_put(&g_event_fifo, ev);
	spin_unlock_irqrestore(&g_event_lock, flags);

	wake_up_interruptible(&g_event_wq);
}

static void ulp_arm_timer_fn(struct timer_list *t)
{
	unsigned long flags;

	spin_lock_irqsave(&g_arm_lock, flags);
	if (g_driver_state == ULP_STATE_ARMED) {
		g_driver_state = ULP_STATE_LOCKED;
		g_arm_nonce = 0;
		pr_info("[ulp_driver] Maintenance arming session expired (TTL elapsed). Driver locked into fail-closed enforce mode.\n");
		ulp_push_event(ULP_EVT_DISARMED, 0, 0, 0, "kernel", "ttl_expiry", "Session TTL elapsed; locked");
	}
	spin_unlock_irqrestore(&g_arm_lock, flags);
}

/* Sysctl Scope Configuration */
static int ulp_scope = ULP_SCOPE_ROOT_ONLY; /* Default: 2 (Root only) */
static int ulp_scope_min = ULP_SCOPE_DISABLED;
static int ulp_scope_max = ULP_SCOPE_LOCKED;
static bool ulp_dev_mode;
module_param_named(dev_mode, ulp_dev_mode, bool, 0644);
MODULE_PARM_DESC(dev_mode, "Developer mode: allows module unload and scope changes in Scope 3 for testing");

static bool ulp_module_pinned;

static int ulp_sysctl_handler(const struct ctl_table *table, int write,
							  void *buffer, size_t *lenp, loff_t *ppos)
{
	int old_val = READ_ONCE(ulp_scope);
	int new_val = old_val;
	struct ctl_table tmp_tbl = *table;
	int ret;

	tmp_tbl.data = &new_val;
	ret = proc_dointvec_minmax(&tmp_tbl, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (write) {
		/* If previously locked (Mode 3), prevent lowering scope unless in dev_mode */
		if (old_val == ULP_SCOPE_LOCKED && new_val < ULP_SCOPE_LOCKED && !ulp_dev_mode) {
			pr_warn("[ulp_driver] Attempt to lower kernel.ulp_scope from locked mode rejected\n");
			return -EPERM;
		}

		/* In production (dev_mode=false), permanently pin module in memory when locked */
		if (new_val == ULP_SCOPE_LOCKED && !ulp_module_pinned && !ulp_dev_mode) {
			if (try_module_get(THIS_MODULE)) {
				ulp_module_pinned = true;
				pr_info("[ulp_driver] kernel.ulp_scope is now LOCKED (3). Module pinned permanently until reboot.\n");
			}
		}

		WRITE_ONCE(ulp_scope, new_val);
		pr_info("[ulp_driver] kernel.ulp_scope changed: %d -> %d\n", old_val, new_val);
	}
	return 0;
}

static struct ctl_table ulp_sysctl_table[] = {
	{
		.procname      = "ulp_scope",
		.data          = &ulp_scope,
		.maxlen        = sizeof(int),
		.mode          = 0644,
		.proc_handler  = ulp_sysctl_handler,
		.extra1        = &ulp_scope_min,
		.extra2        = &ulp_scope_max,
	},
};
static struct ctl_table_header *ulp_sysctl_header;

struct ulp_patch_entry {
	struct list_head list;
	struct rcu_head rcu;
	struct ulp_patch_info info;
	uid_t creator_uid;
	__u8 orig_bytes[16];
	__u8 patch_bytes[16];
};

static LIST_HEAD(g_patch_list);
static DEFINE_SPINLOCK(g_patch_lock);
static atomic_t g_active_patches = ATOMIC_INIT(0);

struct ulp_kernel_rule {
	struct list_head list;
	struct rcu_head rcu;
	struct ulp_kernel_rule_req req;
	uid_t creator_uid;
	u8 enabled;
};

static LIST_HEAD(g_rule_list);
static DEFINE_SPINLOCK(g_rule_lock);
static atomic_t g_active_rules = ATOMIC_INIT(0);

/* =========================================================================
 * Driver Resumption & State Handoff Architecture
 * =========================================================================
 */
#define ULP_STATE_MAGIC 0x554C505354415445ULL /* "ULPSTATE" */
#define ULP_STATE_VERSION 2 /* v2: rules carry a build-id */
#define ULP_DEFAULT_STATE_FILE "/run/ulp/state.bin"
#define ULP_FALLBACK_STATE_FILE "/run/ulp_state.bin"

struct ulp_state_header {
	__u64 magic;
	__u32 version;
	__u32 patch_count;
	__u32 rule_count;
	__u32 scope;
	__u64 timestamp_ns;
};

struct ulp_state_patch_record {
	struct ulp_patch_info info;
	__u8 orig_bytes[16];
	__u8 patch_bytes[16];
	__u32 creator_uid;
};

struct ulp_state_rule_record {
	struct ulp_kernel_rule_req req;
	__u32 creator_uid;
	__u8 enabled;
	__u8 _pad[3];
};

static bool ulp_allow_resumption;
static bool ulp_resume;
static atomic_t g_pinned_refs = ATOMIC_INIT(0);

static int ulp_allow_resumption_set(const char *val, const struct kernel_param *kp)
{
	bool old_val = ulp_allow_resumption;
	int ret;
	unsigned long flags;

	ret = param_set_bool(val, kp);
	if (ret)
		return ret;

	if (ulp_allow_resumption == old_val)
		return 0;

	spin_lock_irqsave(&g_patch_lock, flags);
	if (ulp_allow_resumption) {
		while (atomic_read(&g_pinned_refs) > 0) {
			module_put(THIS_MODULE);
			atomic_dec(&g_pinned_refs);
		}
		pr_info("[ulp_driver] Resumption mode ENABLED: Module reference pinning released. State will serialize on unload.\n");
	} else {
		int count = atomic_read(&g_active_patches);
		int i;

		for (i = 0; i < count; i++) {
			if (try_module_get(THIS_MODULE))
				atomic_inc(&g_pinned_refs);
		}
		pr_info("[ulp_driver] resumption disabled: module pinned while patches are active (%d refs)\n",
				atomic_read(&g_pinned_refs));
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	return 0;
}

static const struct kernel_param_ops ulp_allow_resumption_ops = {
	.set = ulp_allow_resumption_set,
	.get = param_get_bool,
};

module_param_cb(allow_resumption, &ulp_allow_resumption_ops, &ulp_allow_resumption, 0644);
MODULE_PARM_DESC(allow_resumption, "Allow module unload without reverting userspace livepatches and serialize state for seamless resumption");

module_param_named(resume, ulp_resume, bool, 0644);
MODULE_PARM_DESC(resume, "Restore active livepatches and rules from saved state on module load");

static inline bool ulp_pin_module_ref(void)
{
	if (!READ_ONCE(ulp_allow_resumption)) {
		if (!try_module_get(THIS_MODULE))
			return false;
		atomic_inc(&g_pinned_refs);
	}
	return true;
}

static inline void ulp_unpin_module_ref(void)
{
	if (atomic_read(&g_pinned_refs) > 0) {
		module_put(THIS_MODULE);
		atomic_dec(&g_pinned_refs);
	}
}

/* Tracking kprobe registration states */
static bool g_kp_fork_registered;
static bool g_kp_exec_registered;

/* Emergency override state, validated with a 256-bit magic value */
static struct {
	u64 magic[4];
	char binary_path[128];
	unsigned long expires_jiffies;
	u32 active;
} g_override_state;

static void ulp_ipi_sync_core(void *info)
{
	/* On x86, IPI interrupt entry/exit serializes the CPU pipeline */
	smp_mb();
}

static struct task_struct *ulp_get_task_by_pid(pid_t nr)
{
	struct task_struct *task = NULL;
	struct pid *pid_struct;

	rcu_read_lock();
	pid_struct = find_vpid(nr);
	if (pid_struct) {
		task = pid_task(pid_struct, PIDTYPE_PID);
		if (task)
			get_task_struct(task);
	}
	rcu_read_unlock();
	return task;
}

/* True if the target may be ptraced by a same-credential user (dumpable == "owner") */
static bool ulp_task_dumpable_by_owner(struct task_struct *task, struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 2, 0)
	/* 7.2+: dumpability lives in task->exec_state; the accessor is not exported */
	struct task_exec_state *es;
	bool ret;

	rcu_read_lock();
	es = rcu_dereference(task->exec_state);
	ret = es && READ_ONCE(es->dumpable) == TASK_DUMPABLE_OWNER;
	rcu_read_unlock();
	return ret;
#else
	return get_dumpable(mm) == SUID_DUMP_USER;
#endif
}

/* Enforce sysctl scope, capability, and DAC user boundaries */
static bool ulp_check_access(struct task_struct *task, struct mm_struct *mm, bool is_revert)
{
	const struct cred *tcred;
	bool allowed = false;
	int current_scope = READ_ONCE(ulp_scope);

	/* Emergency Revert Path: Root can always revert even if scope is 0 (Disabled) */
	if (is_revert && capable(CAP_SYS_ADMIN))
		return true;

	/* Mode 0: Disabled system-wide */
	if (current_scope == ULP_SCOPE_DISABLED) {
		pr_warn_ratelimited("[ulp_driver] Operation rejected: kernel.ulp_scope is 0 (Disabled)\n");
		return false;
	}

	/* Mode 2 & 3: Root (CAP_SYS_ADMIN) only */
	if (current_scope >= ULP_SCOPE_ROOT_ONLY)
		return capable(CAP_SYS_ADMIN);

	/* Mode 1 (ULP_SCOPE_USER_SAME_UID): Root OR matching UID/EUID/SUID for unprivileged users */
	if (capable(CAP_SYS_ADMIN))
		return true;

	/*
	 * Writing to another process's text is equivalent to ptrace attach.
	 * ptrace_may_access() is not exported to modules, so mirror its core
	 * checks here: refuse non-dumpable targets (setuid binaries, processes
	 * that dropped privileges or called prctl(PR_SET_DUMPABLE, 0)), then
	 * require fully matching credentials. Yama and LSM ptrace hooks are not
	 * reachable from a module and are NOT applied.
	 */
	if (!ulp_task_dumpable_by_owner(task, mm))
		return false;

	rcu_read_lock();
	tcred = __task_cred(task);
	if (tcred) {
		if (uid_eq(current_uid(), tcred->uid) &&
			uid_eq(current_euid(), tcred->euid) &&
			uid_eq(current_uid(), tcred->suid) &&
			uid_eq(tcred->uid, tcred->euid) &&
			gid_eq(current_gid(), tcred->gid) &&
			gid_eq(current_egid(), tcred->egid) &&
			gid_eq(current_gid(), tcred->sgid)) {
			allowed = true;
		}
	}
	rcu_read_unlock();

	return allowed;
}

/* Verify that target virtual address is in a valid, executable memory segment */
static int ulp_verify_vma(struct mm_struct *mm, __u64 vaddr)
{
	struct vm_area_struct *vma;
	int ret = 0;

	mmap_read_lock(mm);
	vma = find_vma(mm, vaddr);
	if (!vma || vaddr < vma->vm_start || (vaddr + 16) > vma->vm_end) {
		pr_err("[ulp_driver] Target vaddr 0x%llx is outside valid VMA bounds\n", vaddr);
		ret = -EINVAL;
	} else if (!(vma->vm_flags & VM_EXEC)) {
		pr_err("[ulp_driver] Target vaddr 0x%llx is not in an executable VMA (flags=0x%lx)\n",
			   vaddr, vma->vm_flags);
		ret = -EACCES;
	}
	mmap_read_unlock(mm);

	return ret;
}

/* Verify that no thread in the process is currently executing inside the target function */
static int ulp_verify_thread_quiescence(struct task_struct *task, __u64 vaddr_start, __u32 func_len)
{
	struct task_struct *t;
	__u64 vaddr_end;
	size_t iters = 0;

	/* Default a zero length to the 16-byte trampoline window */
	if (func_len == 0)
		func_len = 16;

	if (func_len < 5) {
		pr_warn("[ulp_driver] Quiescence rejected: func_len (%u) is less than minimum 5-byte trampoline size\n", func_len);
		return -EINVAL;
	}

	vaddr_end = vaddr_start + func_len;

	rcu_read_lock();
	for_each_thread(task, t) {
		struct pt_regs *regs;

		if (++iters > ULP_MAX_LOOP_ITERS) {
			pr_warn_ratelimited("[ulp_driver] Quiescence check reached max thread loop bound\n");
			break;
		}
		regs = task_pt_regs(t);
		if (regs && regs->ip >= vaddr_start && regs->ip < vaddr_end) {
			rcu_read_unlock();
			pr_warn("[ulp_driver] Quiescence check failed: Thread TID %u has IP 0x%lx inside target [0x%llx - 0x%llx]\n",
					t->pid, (unsigned long)regs->ip, vaddr_start, vaddr_end);
			return -EAGAIN;
		}
	}
	rcu_read_unlock();

	return 0;
}

/* Verify that the associated futex / mutex is unlocked (val == 0) */
static int ulp_verify_futex_unlocked(struct task_struct *task, __u64 futex_vaddr)
{
	__u32 futex_val = 0;
	int bytes;

	if (!futex_vaddr)
		return 0;

	bytes = access_process_vm(task, futex_vaddr, &futex_val, sizeof(futex_val), 0);
	if (bytes != sizeof(futex_val)) {
		pr_err("[ulp_driver] Failed to read futex at 0x%llx\n", futex_vaddr);
		return -EFAULT;
	}

	if (futex_val != 0) {
		pr_warn("[ulp_driver] Target futex at 0x%llx is currently LOCKED (val=0x%x). Rejecting patch.\n",
				futex_vaddr, futex_val);
		return -EBUSY;
	}

	return 0;
}

/* Atomic Direct Text Poke (Supports 5-byte relative and 16-byte absolute trampolines) */
static int ulp_atomic_direct_poke(struct task_struct *task, __u64 vaddr, const __u8 *new_bytes, __u32 tramp_len, bool is_revert)
{
	int bytes;

	if (tramp_len == 5) {
		__u8 word[8];
		/* Read original 8-byte word */
		bytes = access_process_vm(task, vaddr, word, 8, 0);
		if (bytes != 8)
			return -EFAULT;

		/* Overlay 5 new bytes onto the word, preserving upper 3 bytes */
		memcpy(word, new_bytes, 5);

		/* Single atomic 8-byte write */
		bytes = access_process_vm(task, vaddr, word, 8, FOLL_WRITE | FOLL_FORCE);
		if (bytes != 8)
			return -EFAULT;
	} else if (is_revert) {
		/*
		 * On revert, write the leading 8 entry bytes first.
		 * Neutralizes entry detour immediately, preventing threads from jumping
		 * into partially restored trailing payload.
		 */
		bytes = access_process_vm(task, vaddr, (void *)new_bytes, 8, FOLL_WRITE | FOLL_FORCE);
		if (bytes != 8)
			return -EFAULT;

		/* Restore trailing 8 payload bytes */
		bytes = access_process_vm(task, vaddr + 8, (void *)(new_bytes + 8), 8, FOLL_WRITE | FOLL_FORCE);
		if (bytes != 8)
			return -EFAULT;
	} else {
		/*
		 * On apply, write trailing 8 payload bytes first, then atomically write
		 * leading 8 entry bytes to activate detour in one cycle.
		 */
		bytes = access_process_vm(task, vaddr + 8, (void *)(new_bytes + 8), 8, FOLL_WRITE | FOLL_FORCE);
		if (bytes != 8)
			return -EFAULT;

		/* Atomically write leading 8 entry bytes */
		bytes = access_process_vm(task, vaddr, (void *)new_bytes, 8, FOLL_WRITE | FOLL_FORCE);
		if (bytes != 8)
			return -EFAULT;
	}

	/* Core pipeline sync */
	on_each_cpu(ulp_ipi_sync_core, NULL, 1);

	return 0;
}

/* Automatically reap entries belonging to terminated processes */
static void ulp_reap_dead_entries_locked(void)
{
	struct ulp_patch_entry *entry, *tmp;
	struct pid *pid_struct;
	size_t iters = 0;

	list_for_each_entry_safe(entry, tmp, &g_patch_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS)
			break;
		rcu_read_lock();
		pid_struct = find_vpid(entry->info.target_pid);
		if (!pid_struct || !pid_task(pid_struct, PIDTYPE_PID)) {
			rcu_read_unlock();
			pr_info("[ulp_driver] Auto-reaping orphaned livepatch for terminated PID %u\n",
					entry->info.target_pid);
			list_del_rcu(&entry->list);
			atomic_dec(&g_active_patches);
			ulp_unpin_module_ref();
			kfree_rcu(entry, rcu);
		} else {
			rcu_read_unlock();
		}
	}
}

static long ulp_apply_patch(struct ulp_patch_req *req)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct ulp_patch_entry *entry, *existing = NULL;
	struct ulp_patch_entry *new_entry = NULL;
	int bytes, ret = 0;
	uid_t target_uid = 0;
	uid_t caller_uid = from_kuid(&init_user_ns, current_uid());
	size_t iters = 0;

	/* Ensure string inputs are safely null-terminated */
	req->patch_name[ULP_NAME_MAX - 1] = '\0';
	req->func_name[ULP_NAME_MAX - 1] = '\0';

	task = ulp_get_task_by_pid(req->target_pid);
	if (!task) {
		pr_err("[ulp_driver] Target PID %u not found\n", req->target_pid);
		return -ESRCH;
	}

	/* Pin target mm lifecycle across the entire operation */
	mm = get_task_mm(task);
	if (!mm) {
		pr_err("[ulp_driver] Target PID %u has no active mm\n", req->target_pid);
		put_task_struct(task);
		return -ESRCH;
	}

	/* Enforce sysctl scope and DAC security boundaries */
	if (!ulp_check_access(task, mm, false)) {
		pr_err("[ulp_driver] Access denied for caller targeting PID %u under scope %d\n",
			   req->target_pid, READ_ONCE(ulp_scope));
		mmput(mm);
		put_task_struct(task);
		return -EPERM;
	}

	/* Verify VMA executable mapping */
	ret = ulp_verify_vma(mm, req->target_vaddr);
	if (ret) {
		mmput(mm);
		put_task_struct(task);
		return ret;
	}

	if (req->patch_vaddr != 0) {
		ret = ulp_verify_vma(mm, req->patch_vaddr);
		if (ret) {
			pr_err("[ulp_driver] Patch vaddr 0x%llx is invalid or not executable\n", req->patch_vaddr);
			mmput(mm);
			put_task_struct(task);
			return ret;
		}
	}

	/* Verify 8-byte natural alignment to guarantee atomic instruction stream updates */
	if (req->target_vaddr & 0x7) {
		pr_err("[ulp_driver] Target virtual address 0x%llx is not 8-byte aligned (torn write hazard)\n",
			   req->target_vaddr);
		mmput(mm);
		put_task_struct(task);
		return -EINVAL;
	}

	/* Verify thread stack quiescence and minimum symbol size (func_len >= 16) */
	ret = ulp_verify_thread_quiescence(task, req->target_vaddr, req->func_len);
	if (ret) {
		mmput(mm);
		put_task_struct(task);
		return ret;
	}

	/* Check Futex Lock State */
	if (req->futex_vaddr) {
		ret = ulp_verify_futex_unlocked(task, req->futex_vaddr);
		if (ret) {
			mmput(mm);
			put_task_struct(task);
			return ret;
		}
	}

	rcu_read_lock();
	if (__task_cred(task))
		target_uid = from_kuid(&init_user_ns, __task_cred(task)->uid);
	rcu_read_unlock();

	__u32 tramp_len = 16;
	__s64 disp = (__s64)req->patch_vaddr - ((__s64)req->target_vaddr + 5);

	/* 1. Build trampoline (5-byte relative jump if size < 16 or requested, otherwise 16-byte absolute) */
	if (req->tramp_type == ULP_TRAMP_REL5 ||
		(req->tramp_type == ULP_TRAMP_AUTO && req->func_len > 0 && req->func_len < 16)) {
		if (disp < -2147483648LL || disp > 2147483647LL) {
			pr_err("[ulp_driver] Relative jump displacement out of range (0x%llx -> 0x%llx)\n",
				   req->target_vaddr, req->patch_vaddr);
			mmput(mm);
			put_task_struct(task);
			return -ERANGE;
		}
		req->patch_bytes[0] = 0xe9; /* jmp rel32 */
		memcpy(&req->patch_bytes[1], &disp, 4);
		memset(&req->patch_bytes[5], 0x90, 11); /* NOP padding */
		tramp_len = 5;
	} else {
		/* 16-byte CET/IBT-compliant absolute trampoline */
		req->patch_bytes[0] = 0xf3; /* endbr64 */
		req->patch_bytes[1] = 0x0f;
		req->patch_bytes[2] = 0x1e;
		req->patch_bytes[3] = 0xfa;
		req->patch_bytes[4] = 0x48; /* movabs $target, %rax */
		req->patch_bytes[5] = 0xb8;
		memcpy(&req->patch_bytes[6], &req->patch_vaddr, sizeof(__u64));
		req->patch_bytes[14] = 0xff; /* jmpq *%rax */
		req->patch_bytes[15] = 0xe0;
		tramp_len = 16;
	}

	/* 2. Allocate the tracking node before modifying process memory */
	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry) {
		mmput(mm);
		put_task_struct(task);
		return -ENOMEM;
	}

	unsigned long flags;

	spin_lock_irqsave(&g_patch_lock, flags);
	ulp_reap_dead_entries_locked();

	list_for_each_entry(entry, &g_patch_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS)
			break;
		if (entry->info.target_pid == req->target_pid &&
			entry->info.target_vaddr == req->target_vaddr) {
			existing = entry;
			memcpy(req->orig_bytes, existing->orig_bytes, 16);
			break;
		}
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	if (!existing) {
		/* Pin the module while patches are active, unless resumption mode is enabled */
		if (!ulp_pin_module_ref()) {
			pr_err("[ulp_driver] Module is unloading. Rejecting patch application.\n");
			kfree(new_entry);
			mmput(mm);
			put_task_struct(task);
			return -EBUSY;
		}

		/* Read original 16 prologue bytes from unpatched process */
		bytes = access_process_vm(task, req->target_vaddr, req->orig_bytes, 16, 0);
		if (bytes != 16) {
			pr_err("[ulp_driver] Failed to read original prologue at 0x%llx\n", req->target_vaddr);
			ulp_unpin_module_ref();
			kfree(new_entry);
			mmput(mm);
			put_task_struct(task);
			return -EFAULT;
		}
	}

	/* 3. Atomic direct text poke (is_revert = false) */
	ret = ulp_atomic_direct_poke(task, req->target_vaddr, req->patch_bytes, tramp_len, false);
	if (ret) {
		pr_err("[ulp_driver] Atomic text poke failed at 0x%llx\n", req->target_vaddr);
		if (!existing)
			ulp_unpin_module_ref();
		kfree(new_entry);
		mmput(mm);
		put_task_struct(task);
		return ret;
	}

	/* 4. Commit tracking entry into registry */
	spin_lock_irqsave(&g_patch_lock, flags);
	existing = NULL;
	list_for_each_entry(entry, &g_patch_list, list) {
		if (entry->info.target_pid == req->target_pid &&
			entry->info.target_vaddr == req->target_vaddr) {
			existing = entry;
			break;
		}
	}

	if (!existing) {
		entry = new_entry;
		entry->info.target_pid = req->target_pid;
		entry->info.owner_uid = target_uid;
		entry->creator_uid = caller_uid;
		get_task_comm(entry->info.comm, task);
		strscpy(entry->info.patch_name, req->patch_name[0] ? req->patch_name : "unnamed_patch", ULP_NAME_MAX);
		strscpy(entry->info.func_name, req->func_name[0] ? req->func_name : "unknown_func", ULP_NAME_MAX);
		entry->info.target_vaddr = req->target_vaddr;
		entry->info.patch_vaddr = req->patch_vaddr;
		entry->info.tramp_len = tramp_len;
		entry->info.enabled = 1;
		memcpy(entry->orig_bytes, req->orig_bytes, 16);
		memcpy(entry->patch_bytes, req->patch_bytes, 16);
		list_add_tail_rcu(&entry->list, &g_patch_list);
		atomic_inc(&g_active_patches);
	} else {
		existing->info.enabled = 1;
		existing->creator_uid = caller_uid;
		if (req->patch_name[0])
			strscpy(existing->info.patch_name, req->patch_name, ULP_NAME_MAX);
		if (req->func_name[0])
			strscpy(existing->info.func_name, req->func_name, ULP_NAME_MAX);
		existing->info.patch_vaddr = req->patch_vaddr;
		existing->info.tramp_len = tramp_len;
		memcpy(existing->patch_bytes, req->patch_bytes, 16);
		kfree(new_entry);
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	pr_info("[ulp_driver] Livepatch applied [scope %d, len %u]: PID %u (%s, UID %u, creator %u) -> %s::%s [0x%llx -> 0x%llx]\n",
			READ_ONCE(ulp_scope), tramp_len, req->target_pid, task->comm, target_uid, caller_uid,
			req->patch_name, req->func_name,
			req->target_vaddr, req->patch_vaddr);

	mmput(mm);
	put_task_struct(task);
	return 0;
}

static long ulp_revert_patch(struct ulp_patch_req *req)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct ulp_patch_entry *entry, *found = NULL;
	uid_t caller_uid = from_kuid(&init_user_ns, current_uid());
	bool is_admin = capable(CAP_SYS_ADMIN);
	size_t iters = 0;
	int ret;
	unsigned long flags;

	task = ulp_get_task_by_pid(req->target_pid);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -ESRCH;
	}

	/* Enforce sysctl scope and DAC security boundaries */
	if (!ulp_check_access(task, mm, true)) {
		pr_err("[ulp_driver] Revert access denied for caller targeting PID %u under scope %d\n",
			   req->target_pid, READ_ONCE(ulp_scope));
		mmput(mm);
		put_task_struct(task);
		return -EPERM;
	}

	__u8 orig_bytes[16];
	__u32 tramp_len = 0;
	uid_t creator_uid = 0;

	spin_lock_irqsave(&g_patch_lock, flags);
	ulp_reap_dead_entries_locked();
	list_for_each_entry(entry, &g_patch_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS)
			break;
		if (entry->info.target_pid == req->target_pid &&
			entry->info.target_vaddr == req->target_vaddr) {
			found = entry;
			memcpy(orig_bytes, entry->orig_bytes, 16);
			memcpy(req->orig_bytes, entry->orig_bytes, 16);
			tramp_len = entry->info.tramp_len;
			creator_uid = entry->creator_uid;
			break;
		}
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	/* Prevent silent corruption/zeroing on unknown targets */
	if (!found) {
		pr_err("[ulp_driver] Revert rejected: No active patch registered for PID %u at 0x%llx\n",
			   req->target_pid, req->target_vaddr);
		mmput(mm);
		put_task_struct(task);
		return -ENOENT;
	}

	/* Enforce patch ownership: Only root or the original patch creator can revert */
	if (!is_admin && caller_uid != creator_uid) {
		pr_warn("[ulp_driver] Revert rejected: Caller UID %u is not creator UID %u and lacks CAP_SYS_ADMIN\n",
				caller_uid, creator_uid);
		mmput(mm);
		put_task_struct(task);
		return -EPERM;
	}

	/* Verify thread stack quiescence before restoring prologue */
	ret = ulp_verify_thread_quiescence(task, req->target_vaddr, tramp_len);
	if (ret) {
		pr_warn("[ulp_driver] Revert delayed: Thread stack not quiescent for PID %u\n", req->target_pid);
		mmput(mm);
		put_task_struct(task);
		return ret;
	}

	/* Atomic direct restoration of true original prologue bytes (is_revert = true) */
	ret = ulp_atomic_direct_poke(task, req->target_vaddr, orig_bytes, tramp_len, true);
	if (ret) {
		pr_err("[ulp_driver] Failed to restore original bytes at 0x%llx\n", req->target_vaddr);
		mmput(mm);
		put_task_struct(task);
		return ret;
	}

	/* On successful poke commit, unlink and free entry under lock */
	spin_lock_irqsave(&g_patch_lock, flags);
	list_for_each_entry(entry, &g_patch_list, list) {
		if (entry == found) {
			list_del_rcu(&entry->list);
			atomic_dec(&g_active_patches);
			ulp_unpin_module_ref();
			kfree_rcu(entry, rcu);
			break;
		}
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	pr_info("[ulp_driver] Successfully reverted livepatch for PID %u at 0x%llx\n",
			req->target_pid, req->target_vaddr);

	mmput(mm);
	put_task_struct(task);
	return 0;
}

static long ulp_list_patches(struct ulp_list_req __user *user_req)
{
	struct ulp_list_req *kreq;
	struct ulp_patch_entry *entry;
	__u32 count = 0;
	bool is_admin = capable(CAP_SYS_ADMIN);
	uid_t caller_uid = from_kuid(&init_user_ns, current_uid());
	size_t iters = 0;
	unsigned long flags;

	kreq = kzalloc(sizeof(*kreq), GFP_KERNEL);
	if (!kreq)
		return -ENOMEM;

	spin_lock_irqsave(&g_patch_lock, flags);
	ulp_reap_dead_entries_locked();

	list_for_each_entry(entry, &g_patch_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS || count >= ULP_MAX_PATCH_RECORDS)
			break;
		if (is_admin || entry->info.owner_uid == caller_uid) {
			memcpy(&kreq->entries[count], &entry->info, sizeof(struct ulp_patch_info));
			count++;
		}
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	kreq->count = count;
	if (copy_to_user(user_req, kreq, sizeof(*kreq))) {
		kfree(kreq);
		return -EFAULT;
	}

	kfree(kreq);
	return 0;
}

static long ulp_add_rule(struct ulp_kernel_rule_req *req)
{
	struct ulp_kernel_rule *rule;
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	req->binary_path[sizeof(req->binary_path) - 1] = '\0';
	req->patch_name[sizeof(req->patch_name) - 1] = '\0';
	req->func_name[sizeof(req->func_name) - 1] = '\0';

	if (req->build_id_len > ULP_BUILD_ID_MAX)
		return -EINVAL;
	if (!req->build_id_len)
		pr_warn("[ulp_driver] rule for %s has no build-id: it will also be applied if the binary is replaced\n",
			req->binary_path);

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	memcpy(&rule->req, req, sizeof(*req));
	rule->creator_uid = from_kuid(&init_user_ns, current_uid());
	rule->enabled = 1;

	spin_lock_irqsave(&g_rule_lock, flags);
	list_add_tail_rcu(&rule->list, &g_rule_list);
	atomic_inc(&g_active_rules);
	spin_unlock_irqrestore(&g_rule_lock, flags);

	pr_info("[ulp_driver] Registered in-kernel persistent rule: %s -> offset 0x%llx [%s::%s] (UID %u, Global %u)\n",
			req->binary_path, req->target_offset, req->patch_name, req->func_name,
			req->match_uid, req->global_scope);
	return 0;
}

static long ulp_del_rule(struct ulp_kernel_rule_req *req)
{
	struct ulp_kernel_rule *rule, *tmp;
	bool found = false;
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	req->binary_path[sizeof(req->binary_path) - 1] = '\0';

	spin_lock_irqsave(&g_rule_lock, flags);
	list_for_each_entry_safe(rule, tmp, &g_rule_list, list) {
		if (strcmp(rule->req.binary_path, req->binary_path) == 0 &&
			rule->req.target_offset == req->target_offset) {
			list_del_rcu(&rule->list);
			atomic_dec(&g_active_rules);
			kfree_rcu(rule, rcu);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&g_rule_lock, flags);

	return found ? 0 : -ENOENT;
}

static long ulp_list_rules(struct ulp_kernel_rules_list __user *user_list)
{
	struct ulp_kernel_rules_list *klist;
	struct ulp_kernel_rule *rule;
	__u32 count = 0;
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	klist = kzalloc(sizeof(*klist), GFP_KERNEL);
	if (!klist)
		return -ENOMEM;

	spin_lock_irqsave(&g_rule_lock, flags);
	list_for_each_entry(rule, &g_rule_list, list) {
		if (count >= ULP_MAX_KERNEL_RULES)
			break;
		memcpy(&klist->entries[count], &rule->req, sizeof(struct ulp_kernel_rule_req));
		count++;
	}
	spin_unlock_irqrestore(&g_rule_lock, flags);

	klist->count = count;
	if (copy_to_user(user_list, klist, sizeof(*klist))) {
		kfree(klist);
		return -EFAULT;
	}

	kfree(klist);
	return 0;
}

static long ulp_set_override(struct ulp_override_req *req)
{
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	req->binary_path[sizeof(req->binary_path) - 1] = '\0';

	/* Validate the 256-bit magic value */
	if (req->magic[0] != ULP_OVERRIDE_MAGIC_0 ||
		req->magic[1] != ULP_OVERRIDE_MAGIC_1 ||
		req->magic[2] != ULP_OVERRIDE_MAGIC_2 ||
		req->magic[3] != ULP_OVERRIDE_MAGIC_3) {
		pr_alert("[ulp_driver] set override rejected: invalid magic value\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&g_rule_lock, flags);
	memcpy(g_override_state.magic, req->magic, sizeof(req->magic));
	strscpy(g_override_state.binary_path, req->binary_path, sizeof(g_override_state.binary_path));
	g_override_state.expires_jiffies = jiffies + (req->ttl_seconds * HZ);
	g_override_state.active = 1;
	spin_unlock_irqrestore(&g_rule_lock, flags);

	pr_warn("[ulp_driver] Emergency kernel override activated for '%s' (TTL: %u seconds)\n",
			req->binary_path, req->ttl_seconds);
	return 0;
}

static long ulp_clear_override(void)
{
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	spin_lock_irqsave(&g_rule_lock, flags);
	memset(&g_override_state, 0, sizeof(g_override_state));
	spin_unlock_irqrestore(&g_rule_lock, flags);

	pr_info("[ulp_driver] Emergency kernel override cleared. Livepatching is fully active.\n");
	return 0;
}

static struct kprobe kp_fork;
static struct kprobe kp_exec;

/* Fork Inheritance: Runs in scheduler atomic context (wake_up_new_task) */
static int ulp_probe_fork(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *child = (struct task_struct *)regs->di;
	struct ulp_patch_entry *entry, *new_entry;
	pid_t parent_pid = current->pid;
	pid_t child_pid;
	LIST_HEAD(local_clones);
	int count = 0;
	size_t iters = 0;
	unsigned long flags;

	if (!child || (child->flags & PF_KTHREAD) || child->tgid == current->tgid)
		return 0;

	/* Fast path: If no patches exist on system, return immediately */
	if (atomic_read(&g_active_patches) == 0)
		return 0;

	child_pid = child->pid;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &g_patch_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS)
			break;
		if (entry->info.target_pid == parent_pid && entry->info.enabled) {
			if (!ulp_pin_module_ref())
				continue;

			new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
			if (!new_entry) {
				ulp_unpin_module_ref();
				continue;
			}

			memcpy(&new_entry->info, &entry->info, sizeof(entry->info));
			new_entry->info.target_pid = child_pid;
			new_entry->info.owner_uid = from_kuid(&init_user_ns, current_uid());
			new_entry->creator_uid = from_kuid(&init_user_ns, current_uid());
			strscpy(new_entry->info.comm, child->comm, sizeof(new_entry->info.comm));
			memcpy(new_entry->orig_bytes, entry->orig_bytes, sizeof(new_entry->orig_bytes));
			memcpy(new_entry->patch_bytes, entry->patch_bytes, sizeof(new_entry->patch_bytes));

			list_add_tail(&new_entry->list, &local_clones);
			count++;
		}
	}
	rcu_read_unlock();

	if (count > 0) {
		struct ulp_patch_entry *c_entry, *c_tmp;

		spin_lock_irqsave(&g_patch_lock, flags);
		list_for_each_entry_safe(c_entry, c_tmp, &local_clones, list) {
			list_del(&c_entry->list);
			list_add_tail_rcu(&c_entry->list, &g_patch_list);
		}
		spin_unlock_irqrestore(&g_patch_lock, flags);

		atomic_add(count, &g_active_patches);
		pr_debug("[ulp_driver] Fork inheritance: Child PID %d inherited %d livepatches from Parent PID %d\n",
				 child_pid, count, parent_pid);
		ulp_push_event(ULP_EVT_FORK_INHERIT, child_pid, from_kuid(&init_user_ns, current_uid()),
					   0, child->comm, "fork_clone", "Fork child inherited livepatch");
	}
	return 0;
}

/* Task Work Structure for Safe Process-Context Livepatching */
struct ulp_exec_work {
	struct callback_head work;
	struct ulp_kernel_rule_req rule;
};

#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif

/*
 * Read the GNU build-id note of an ELF64 file. build_id_parse_file() is not
 * exported to modules, so walk the PT_NOTE segments with kernel_read().
 * Returns the build-id length, 0 if the file has none, or a negative errno.
 */
static int ulp_read_build_id(struct file *file, u8 *id)
{
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	loff_t pos = 0;
	u8 *buf;
	int i, ret = 0;

	if (kernel_read(file, &eh, sizeof(eh), &pos) != sizeof(eh))
		return -EIO;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh.e_phentsize != sizeof(ph) || eh.e_phnum > 128)
		return -ENOEXEC;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < eh.e_phnum && ret == 0; i++) {
		size_t off = 0, len;
		ssize_t n;

		pos = eh.e_phoff + (u64)i * sizeof(ph);
		if (kernel_read(file, &ph, sizeof(ph), &pos) != sizeof(ph)) {
			ret = -EIO;
			break;
		}
		if (ph.p_type != PT_NOTE)
			continue;
		len = min_t(u64, ph.p_filesz, PAGE_SIZE);
		pos = ph.p_offset;
		n = kernel_read(file, buf, len, &pos);
		if (n <= 0)
			continue;

		while (off + sizeof(Elf64_Nhdr) <= (size_t)n) {
			Elf64_Nhdr *nh = (Elf64_Nhdr *)(buf + off);
			size_t name_off = off + sizeof(*nh);
			size_t desc_off = name_off + ALIGN(nh->n_namesz, 4);
			size_t next = desc_off + ALIGN(nh->n_descsz, 4);

			if (next > (size_t)n || next <= off)
				break;
			if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 &&
			    !memcmp(buf + name_off, "GNU", 4) &&
			    nh->n_descsz > 0 && nh->n_descsz <= ULP_BUILD_ID_MAX) {
				memcpy(id, buf + desc_off, nh->n_descsz);
				ret = nh->n_descsz;
				break;
			}
			off = next;
		}
	}
	kfree(buf);
	return ret;
}

/* Executes in normal, sleepable, preemptible process context just before return to userspace */
static void ulp_exec_task_work_fn(struct callback_head *cb)
{
	struct ulp_exec_work *ework = container_of(cb, struct ulp_exec_work, work);
	struct task_struct *task = current;
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	struct ulp_patch_entry *p_entry = NULL;
	struct file *exe_file = NULL;
	u64 target_vaddr = 0;
	int ret;
	unsigned long flags;

	if (READ_ONCE(ulp_scope) == ULP_SCOPE_DISABLED) {
		kfree(ework);
		return;
	}

	if (!mm) {
		kfree(ework);
		return;
	}

	/* 1. Identify target executable VMA matching the binary */
	mmap_read_lock(mm);
	VMA_ITERATOR(vmi, mm, 0);
	for_each_vma(vmi, vma) {
		if ((vma->vm_flags & VM_EXEC) && vma->vm_file && (vma->vm_file == mm->exe_file)) {
			if (ework->rule.target_offset >= vma->vm_start && ework->rule.target_offset < vma->vm_end)
				target_vaddr = ework->rule.target_offset; /* Non-PIE absolute */
			else
				target_vaddr = vma->vm_start + ework->rule.target_offset; /* PIE relative */
			exe_file = get_file(vma->vm_file);
			break;
		}
	}
	mmap_read_unlock(mm);

	if (!target_vaddr) {
		if (exe_file)
			fput(exe_file);
		kfree(ework);
		return;
	}

	/*
	 * Skip rules made for a different build of this binary (e.g. after a
	 * package update): writing the trampoline at a stale offset would
	 * corrupt unrelated code and crash the process on every start.
	 */
	if (ework->rule.build_id_len) {
		u8 id[ULP_BUILD_ID_MAX];
		int len = ulp_read_build_id(exe_file, id);

		if (len != ework->rule.build_id_len ||
		    memcmp(id, ework->rule.build_id, ework->rule.build_id_len)) {
			pr_warn_ratelimited("[ulp_driver] skipping stale rule '%s' for %s in PID %d: build-id mismatch\n",
					    ework->rule.patch_name, ework->rule.binary_path, task->pid);
			ulp_push_event(ULP_EVT_SECURITY_ALERT, task->pid,
				       from_kuid(&init_user_ns, task_uid(task)), target_vaddr,
				       task->comm, ework->rule.patch_name, "Rule skipped: build-id mismatch");
			fput(exe_file);
			kfree(ework);
			return;
		}
	}
	fput(exe_file);

	/* Pin the module while patches are active, unless resumption mode is enabled */
	if (!ulp_pin_module_ref()) {
		pr_warn("[ulp_driver] Module is unloading. Aborting execve auto-patch for PID %d\n", task->pid);
		kfree(ework);
		return;
	}

	/*
	 * Allocate before commit.
	 * Pre-allocate tracking node BEFORE modifying memory.
	 * Prevents unmanaged "ghost trampolines" if memory allocation fails.
	 */
	p_entry = kzalloc(sizeof(*p_entry), GFP_KERNEL);
	if (!p_entry) {
		ulp_unpin_module_ref();
		kfree(ework);
		return;
	}

	/* 2. Apply livepatch trampoline via sleepable, demand-page-safe direct poke (is_revert = false) */
	ret = ulp_atomic_direct_poke(task, target_vaddr, ework->rule.patch_bytes,
								 (ework->rule.tramp_type == ULP_TRAMP_REL5) ? 5 : 16, false);
	if (ret != 0) {
		pr_err("[ulp_driver] Kernel execve auto-patch poke failed for PID %d at 0x%llx (ret=%d)\n",
			   task->pid, target_vaddr, ret);
		ulp_unpin_module_ref();
		kfree(p_entry);
		kfree(ework);
		return;
	}

	p_entry->info.target_pid = task->pid;
	p_entry->info.owner_uid = from_kuid(&init_user_ns, current_uid());
	p_entry->creator_uid = p_entry->info.owner_uid;
	p_entry->info.target_vaddr = target_vaddr;
	p_entry->info.patch_vaddr = ework->rule.patch_vaddr;
	p_entry->info.tramp_len = (ework->rule.tramp_type == ULP_TRAMP_REL5) ? 5 : 16;
	p_entry->info.enabled = 1;
	strscpy(p_entry->info.patch_name, ework->rule.patch_name, sizeof(p_entry->info.patch_name));
	strscpy(p_entry->info.func_name, ework->rule.func_name, sizeof(p_entry->info.func_name));
	strscpy(p_entry->info.comm, task->comm, sizeof(p_entry->info.comm));
	memcpy(p_entry->patch_bytes, ework->rule.patch_bytes, 16);

	spin_lock_irqsave(&g_patch_lock, flags);
	list_add_tail_rcu(&p_entry->list, &g_patch_list);
	spin_unlock_irqrestore(&g_patch_lock, flags);

	atomic_inc(&g_active_patches);

	pr_info("[ulp_driver] Kernel execve auto-patch: Applied '%s::%s' to PID %d (%s) at 0x%llx\n",
			ework->rule.patch_name, ework->rule.func_name, task->pid, task->comm, target_vaddr);
	ulp_push_event(ULP_EVT_EXEC_AUTO_PATCH, task->pid, from_kuid(&init_user_ns, current_uid()),
				   target_vaddr, task->comm, ework->rule.patch_name, "Exec auto-patch applied");
	kfree(ework);
}

/* Execve Hook: Runs in kprobe pre_handler (arch_setup_additional_pages) */
static int ulp_probe_exec(struct kprobe *p, struct pt_regs *regs)
{
	char path_buf[256];
	char *exe_path = NULL;
	struct ulp_kernel_rule *rule;
	struct task_struct *task = current;
	struct mm_struct *mm = task->mm;
	kuid_t uid = current_uid();
	kgid_t gid = current_gid();
	struct ulp_exec_work *ework;
	size_t iters = 0;
	unsigned long rflags;
	bool override_active = false;

	if (READ_ONCE(ulp_scope) == ULP_SCOPE_DISABLED)
		return 0;

	if (!mm || !mm->exe_file)
		return 0;

	/* Fast path: If no rules registered, return immediately */
	if (atomic_read(&g_active_rules) == 0 && !READ_ONCE(g_override_state.active))
		return 0;

	exe_path = d_path(&mm->exe_file->f_path, path_buf, sizeof(path_buf));
	if (IS_ERR(exe_path))
		return 0;

	/* Check the emergency override state under lock */
	if (READ_ONCE(g_override_state.active)) {
		spin_lock_irqsave(&g_rule_lock, rflags);
		if (g_override_state.active &&
			time_before(jiffies, g_override_state.expires_jiffies) &&
			strcmp(g_override_state.binary_path, exe_path) == 0) {
			if (g_override_state.magic[0] == ULP_OVERRIDE_MAGIC_0 &&
				g_override_state.magic[1] == ULP_OVERRIDE_MAGIC_1 &&
				g_override_state.magic[2] == ULP_OVERRIDE_MAGIC_2 &&
				g_override_state.magic[3] == ULP_OVERRIDE_MAGIC_3) {
				override_active = true;
			} else {
				pr_alert("[ulp_driver] override magic value corrupted; failing closed\n");
			}
		}
		spin_unlock_irqrestore(&g_rule_lock, rflags);

		if (override_active) {
			pr_warn("[ulp_driver] Emergency override active for %s (PID %d). Skipping execve livepatch.\n",
					exe_path, task->pid);
			return 0;
		}
	}

	rcu_read_lock();
	list_for_each_entry_rcu(rule, &g_rule_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS)
			break;
		if (!rule->enabled)
			continue;

		if (strcmp(rule->req.binary_path, exe_path) == 0) {
			/* Check UID/GID matching */
			if (!rule->req.global_scope) {
				if (rule->req.match_uid != (u32)-1 && rule->req.match_uid != __kuid_val(uid))
					continue;
				if (rule->req.match_gid != (u32)-1 && rule->req.match_gid != __kgid_val(gid))
					continue;
			}

			/* Check Parent PID hierarchy under RCU protection */
			if (rule->req.parent_pid != 0) {
				pid_t ppid = 0, rppid = 0;

				rcu_read_lock();
				if (task->real_parent)
					rppid = task->real_parent->pid;
				if (task->parent)
					ppid = task->parent->pid;
				rcu_read_unlock();

				if (rppid != rule->req.parent_pid && ppid != rule->req.parent_pid)
					continue;
			}

			/* Defer memory modification to process context before return to userspace */
			ework = kzalloc(sizeof(*ework), GFP_ATOMIC);
			if (ework) {
				memcpy(&ework->rule, &rule->req, sizeof(rule->req));
				init_task_work(&ework->work, ulp_exec_task_work_fn);
				if (task_work_add(task, &ework->work, TWA_RESUME)) {
					/* Finding 5: Log warning and emit security alert on task work queue failure */
					pr_warn_ratelimited("[ulp_driver] Failed to queue execve livepatch task_work for PID %d (%s)\n",
										task->pid, task->comm);
					ulp_push_event(ULP_EVT_SECURITY_ALERT, task->pid, from_kuid(&init_user_ns, current_uid()),
								   0, task->comm, rule->req.patch_name, "Failed to queue exec task_work");
					kfree(ework);
				}
			} else {
				pr_warn_ratelimited("[ulp_driver] Failed to allocate execve livepatch work for PID %d (%s)\n",
									task->pid, task->comm);
				ulp_push_event(ULP_EVT_SECURITY_ALERT, task->pid, from_kuid(&init_user_ns, current_uid()),
							   0, task->comm, rule->req.patch_name, "Failed to allocate exec task_work");
			}
			break;
		}
	}
	rcu_read_unlock();
	return 0;
}

static long ulp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ulp_patch_req req;
	struct ulp_kernel_rule_req krule_req;
	struct ulp_override_req ovr_req;
	long ret = 0;

	switch (cmd) {
	case ULP_IOC_APPLY_PATCH: {
		unsigned long flags;
		bool is_armed;

		spin_lock_irqsave(&g_arm_lock, flags);
		is_armed = (g_driver_state == ULP_STATE_ARMED && time_before(jiffies, g_armed_until));
		spin_unlock_irqrestore(&g_arm_lock, flags);

		if (!is_armed && !ulp_dev_mode) {
			pr_err("[ulp_driver] apply rejected: maintenance window not armed\n");
			return -EPERM;
		}

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		ret = ulp_apply_patch(&req);
		if (ret == 0 && copy_to_user((void __user *)arg, &req, sizeof(req)))
			ret = -EFAULT;
		break;
	}

	case ULP_IOC_REVERT_PATCH:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		ret = ulp_revert_patch(&req);
		break;

	case ULP_IOC_LIST_PATCHES:
		ret = ulp_list_patches((struct ulp_list_req __user *)arg);
		break;

	case ULP_IOC_ADD_RULE:
		if (copy_from_user(&krule_req, (void __user *)arg, sizeof(krule_req)))
			return -EFAULT;
		ret = ulp_add_rule(&krule_req);
		break;

	case ULP_IOC_DEL_RULE:
		if (copy_from_user(&krule_req, (void __user *)arg, sizeof(krule_req)))
			return -EFAULT;
		ret = ulp_del_rule(&krule_req);
		break;

	case ULP_IOC_LIST_RULES:
		ret = ulp_list_rules((struct ulp_kernel_rules_list __user *)arg);
		break;

	case ULP_IOC_SET_OVERRIDE:
		if (copy_from_user(&ovr_req, (void __user *)arg, sizeof(ovr_req)))
			return -EFAULT;
		ret = ulp_set_override(&ovr_req);
		break;

	case ULP_IOC_CLEAR_OVERRIDE:
		ret = ulp_clear_override();
		break;

	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

/* /proc/ulp_patches filtered sequential reader */
static int ulp_proc_show(struct seq_file *m, void *v)
{
	struct ulp_patch_entry *entry;
	bool is_admin = capable(CAP_SYS_ADMIN);
	uid_t caller_uid = from_kuid(&init_user_ns, current_uid());
	size_t iters = 0;
	unsigned long flags;

	seq_printf(m, "%-7s %-6s %-16s %-22s %-22s %-18s %-18s %-5s %s\n",
			   "PID", "UID", "PROCESS", "PATCH_NAME", "FUNCTION", "ORIG_ADDR", "PATCH_ADDR", "LEN", "STATUS");
	seq_puts(m, "------------------------------------------------------------------------------------------------------------------------------------\n");

	spin_lock_irqsave(&g_patch_lock, flags);
	ulp_reap_dead_entries_locked();

	list_for_each_entry(entry, &g_patch_list, list) {
		if (++iters > ULP_MAX_LOOP_ITERS)
			break;
		if (is_admin || entry->info.owner_uid == caller_uid) {
			seq_printf(m, "%-7u %-6u %-16s %-22s %-22s 0x%016llx 0x%016llx %-5u %s\n",
					   entry->info.target_pid,
					   entry->info.owner_uid,
					   entry->info.comm,
					   entry->info.patch_name,
					   entry->info.func_name,
					   entry->info.target_vaddr,
					   entry->info.patch_vaddr,
					   entry->info.tramp_len,
					   entry->info.enabled ? "ACTIVE (1)" : "DISABLED (0)");
		}
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	return 0;
}

static int ulp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, ulp_proc_show, NULL);
}

static const struct proc_ops ulp_proc_ops = {
	.proc_open    = ulp_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

struct ulp_file_session {
	bool is_armed;
	u32 nonce;
};

static int ulp_fops_open(struct inode *inode, struct file *file)
{
	struct ulp_file_session *sess;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return -ENOMEM;

	file->private_data = sess;
	return 0;
}

static int ulp_fops_release(struct inode *inode, struct file *file)
{
	struct ulp_file_session *sess = file->private_data;
	unsigned long flags;

	if (sess) {
		if (sess->is_armed) {
			spin_lock_irqsave(&g_arm_lock, flags);
			if (g_driver_state == ULP_STATE_ARMED && g_arm_nonce == sess->nonce) {
				g_driver_state = ULP_STATE_LOCKED;
				g_arm_nonce = 0;
				del_timer(&g_arm_timer);
				pr_info("[ulp_driver] Maintenance session closed. Driver locked into fail-closed enforce mode.\n");
				ulp_push_event(ULP_EVT_DISARMED, current->pid, from_kuid(&init_user_ns, current_uid()), 0,
							   current->comm, "session_close", "Session closed; locked");
			}
			spin_unlock_irqrestore(&g_arm_lock, flags);
		}
		kfree(sess);
	}
	return 0;
}

static ssize_t ulp_fops_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct ulp_event ev;
	unsigned long flags;
	int ret;

	if (count < sizeof(struct ulp_event))
		return -EINVAL;

	if (kfifo_is_empty(&g_event_fifo)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(g_event_wq, !kfifo_is_empty(&g_event_fifo));
		if (ret)
			return ret;
	}

	spin_lock_irqsave(&g_event_lock, flags);
	ret = kfifo_get(&g_event_fifo, &ev);
	spin_unlock_irqrestore(&g_event_lock, flags);

	if (!ret)
		return 0;

	if (copy_to_user(buf, &ev, sizeof(ev)))
		return -EFAULT;

	return sizeof(ev);
}

static __poll_t ulp_fops_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &g_event_wq, wait);

	if (!kfifo_is_empty(&g_event_fifo))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static ssize_t ulp_fops_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct ulp_file_session *sess = file->private_data;
	struct ulp_cmd_v1 cmd;
	unsigned long flags;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count < sizeof(cmd.size))
		return -EINVAL;

	ret = copy_struct_from_user(&cmd, sizeof(cmd), buf, count);
	if (ret)
		return ret;

	switch (cmd.cmd_type) {
	case ULP_CMD_ARM: {
		u32 ttl = cmd.ttl_seconds ? cmd.ttl_seconds : 60;

		if (ttl > 300)
			ttl = 300;

		spin_lock_irqsave(&g_arm_lock, flags);
		get_random_bytes(&g_arm_nonce, sizeof(g_arm_nonce));
		if (!g_arm_nonce)
			g_arm_nonce = 1;
		g_driver_state = ULP_STATE_ARMED;
		g_armed_until = jiffies + (ttl * HZ);
		mod_timer(&g_arm_timer, g_armed_until);
		if (sess) {
			sess->is_armed = true;
			sess->nonce = g_arm_nonce;
		}
		spin_unlock_irqrestore(&g_arm_lock, flags);

		pr_warn("[ulp_driver] Driver ARMED for maintenance (TTL: %u seconds, Nonce: 0x%x)\n", ttl, g_arm_nonce);
		ulp_push_event(ULP_EVT_ARMED, current->pid, from_kuid(&init_user_ns, current_uid()), 0,
					   current->comm, "arm", "Driver armed for maintenance");
		return sizeof(cmd);
	}
	case ULP_CMD_DISARM: {
		spin_lock_irqsave(&g_arm_lock, flags);
		g_driver_state = ULP_STATE_LOCKED;
		g_arm_nonce = 0;
		del_timer(&g_arm_timer);
		if (sess)
			sess->is_armed = false;
		spin_unlock_irqrestore(&g_arm_lock, flags);

		pr_info("[ulp_driver] Driver DISARMED by operator. Locked into fail-closed enforce mode.\n");
		ulp_push_event(ULP_EVT_DISARMED, current->pid, from_kuid(&init_user_ns, current_uid()), 0,
					   current->comm, "disarm", "Driver disarmed by operator");
		return sizeof(cmd);
	}
	case ULP_CMD_APPLY_PATCH: {
		struct ulp_patch_req preq;
		bool session_ok;

		spin_lock_irqsave(&g_arm_lock, flags);
		session_ok = (sess && sess->is_armed && sess->nonce == g_arm_nonce);
		if (cmd.arm_nonce && cmd.arm_nonce == g_arm_nonce)
			session_ok = true;

		if (g_driver_state != ULP_STATE_ARMED || !session_ok || time_after(jiffies, g_armed_until)) {
			spin_unlock_irqrestore(&g_arm_lock, flags);
			pr_err("[ulp_driver] apply rejected: maintenance window not armed\n");
			ulp_push_event(ULP_EVT_SECURITY_ALERT, current->pid, from_kuid(&init_user_ns, current_uid()),
						   cmd.target_vaddr, current->comm, cmd.patch_name, "Apply rejected: driver locked");
			return -EPERM;
		}
		spin_unlock_irqrestore(&g_arm_lock, flags);

		memset(&preq, 0, sizeof(preq));
		preq.target_pid = (u32)cmd.target_pid;
		preq.target_vaddr = cmd.target_vaddr;
		preq.patch_vaddr = cmd.patch_vaddr;
		preq.tramp_type = cmd.tramp_len == 5 ? ULP_TRAMP_REL5 : ULP_TRAMP_ABS16;
		strscpy(preq.patch_name, cmd.patch_name, sizeof(preq.patch_name));
		strscpy(preq.func_name, cmd.func_name, sizeof(preq.func_name));
		memcpy(preq.patch_bytes, cmd.patch_bytes, 16);

		ret = ulp_apply_patch(&preq);
		if (ret == 0) {
			ulp_push_event(ULP_EVT_MANUAL_APPLY, (u32)cmd.target_pid, from_kuid(&init_user_ns, current_uid()),
						   cmd.target_vaddr, current->comm, cmd.patch_name, "Livepatch applied via VFS write");
			return sizeof(cmd);
		}
		return ret;
	}
	case ULP_CMD_REVERT_PATCH: {
		struct ulp_patch_req preq;

		memset(&preq, 0, sizeof(preq));
		preq.target_pid = (u32)cmd.target_pid;
		preq.target_vaddr = cmd.target_vaddr;

		ret = ulp_revert_patch(&preq);
		if (ret == 0) {
			ulp_push_event(ULP_EVT_MANUAL_REVERT, (u32)cmd.target_pid, from_kuid(&init_user_ns, current_uid()),
						   cmd.target_vaddr, current->comm, "revert", "Livepatch reverted via VFS write");
			return sizeof(cmd);
		}
		return ret;
	}
	case ULP_CMD_ADD_RULE: {
		struct ulp_kernel_rule_req rreq;
		bool session_ok;

		spin_lock_irqsave(&g_arm_lock, flags);
		session_ok = (sess && sess->is_armed && sess->nonce == g_arm_nonce);
		if (cmd.arm_nonce && cmd.arm_nonce == g_arm_nonce)
			session_ok = true;

		if (g_driver_state != ULP_STATE_ARMED || !session_ok || time_after(jiffies, g_armed_until)) {
			spin_unlock_irqrestore(&g_arm_lock, flags);
			pr_err("[ulp_driver] add rule rejected: maintenance window not armed\n");
			return -EPERM;
		}
		spin_unlock_irqrestore(&g_arm_lock, flags);

		memset(&rreq, 0, sizeof(rreq));
		strscpy(rreq.binary_path, cmd.binary_path, sizeof(rreq.binary_path));
		strscpy(rreq.patch_name, cmd.patch_name, sizeof(rreq.patch_name));
		strscpy(rreq.func_name, cmd.func_name, sizeof(rreq.func_name));
		rreq.target_offset = cmd.target_offset;
		rreq.patch_vaddr = cmd.patch_vaddr;
		rreq.match_uid = cmd.match_uid;
		rreq.global_scope = (u8)cmd.global_scope;
		rreq.tramp_type = cmd.tramp_len == 5 ? ULP_TRAMP_REL5 : ULP_TRAMP_ABS16;
		memcpy(rreq.patch_bytes, cmd.patch_bytes, 16);

		ret = ulp_add_rule(&rreq);
		if (ret == 0)
			return sizeof(cmd);
		return ret;
	}
	case ULP_CMD_DEL_RULE: {
		struct ulp_kernel_rule_req rreq;

		memset(&rreq, 0, sizeof(rreq));
		strscpy(rreq.binary_path, cmd.binary_path, sizeof(rreq.binary_path));
		rreq.target_offset = cmd.target_offset;

		ret = ulp_del_rule(&rreq);
		if (ret == 0)
			return sizeof(cmd);
		return ret;
	}
	default:
		return -EINVAL;
	}
}

static int ulp_save_state(void)
{
	struct file *file;
	struct ulp_state_header hdr;
	struct ulp_state_patch_record *prec_buf = NULL;
	struct ulp_state_rule_record *rrec_buf = NULL;
	struct ulp_patch_entry *entry;
	struct ulp_kernel_rule *rule;
	loff_t pos = 0;
	ssize_t written;
	u32 patch_cnt = 0, rule_cnt = 0;
	u32 i;
	unsigned long flags;
	const char *filepath = ULP_DEFAULT_STATE_FILE;
	int ret = 0;

	spin_lock_irqsave(&g_patch_lock, flags);
	list_for_each_entry(entry, &g_patch_list, list) {
		if (entry->info.enabled)
			patch_cnt++;
	}
	spin_unlock_irqrestore(&g_patch_lock, flags);

	spin_lock_irqsave(&g_rule_lock, flags);
	list_for_each_entry(rule, &g_rule_list, list) {
		if (rule->enabled)
			rule_cnt++;
	}
	spin_unlock_irqrestore(&g_rule_lock, flags);

	if (patch_cnt == 0 && rule_cnt == 0)
		return 0;

	if (patch_cnt > 0) {
		prec_buf = kmalloc_array(patch_cnt, sizeof(*prec_buf), GFP_KERNEL);
		if (!prec_buf)
			return -ENOMEM;
	}

	if (rule_cnt > 0) {
		rrec_buf = kmalloc_array(rule_cnt, sizeof(*rrec_buf), GFP_KERNEL);
		if (!rrec_buf) {
			kfree(prec_buf);
			return -ENOMEM;
		}
	}

	/* Snapshot active patches under spinlock */
	spin_lock_irqsave(&g_patch_lock, flags);
	i = 0;
	list_for_each_entry(entry, &g_patch_list, list) {
		if (entry->info.enabled && i < patch_cnt) {
			memcpy(&prec_buf[i].info, &entry->info, sizeof(prec_buf[i].info));
			memcpy(prec_buf[i].orig_bytes, entry->orig_bytes, 16);
			memcpy(prec_buf[i].patch_bytes, entry->patch_bytes, 16);
			prec_buf[i].creator_uid = entry->creator_uid;
			i++;
		}
	}
	patch_cnt = i;
	spin_unlock_irqrestore(&g_patch_lock, flags);

	/* Snapshot active rules under spinlock */
	spin_lock_irqsave(&g_rule_lock, flags);
	i = 0;
	list_for_each_entry(rule, &g_rule_list, list) {
		if (rule->enabled && i < rule_cnt) {
			memcpy(&rrec_buf[i].req, &rule->req, sizeof(rrec_buf[i].req));
			rrec_buf[i].creator_uid = rule->creator_uid;
			rrec_buf[i].enabled = rule->enabled;
			i++;
		}
	}
	rule_cnt = i;
	spin_unlock_irqrestore(&g_rule_lock, flags);

	file = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (IS_ERR(file)) {
		filepath = ULP_FALLBACK_STATE_FILE;
		file = filp_open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			pr_err("[ulp_driver] Failed to open state file for saving: %d\n", ret);
			goto out_free;
		}
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = ULP_STATE_MAGIC;
	hdr.version = ULP_STATE_VERSION;
	hdr.patch_count = patch_cnt;
	hdr.rule_count = rule_cnt;
	hdr.scope = READ_ONCE(ulp_scope);
	hdr.timestamp_ns = ktime_get_real_ns();

	written = kernel_write(file, &hdr, sizeof(hdr), &pos);
	if (written != sizeof(hdr)) {
		pr_err("[ulp_driver] Failed to write state header to %s (ret=%ld)\n", filepath, written);
		ret = -EIO;
		goto out_close;
	}

	if (patch_cnt > 0) {
		size_t bytes_to_write = patch_cnt * sizeof(*prec_buf);

		written = kernel_write(file, prec_buf, bytes_to_write, &pos);
		if (written != bytes_to_write) {
			pr_err("[ulp_driver] Failed to write patch records to %s\n", filepath);
			ret = -EIO;
			goto out_close;
		}
	}

	if (rule_cnt > 0) {
		size_t bytes_to_write = rule_cnt * sizeof(*rrec_buf);

		written = kernel_write(file, rrec_buf, bytes_to_write, &pos);
		if (written != bytes_to_write) {
			pr_err("[ulp_driver] Failed to write rule records to %s\n", filepath);
			ret = -EIO;
			goto out_close;
		}
	}

	pr_info("[ulp_driver] Resumption state serialized: %u patches, %u rules written to %s\n",
			patch_cnt, rule_cnt, filepath);

out_close:
	filp_close(file, NULL);
out_free:
	kfree(prec_buf);
	kfree(rrec_buf);
	return ret;
}

static int ulp_restore_state(void)
{
	struct file *file;
	struct ulp_state_header hdr;
	loff_t pos = 0;
	ssize_t nread;
	const char *filepath = ULP_DEFAULT_STATE_FILE;
	u32 i, resumed_patches = 0, resumed_rules = 0;
	int ret = 0;

	file = filp_open(filepath, O_RDONLY, 0);
	if (IS_ERR(file)) {
		filepath = ULP_FALLBACK_STATE_FILE;
		file = filp_open(filepath, O_RDONLY, 0);
		if (IS_ERR(file)) {
			/* No state file present */
			return 0;
		}
	}

	nread = kernel_read(file, &hdr, sizeof(hdr), &pos);
	if (nread != sizeof(hdr)) {
		filp_close(file, NULL);
		return 0;
	}

	if (hdr.magic != ULP_STATE_MAGIC || hdr.version != ULP_STATE_VERSION) {
		pr_warn("[ulp_driver] Invalid or stale state header in %s (magic=0x%llx)\n",
				filepath, hdr.magic);
		filp_close(file, NULL);
		return -EINVAL;
	}

	if (hdr.patch_count > 1024 || hdr.rule_count > 1024) {
		pr_warn("[ulp_driver] State file has unreasonable counts: patches=%u rules=%u\n",
				hdr.patch_count, hdr.rule_count);
		filp_close(file, NULL);
		return -EINVAL;
	}

	pr_info("[ulp_driver] Restoring livepatch state from %s (timestamp: %llu ns, %u patches, %u rules)...\n",
			filepath, hdr.timestamp_ns, hdr.patch_count, hdr.rule_count);

	/* 1. Restore Patches */
	for (i = 0; i < hdr.patch_count; i++) {
		struct ulp_state_patch_record prec;
		struct task_struct *task;
		u8 cur_bytes[16];
		int bytes;
		struct ulp_patch_entry *new_entry;
		unsigned long flags;

		nread = kernel_read(file, &prec, sizeof(prec), &pos);
		if (nread != sizeof(prec)) {
			pr_err("[ulp_driver] Error reading patch record %u from %s\n", i, filepath);
			break;
		}

		task = ulp_get_task_by_pid(prec.info.target_pid);
		if (!task) {
			pr_info("[ulp_driver] PID %u no longer active during resumption, skipping livepatch '%s'\n",
					prec.info.target_pid, prec.info.patch_name);
			continue;
		}

		/* Verify comm matches */
		if (strncmp(task->comm, prec.info.comm, sizeof(task->comm)) != 0) {
			pr_warn("[ulp_driver] PID %u comm mismatch ('%s' vs '%s') during resumption, skipping\n",
					prec.info.target_pid, task->comm, prec.info.comm);
			put_task_struct(task);
			continue;
		}

		/* Verify trampoline in process memory */
		bytes = access_process_vm(task, prec.info.target_vaddr, cur_bytes, prec.info.tramp_len, 0);
		if (bytes != prec.info.tramp_len || memcmp(cur_bytes, prec.patch_bytes, prec.info.tramp_len) != 0) {
			pr_warn("[ulp_driver] Trampoline verification failed at 0x%llx for PID %u (%s), skipping\n",
					prec.info.target_vaddr, prec.info.target_pid, prec.info.comm);
			put_task_struct(task);
			continue;
		}

		/* Trampoline verified! Re-adopt the livepatch */
		new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			put_task_struct(task);
			pr_err("[ulp_driver] OOM allocating patch entry during resumption\n");
			continue;
		}

		memcpy(&new_entry->info, &prec.info, sizeof(new_entry->info));
		memcpy(new_entry->orig_bytes, prec.orig_bytes, 16);
		memcpy(new_entry->patch_bytes, prec.patch_bytes, 16);
		new_entry->creator_uid = prec.creator_uid;

		spin_lock_irqsave(&g_patch_lock, flags);
		list_add_tail_rcu(&new_entry->list, &g_patch_list);
		atomic_inc(&g_active_patches);
		if (!READ_ONCE(ulp_allow_resumption)) {
			if (try_module_get(THIS_MODULE))
				atomic_inc(&g_pinned_refs);
		}
		spin_unlock_irqrestore(&g_patch_lock, flags);

		ulp_push_event(ULP_EVT_RESUME, prec.info.target_pid, prec.creator_uid,
					   prec.info.target_vaddr, prec.info.comm, prec.info.patch_name,
					   "Resumed livepatch across driver reload");

		pr_info("[ulp_driver] Successfully resumed livepatch '%s' for PID %u (%s) at 0x%llx\n",
				prec.info.patch_name, prec.info.target_pid, prec.info.comm, prec.info.target_vaddr);
		resumed_patches++;
		put_task_struct(task);
	}

	/* 2. Restore Rules */
	for (i = 0; i < hdr.rule_count; i++) {
		struct ulp_state_rule_record rrec;
		struct ulp_kernel_rule *new_rule;
		unsigned long flags;

		nread = kernel_read(file, &rrec, sizeof(rrec), &pos);
		if (nread != sizeof(rrec)) {
			pr_err("[ulp_driver] Error reading rule record %u from %s\n", i, filepath);
			break;
		}

		new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
		if (!new_rule)
			continue;

		memcpy(&new_rule->req, &rrec.req, sizeof(new_rule->req));
		new_rule->creator_uid = rrec.creator_uid;
		new_rule->enabled = rrec.enabled;

		spin_lock_irqsave(&g_rule_lock, flags);
		list_add_tail_rcu(&new_rule->list, &g_rule_list);
		atomic_inc(&g_active_rules);
		spin_unlock_irqrestore(&g_rule_lock, flags);

		pr_info("[ulp_driver] Successfully resumed persistent rule for '%s'\n", new_rule->req.binary_path);
		resumed_rules++;
	}

	filp_close(file, NULL);

	/* Invalidate state file so it is not re-adopted again */
	file = filp_open(filepath, O_WRONLY | O_TRUNC, 0);
	if (!IS_ERR(file))
		filp_close(file, NULL);

	pr_info("[ulp_driver] Resumption complete: %u patches and %u rules re-adopted.\n",
			resumed_patches, resumed_rules);
	return ret;
}

static const struct file_operations ulp_fops = {
	.owner          = THIS_MODULE,
	.open           = ulp_fops_open,
	.release        = ulp_fops_release,
	.read           = ulp_fops_read,
	.write          = ulp_fops_write,
	.poll           = ulp_fops_poll,
	.unlocked_ioctl = ulp_ioctl,
	.compat_ioctl   = NULL, /* Explicitly reject 32-bit compat callers */
};

static struct miscdevice ulp_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "ulp",
	.fops  = &ulp_fops,
	.mode  = 0600, /* root only */
};

static int __init ulp_init(void)
{
	int ret;

	timer_setup(&g_arm_timer, ulp_arm_timer_fn, 0);

	ret = misc_register(&ulp_misc_device);
	if (ret) {
		pr_err("[ulp_driver] Failed to register /dev/ulp: %d\n", ret);
		return ret;
	}

	/* Register Fork Inheritance Kprobe */
	kp_fork.symbol_name = "wake_up_new_task";
	kp_fork.pre_handler = ulp_probe_fork;
	ret = register_kprobe(&kp_fork);
	if (ret)
		pr_warn("[ulp_driver] Warning: Failed to register fork kprobe: %d\n", ret);
	else
		g_kp_fork_registered = true;

	/* Register Execve Auto-Patching Kprobe */
	kp_exec.symbol_name = "arch_setup_additional_pages";
	kp_exec.pre_handler = ulp_probe_exec;
	ret = register_kprobe(&kp_exec);
	if (ret)
		pr_warn("[ulp_driver] Warning: Failed to register exec kprobe: %d\n", ret);
	else
		g_kp_exec_registered = true;

	ulp_sysctl_header = register_sysctl("kernel", ulp_sysctl_table);
	if (!ulp_sysctl_header)
		pr_warn("[ulp_driver] Warning: Failed to register /proc/sys/kernel/ulp_scope\n");

	proc_create("ulp_patches", 0444, NULL, &ulp_proc_ops);

	if (ulp_resume || ulp_allow_resumption)
		ulp_restore_state();

	pr_info("[ulp_driver] loaded (/proc/sys/kernel/ulp_scope=%d, allow_resumption=%d)\n",
			ulp_scope, ulp_allow_resumption);
	return 0;
}

static void __exit ulp_exit(void)
{
	struct ulp_patch_entry *entry, *tmp;
	struct ulp_kernel_rule *rule, *rtmp;
	unsigned long rflags, pflags;

	del_timer_sync(&g_arm_timer);

	if (g_kp_exec_registered)
		unregister_kprobe(&kp_exec);
	if (g_kp_fork_registered)
		unregister_kprobe(&kp_fork);

	synchronize_rcu();

	if (ulp_sysctl_header)
		unregister_sysctl_table(ulp_sysctl_header);

	remove_proc_entry("ulp_patches", NULL);
	misc_deregister(&ulp_misc_device);

	if (READ_ONCE(ulp_allow_resumption))
		ulp_save_state();

	spin_lock_irqsave(&g_rule_lock, rflags);
	list_for_each_entry_safe(rule, rtmp, &g_rule_list, list) {
		list_del_rcu(&rule->list);
		kfree_rcu(rule, rcu);
	}
	spin_unlock_irqrestore(&g_rule_lock, rflags);

	spin_lock_irqsave(&g_patch_lock, pflags);
	list_for_each_entry_safe(entry, tmp, &g_patch_list, list) {
		list_del_rcu(&entry->list);
		kfree_rcu(entry, rcu);
	}
	spin_unlock_irqrestore(&g_patch_lock, pflags);

	synchronize_rcu();
	pr_info("[ulp_driver] Userspace Livepatching Driver unloaded\n");
}

module_init(ulp_init);
module_exit(ulp_exit);
