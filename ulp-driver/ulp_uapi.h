/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _ULP_UAPI_H
#define _ULP_UAPI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define ULP_IOCTL_MAGIC 'U'
#define ULP_NAME_MAX 64

/* Security Scope Levels for /proc/sys/kernel/ulp_scope */
#define ULP_SCOPE_DISABLED      0  /* Livepatching disabled system-wide */
#define ULP_SCOPE_USER_SAME_UID 1  /* Non-root users can patch their own processes; Root can patch all */
#define ULP_SCOPE_ROOT_ONLY     2  /* Only CAP_SYS_ADMIN in init user namespace (Default) */
#define ULP_SCOPE_LOCKED        3  /* Immutable root-only lock: cannot be lowered without reboot */

/* Trampoline Modes */
#define ULP_TRAMP_AUTO   0  /* Auto-detect: 5-byte rel32 if size < 16, else 16-byte abs64 */
#define ULP_TRAMP_ABS16  1  /* 16-byte absolute trampoline (endbr64 + movabs + jmp) */
#define ULP_TRAMP_REL5   2  /* 5-byte relative jump (jmp rel32) */

/**
 * struct ulp_patch_req - Request payload for userspace livepatching
 * @target_pid:   Target process ID (e.g. bgpd, haproxy, or user process PID)
 * @patch_name:   Human-readable patch name (e.g. "haproxy_sanitizer_fixes")
 * @func_name:    Human-readable function name (e.g. "stktable_deinit")
 * @target_vaddr: Virtual address of function to patch in target process
 * @patch_vaddr:  Virtual address of replacement function in target process
 * @futex_vaddr:  Optional: Address of futex/mutex to verify unlocked (returns -EBUSY if held)
 * @func_len:     Optional: Estimated function length (0 for default 16-byte, or exact size)
 * @tramp_type:   Trampoline type (ULP_TRAMP_AUTO, ULP_TRAMP_ABS16, ULP_TRAMP_REL5)
 * @orig_bytes:   Stores original prologue bytes for atomic rollback/unpatch
 * @patch_bytes:  Stores generated trampoline bytes
 */
struct ulp_patch_req {
	__u32 target_pid;
	char  patch_name[ULP_NAME_MAX];
	char  func_name[ULP_NAME_MAX];
	__u64 target_vaddr;
	__u64 patch_vaddr;
	__u64 futex_vaddr;
	__u32 func_len;
	__u32 tramp_type;
	__u8  orig_bytes[16];
	__u8  patch_bytes[16];
};

/**
 * struct ulp_patch_info - Information record for querying active patches
 */
struct ulp_patch_info {
	__u32 target_pid;
	__u32 owner_uid;
	char  comm[16];
	char  patch_name[ULP_NAME_MAX];
	char  func_name[ULP_NAME_MAX];
	__u64 target_vaddr;
	__u64 patch_vaddr;
	__u32 tramp_len;
	__u8  enabled;
};

#define ULP_MAX_PATCH_RECORDS 64

struct ulp_list_req {
	__u32 count;
	struct ulp_patch_info entries[ULP_MAX_PATCH_RECORDS];
};

/* 256-bit magic value for the emergency override request */
#define ULP_OVERRIDE_MAGIC_0 0xA55AA55A69966996ULL
#define ULP_OVERRIDE_MAGIC_1 0x5AA55AA596699669ULL
#define ULP_OVERRIDE_MAGIC_2 0xF00FF00F0FF00FF0ULL
#define ULP_OVERRIDE_MAGIC_3 0x0FF00FF0F00FF00FULL

/**
 * struct ulp_override_ticket - Authenticated, Cryptographically Signed Override Token
 * Used to temporarily disable livepatching for emergency recovery .
 */
struct ulp_override_ticket {
	__u64 magic[4];           /* ULP_OVERRIDE_MAGIC_0..3 */
	char  binary_path[128];   /* Canonical binary path (e.g. /usr/sbin/haproxy) */
	__u64 issued_at;          /* Unix timestamp of issuance */
	__u64 expires_at;         /* Unix timestamp of expiration (short TTL) */
	__u64 nonce;              /* Random nonce preventing replay attacks */
	__u8  hmac_sig[32];       /* HMAC-SHA256(secret, magic||binary||timestamps||nonce) */
};

/**
 * struct ulp_persistent_rule - Configuration for persistent auto-livepatching on startup
 */
/**
 * struct ulp_kernel_rule_req - In-Kernel Persistent Auto-Patch Rule Definition
 */
struct ulp_kernel_rule_req {
	char  binary_path[128];        /* e.g. /usr/local/sbin/haproxy */
	char  patch_name[ULP_NAME_MAX];
	char  func_name[ULP_NAME_MAX];
	__u64 target_offset;           /* Target symbol offset in binary */
	__u64 patch_vaddr;             /* Absolute virtual address or patch payload */
	__u32 match_uid;               /* Specific UID or (uint32_t)-1 for any */
	__u32 match_gid;               /* Specific GID or (uint32_t)-1 for any */
	__u32 parent_pid;              /* Optional: Match specific parent PID hierarchy (0 = any) */
	__u8  global_scope;            /* 1 = Apply to all processes regardless of user */
	__u32 func_len;                /* Function length for variable trampoline (5 vs 16 bytes) */
	__u32 tramp_type;              /* ULP_TRAMP_AUTO, ULP_TRAMP_ABS16, ULP_TRAMP_REL5 */
	__u8  patch_bytes[16];         /* Pre-compiled trampoline or machine code */
};

#define ULP_MAX_KERNEL_RULES 32

struct ulp_kernel_rules_list {
	__u32 count;
	struct ulp_kernel_rule_req entries[ULP_MAX_KERNEL_RULES];
};

/**
 * struct ulp_override_req - Emergency override request
 */
struct ulp_override_req {
	__u64 magic[4];                /* ULP_OVERRIDE_MAGIC_0..3 */
	char  binary_path[128];        /* Binary to temporarily bypass */
	__u32 ttl_seconds;             /* Auto-expiration timer */
};

#define ULP_IOC_APPLY_PATCH     _IOWR(ULP_IOCTL_MAGIC, 1, struct ulp_patch_req)
#define ULP_IOC_REVERT_PATCH    _IOWR(ULP_IOCTL_MAGIC, 2, struct ulp_patch_req)
#define ULP_IOC_LIST_PATCHES    _IOR(ULP_IOCTL_MAGIC,  3, struct ulp_list_req)
#define ULP_IOC_ADD_RULE        _IOW(ULP_IOCTL_MAGIC,  4, struct ulp_kernel_rule_req)
#define ULP_IOC_DEL_RULE        _IOW(ULP_IOCTL_MAGIC,  5, struct ulp_kernel_rule_req)
#define ULP_IOC_LIST_RULES      _IOR(ULP_IOCTL_MAGIC,  6, struct ulp_kernel_rules_list)
#define ULP_IOC_SET_OVERRIDE    _IOW(ULP_IOCTL_MAGIC,  7, struct ulp_override_req)
#define ULP_IOC_CLEAR_OVERRIDE  _IO(ULP_IOCTL_MAGIC,   8)

/* =========================================================================
 * Command and telemetry interface (/dev/ulp read/write)
 * Supports read(), write() via copy_struct_from_user(), and poll() / epoll
 * ========================================================================= */

enum ulp_vfs_cmd_type {
	ULP_CMD_ARM            = 1, /* Arm maintenance mode (CAP_SYS_ADMIN + TTL) */
	ULP_CMD_DISARM         = 2, /* Lock driver into fail-closed enforce mode */
	ULP_CMD_APPLY_PATCH    = 3, /* Apply livepatch (requires active ARM session) */
	ULP_CMD_REVERT_PATCH   = 4, /* Revert livepatch */
	ULP_CMD_ADD_RULE       = 5, /* Register in-kernel persistent rule */
	ULP_CMD_DEL_RULE       = 6, /* Delete in-kernel persistent rule */
	ULP_CMD_QUERY_STATUS   = 7, /* Query driver state and active nonce */
};

enum ulp_driver_state {
	ULP_STATE_LOCKED       = 0, /* Fail-Closed: Auto-patches existing rules, zero new pokes */
	ULP_STATE_ARMED        = 1, /* Maintenance: Active admin session with TTL timer */
};

enum ulp_event_type {
	ULP_EVT_EXEC_AUTO_PATCH = 1, /* Execve matched rule and applied livepatch */
	ULP_EVT_FORK_INHERIT    = 2, /* Fork inherited active livepatch */
	ULP_EVT_MANUAL_APPLY    = 3, /* Manual patch applied via /dev/ulp write() */
	ULP_EVT_MANUAL_REVERT   = 4, /* Patch reverted */
	ULP_EVT_ARMED           = 5, /* Driver transitioned to ARMED */
	ULP_EVT_DISARMED        = 6, /* Driver transitioned to LOCKED (or TTL expired) */
	ULP_EVT_SECURITY_ALERT  = 7, /* Security boundary violation */
	ULP_EVT_OVERFLOW        = 8, /* Telemetry event queue overflow (gap detected) */
	ULP_EVT_RESUME          = 9, /* Driver re-adopted livepatch across module reload/resumption */
};

/**
 * struct ulp_event - Real-time kernel telemetry event record streamed via read()
 */
struct ulp_event {
	__u64 timestamp_ns;
	__u32 event_type;      /* enum ulp_event_type */
	__u32 pid;
	__u32 uid;
	__u64 vaddr;
	char  comm[16];
	char  patch_name[32];
	char  msg[64];
};

/**
 * struct ulp_cmd_v1 - Version-Tolerant VFS Command Structure (copy_struct_from_user)
 */
struct ulp_cmd_v1 {
	__u32 size;             /* sizeof(struct ulp_cmd_v1) - always first field */
	__u32 cmd_type;         /* enum ulp_vfs_cmd_type */
	__u32 arm_nonce;        /* Nonce validation matching active armed session */
	__u32 ttl_seconds;      /* For ULP_CMD_ARM: TTL in seconds (default 60, max 300) */
	__u64 target_pid;       /* Target process PID */
	__u64 target_vaddr;     /* Function target virtual address */
	__u64 patch_vaddr;      /* Replacement function virtual address */
	__u32 tramp_len;        /* 5 (rel32) or 16 (CET abs jump) */
	__u8  patch_bytes[16];  /* Inlined micro-patch machine code */
	__u8  sha256[32];       /* SHA256 of verified patch payload */
	char  patch_name[ULP_NAME_MAX];
	char  func_name[ULP_NAME_MAX];
	char  binary_path[128];
	__u64 target_offset;
	__u32 match_uid;
	__u32 global_scope;
};

#endif /* _ULP_UAPI_H */
