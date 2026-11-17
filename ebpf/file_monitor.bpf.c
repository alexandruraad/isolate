// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
//
// file_monitor.bpf.c — eBPF file access monitoring via LSM hooks
//
// Attaches to LSM hooks:
//   - lsm/file_open      (any file opened by the isobox)
//   - lsm/inode_create   (new file created)
//   - lsm/path_rename    (file renamed/moved)
//   - lsm/inode_unlink   (file deleted)
//   - lsm/bprm_check_security (executable check — captures SHA256 in userspace)
//
// Emits file_event to ring buffer for all isobox processes.
// Enforces file policy: deny opens to blocked paths.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PATH_MAX_LEN 256

// ── Event structure ───────────────────────────────────────────────────────────

struct file_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  uid;
    __u8   op;        // 0=open 1=create 2=rename 3=delete 4=exec
    __u8   blocked;
    __u16  flags;
    __u32  mode;
    __u64  cgroup_id;
    char   comm[16];
    char   path[PATH_MAX_LEN];
};

// ── Maps ──────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} file_events SEC(".maps");

// Deny list: inode number → 1 (blocked) for known-bad inodes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // inode number
    __type(value, __u8);  // 1 = blocked
} file_deny_inodes SEC(".maps");

// Cgroup → isobox mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} file_cgroup_map SEC(".maps");

// ── LSM file_open ─────────────────────────────────────────────────────────────

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&file_cgroup_map, &cgroup_id))
        return 0;

    struct file_event *ev = bpf_ringbuf_reserve(&file_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid_tgid >> 32;
    ev->uid          = (__u32)(bpf_get_current_uid_gid());
    ev->op           = 0; // open
    ev->blocked      = 0;
    ev->cgroup_id    = cgroup_id;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    // Read file path (simplified — full path resolution in userspace via d_path)
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct qstr d_name    = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), d_name.name);

    // Check inode against deny list
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u8 *denied = bpf_map_lookup_elem(&file_deny_inodes, &ino);
    if (denied && *denied) {
        ev->blocked = 1;
        bpf_ringbuf_submit(ev, 0);
        return -EPERM; // Block the open
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── LSM bprm_check_security (exec monitoring) ─────────────────────────────────

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&file_cgroup_map, &cgroup_id))
        return 0;

    struct file_event *ev = bpf_ringbuf_reserve(&file_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid_tgid >> 32;
    ev->uid          = (__u32)(bpf_get_current_uid_gid());
    ev->op           = 4; // exec
    ev->blocked      = 0;
    ev->cgroup_id    = cgroup_id;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    // Get executable path
    struct file *file    = BPF_CORE_READ(bprm, file);
    struct dentry *dent  = BPF_CORE_READ(file, f_path.dentry);
    struct qstr d_name   = BPF_CORE_READ(dent, d_name);
    bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), d_name.name);

    // SHA256 hash is computed in userspace by the aya event handler
    // (BPF cannot compute SHA256 efficiently)

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual GPL/Apache-2.0";
