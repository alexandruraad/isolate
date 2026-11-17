// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
//
// process_monitor.bpf.c — eBPF process lifecycle monitoring
//
// Attaches to:
//   - tracepoint/sched/sched_process_exec  (new exec — binary replaced)
//   - tracepoint/sched/sched_process_fork  (new process forked)
//   - tracepoint/sched/sched_process_exit  (process exited)
//
// Emits process_event to ring buffer for all isobox processes.
// Cgroup filter: only records events for PIDs inside a registered isobox cgroup.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PATH_MAX_LEN 256

// ── Op codes ──────────────────────────────────────────────────────────────────
#define PROC_OP_EXEC  0
#define PROC_OP_FORK  1
#define PROC_OP_EXIT  2

// ── Event structure ───────────────────────────────────────────────────────────

struct process_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tid;
    __u32  ppid;
    __u32  uid;
    __u8   op;           // PROC_OP_*
    __u8   _pad[3];
    __s32  exit_code;    // valid for op=PROC_OP_EXIT
    __u64  cgroup_id;
    char   comm[16];
    char   filename[PATH_MAX_LEN]; // valid for op=PROC_OP_EXEC
};

// ── Maps ──────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB
} proc_events SEC(".maps");

// Cgroup → isobox mapping (matches syscall_monitor cgroup_map)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    // cgroup_id
    __type(value, __u64);  // isobox sequence number
} proc_cgroup_map SEC(".maps");

// ── Helper: fill common fields ────────────────────────────────────────────────

static __always_inline int fill_common(struct process_event *ev, __u8 op)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&proc_cgroup_map, &cgroup_id))
        return -1;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid_tgid >> 32;
    ev->tid          = (__u32)pid_tgid;
    ev->uid          = (__u32)uid_gid;
    ev->op           = op;
    ev->cgroup_id    = cgroup_id;
    ev->exit_code    = 0;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    return 0;
}

// ── tracepoint/sched/sched_process_exec ──────────────────────────────────────

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *ev = bpf_ringbuf_reserve(&proc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    if (fill_common(ev, PROC_OP_EXEC) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    // Capture the filename being exec'd
    // ctx->filename is a __data_loc field; use the helper to read it
    unsigned int filename_off = ctx->__data_loc_filename & 0xffff;
    bpf_probe_read_kernel_str(
        ev->filename,
        sizeof(ev->filename),
        (void *)ctx + filename_off
    );

    // ppid: read from task_struct via BPF CO-RE
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── tracepoint/sched/sched_process_fork ──────────────────────────────────────

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_event *ev = bpf_ringbuf_reserve(&proc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    if (fill_common(ev, PROC_OP_FORK) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    // For fork, ctx->parent_pid is the PPID
    ev->ppid = ctx->parent_pid;
    // ctx->child_pid is the new PID — record it in pid for the event consumer
    // (the event pid field carries the parent's PID from fill_common;
    //  repopulate with child PID so userspace sees the new process)
    ev->pid  = ctx->child_pid;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ── tracepoint/sched/sched_process_exit ──────────────────────────────────────

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_event *ev = bpf_ringbuf_reserve(&proc_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    if (fill_common(ev, PROC_OP_EXIT) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    // Exit code is encoded in the upper 8 bits of ctx->exit_code (like wait(2))
    ev->exit_code = (ctx->exit_code >> 8) & 0xff;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual GPL/Apache-2.0";
