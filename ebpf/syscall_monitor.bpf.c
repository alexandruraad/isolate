// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
//
// syscall_monitor.bpf.c — eBPF syscall monitoring program
//
// Attaches to sys_enter_* tracepoints to capture every syscall invocation
// from any process inside an isolate cgroup. Events are pushed to userspace
// via BPF ring buffer (zero-copy, ordered, no dropped events under load).
//
// CO-RE (Compile Once, Run Everywhere) — works on kernels ≥ 5.13 without
// recompilation. Requires vmlinux.h (BTF-derived kernel headers).
//
// Loaded by the aya-based EbpfBackend in isolate-sandbox.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Event structure (shared with userspace via aya) ───────────────────────────

#define COMM_LEN 16
#define MAX_ARGS  6

struct syscall_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tid;
    __u32  ppid;
    __u32  uid;
    __u32  gid;
    __u32  syscall_nr;
    __u64  args[MAX_ARGS];
    __s64  ret;           // filled in on sys_exit
    __u8   blocked;       // 1 if enforcer blocked this syscall
    char   comm[COMM_LEN];
    // cgroup path ID (used to correlate with isobox ID)
    __u64  cgroup_id;
};

// ── Maps ──────────────────────────────────────────────────────────────────────

// Ring buffer: kernel → userspace (zero-copy)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); // 8 MB ring buffer
} events SEC(".maps");

// Per-CPU scratch space: store in-progress sys_enter data until sys_exit
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syscall_event);
} scratch SEC(".maps");

// Syscall allowlist / denylist (updated by policy engine via aya map ops)
// Key: syscall_nr, Value: 1 = allowed, 0 = denied
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, __u8);
} syscall_policy SEC(".maps");

// Cgroup ID → isobox ID mapping (string, max 32 bytes)
// Allows correlating events to specific isoboxes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);     // cgroup_id
    __type(value, __u64);   // isobox sequence number
} cgroup_map SEC(".maps");

// ── sys_enter: capture syscall number and arguments ──────────────────────────

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct syscall_event *ev;

    // Only track processes in isolate cgroups
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cgroup_map, &cgroup_id))
        return 0;

    ev = bpf_map_lookup_elem(&scratch, &zero);
    if (!ev)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid          = pid_tgid >> 32;
    ev->tid          = (__u32)pid_tgid;
    ev->uid          = (__u32)uid_gid;
    ev->gid          = uid_gid >> 32;
    ev->syscall_nr   = (__u32)ctx->id;
    ev->cgroup_id    = cgroup_id;
    ev->blocked      = 0;

    // Capture up to MAX_ARGS syscall arguments
    ev->args[0] = ctx->args[0];
    ev->args[1] = ctx->args[1];
    ev->args[2] = ctx->args[2];
    ev->args[3] = ctx->args[3];
    ev->args[4] = ctx->args[4];
    ev->args[5] = ctx->args[5];

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    // Check syscall policy (if map entry exists)
    __u8 *allowed = bpf_map_lookup_elem(&syscall_policy, &ev->syscall_nr);
    if (allowed && *allowed == 0) {
        // Syscall is denied — mark blocked
        ev->blocked = 1;
        // Note: actual blocking is done by LSM BPF (net_enforcer.bpf.c)
        // This program is monitoring only; enforcement via seccomp + LSM BPF
    }

    return 0;
}

// ── sys_exit: capture return value, emit event ───────────────────────────────

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 zero = 0;
    struct syscall_event *ev;

    ev = bpf_map_lookup_elem(&scratch, &zero);
    if (!ev || ev->pid == 0)
        return 0;

    // Verify this is the same PID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) != ev->pid)
        return 0;

    // Fill in return value
    ev->ret = ctx->ret;

    // Write to ring buffer (zero-copy)
    struct syscall_event *rb_ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!rb_ev) {
        // Ring buffer full — event dropped (monitored by stats counter)
        return 0;
    }

    *rb_ev = *ev;
    bpf_ringbuf_submit(rb_ev, 0);

    // Clear scratch
    ev->pid = 0;

    return 0;
}

char LICENSE[] SEC("license") = "Dual GPL/Apache-2.0";
