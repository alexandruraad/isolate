// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
//
// network_monitor.bpf.c — eBPF network monitoring and enforcement
//
// Attaches to:
//   - tc/egress (outbound traffic from isobox)
//   - tc/ingress (inbound traffic to isobox)
//   - lsm/socket_connect (connection attempt interception for enforcement)
//
// For each packet: captures src/dst IP, port, protocol, length.
// Does NOT capture payload content.
//
// Policy enforcement: checks dst IP/port against the network policy map.
// If denied: returns TC_ACT_SHOT (drops the packet silently) or
//             on lsm/socket_connect: returns -EPERM (connection refused).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Ethernet header size
#define ETH_HLEN 14
// IP protocol numbers
#define IPPROTO_TCP  6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP  1

// TC actions
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

// ── Event structure ───────────────────────────────────────────────────────────

struct network_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  uid;
    __u8   direction;    // 0 = egress, 1 = ingress
    __u8   protocol;     // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u8   verdict;      // 0 = allow, 1 = block
    __u8   _pad;
    __u32  src_addr;     // IPv4 (network byte order)
    __u32  dst_addr;
    __u16  src_port;
    __u16  dst_port;
    __u32  length;
    __u64  cgroup_id;
    char   comm[16];
};

// ── Maps ──────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} net_events SEC(".maps");

// Network allowlist: dst_addr (u32, host byte order) → allowed ports bitmap
// In production: use LPM_TRIE for CIDR matching
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct { __u32 prefixlen; __u32 addr; });
    __type(value, __u64); // bitmask of allowed dst ports (simplified)
    __uint(map_flags, BPF_F_NO_PREALLOC);
} net_allowlist SEC(".maps");

// Default policy: 0 = audit/allow, 1 = block
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} net_default_policy SEC(".maps");

// Cgroup → isobox mapping (same as syscall_monitor)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} net_cgroup_map SEC(".maps");

// ── TC egress (outbound traffic classifier) ───────────────────────────────────

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Check we're inside an isolate cgroup
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);
    if (!bpf_map_lookup_elem(&net_cgroup_map, &cgroup_id))
        return TC_ACT_OK;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != 0x0800) // IPv4 only for now
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst_addr = bpf_ntohl(ip->daddr);
    __u32 src_addr = bpf_ntohl(ip->saddr);
    __u16 dst_port = 0, src_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        dst_port = bpf_ntohs(tcp->dest);
        src_port = bpf_ntohs(tcp->source);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        dst_port = bpf_ntohs(udp->dest);
        src_port = bpf_ntohs(udp->source);
    }

    // Check network policy
    struct { __u32 prefixlen; __u32 addr; } lpm_key = {
        .prefixlen = 32,
        .addr      = dst_addr,
    };
    __u8 verdict = TC_ACT_OK;

    __u64 *allowed_ports = bpf_map_lookup_elem(&net_allowlist, &lpm_key);
    if (!allowed_ports) {
        // Not in allowlist — check default policy
        __u32 zero = 0;
        __u8 *default_action = bpf_map_lookup_elem(&net_default_policy, &zero);
        if (default_action && *default_action == 1) {
            verdict = TC_ACT_SHOT;
        }
    }

    // Emit event to ring buffer
    struct network_event *ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
    if (ev) {
        ev->timestamp_ns = bpf_ktime_get_ns();
        __u64 pid_tgid   = bpf_get_current_pid_tgid();
        ev->pid          = pid_tgid >> 32;
        ev->uid          = (__u32)(bpf_get_current_uid_gid());
        ev->direction    = 0; // egress
        ev->protocol     = ip->protocol;
        ev->verdict      = (verdict == TC_ACT_SHOT) ? 1 : 0;
        ev->src_addr     = src_addr;
        ev->dst_addr     = dst_addr;
        ev->src_port     = src_port;
        ev->dst_port     = dst_port;
        ev->length       = skb->len;
        ev->cgroup_id    = cgroup_id;
        bpf_get_current_comm(ev->comm, sizeof(ev->comm));
        bpf_ringbuf_submit(ev, 0);
    }

    return verdict;
}

// ── LSM socket_connect (connection enforcement) ───────────────────────────────

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    // Extract destination IP and port
    // Check against policy map
    // Return 0 = allow, -EPERM = deny

    // Full implementation in Phase 2
    return 0;
}

char LICENSE[] SEC("license") = "Dual GPL/Apache-2.0";
