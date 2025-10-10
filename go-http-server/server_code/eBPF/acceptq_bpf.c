// SPDX-License-Identifier: GPL-2.0
// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct acceptq {
    __u32 curr;
    __u32 max;
    __u32 cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct acceptq);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acceptq_map SEC(".maps");


SEC("kprobe/tcp_v4_syn_recv_sock")
int BPF_KPROBE(on_syn_recv, struct sock *sk)
{
    if (!sk)
        return 0;

    unsigned int pid;
    unsigned int sk_ack_backlog = 0;
    unsigned int sk_max_ack_backlog = 0;
    __u64 sk_cookie = 0;
    __u32 cpu = 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    sk_ack_backlog = BPF_CORE_READ(sk, sk_ack_backlog);
    sk_max_ack_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
    sk_cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    cpu = bpf_get_smp_processor_id();

    if (sk_cookie == 0)
        return 0;

    struct acceptq q = {};
    q.curr = sk_ack_backlog;
    q.max = sk_max_ack_backlog;
    q.cpu = cpu;
    bpf_map_update_elem(&acceptq_map, &sk_cookie, &q, BPF_ANY);

    bpf_printk("PID: %d, Backlog: %d/%d, CPU: %d, Cookie: 0x%llx",
               pid, sk_ack_backlog, sk_max_ack_backlog, cpu, sk_cookie);

    return 0;
}
