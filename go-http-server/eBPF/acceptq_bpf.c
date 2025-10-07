// SPDX-License-Identifier: GPL-2.0
// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// struct acceptq {
//     __u32 curr;
//     __u32 max;
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 128);
//     __type(key, __u64);
//     __type(value, struct acceptq);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
// } acceptq_map SEC(".maps");

// SEC("kprobe/tcp_v4_syn_recv_sock")
// int BPF_KPROBE(on_syn_recv, struct sock *sk)
// {
//     if (!sk)
//         return 0;

//     struct acceptq q = {};
//     q.curr = BPF_CORE_READ(sk, sk_ack_backlog);
//     q.max  = BPF_CORE_READ(sk, sk_max_ack_backlog);

//     __u64 cookie = bpf_get_socket_cookie(sk);
//     bpf_map_update_elem(&acceptq_map, &cookie, &q, BPF_ANY);
//     bpf_printk("acceptq: cookie=%llu curr=%u max=%u\n", cookie, q.curr, q.max);
//     return 0;
// }


SEC("kprobe/tcp_v4_syn_recv_sock")
int BPF_KPROBE(on_syn_recv, struct sock *sk)
{
    if (!sk)
        return 0;

    unsigned int pid;
    unsigned int sk_ack_backlog = 0;
    unsigned int sk_max_ack_backlog = 0;
    __u64 sk_cookie = 0;

    // Get the PID from the BPF helper
    pid = bpf_get_current_pid_tgid() >> 32;

    // Use BPF_CORE_READ to safely and portably read the sk_ack_backlog field.
    sk_ack_backlog = BPF_CORE_READ(sk, sk_ack_backlog);

    // Use BPF_CORE_READ to safely and portably read the sk_max_ack_backlog field.
    // The type of this field can differ between kernel versions (e.g., unsigned short vs. u32),
    // and CORE ensures the correct size is read.
    sk_max_ack_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);

    // Use BPF_CORE_READ to safely and portably read the sk_cookie field.
    sk_cookie = BPF_CORE_READ(sk,
        __sk_common.skc_cookie.counter);

    __u64 sk_ptr = (__u64)sk;

    // Print the values to the kernel trace pipe.
    // bpf_printk can accept up to three 64-bit arguments. We can combine our
    // 32-bit values into one 64-bit argument to fit within the limit.
    // However, the trace pipe is more flexible than older bpf_printk versions,
    // and modern kernels often support more arguments.
    // For clarity, we'll use a single bpf_printk call.
    bpf_printk("PID: %d, Backlog: %d/%d, Cookie: %llu, Pointer: 0x%llx",
                pid, sk_ack_backlog, sk_max_ack_backlog, sk_cookie, sk_ptr);

    return 0;
}