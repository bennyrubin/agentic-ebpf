//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct acceptq {
    __u32 curr;
    __u32 max;
    __u32 cpu;
};

/* Reuse the same pinned maps as acceptqueue.c */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct acceptq);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acceptq_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acceptq_slot_cookies SEC(".maps");

/* CPU utilization map shared with cpuutil.c */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cpu_util_map SEC(".maps");

/* Reuseport socket array targets */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

SEC("sk_reuseport/selector")
enum sk_action agent_selector(struct sk_reuseport_md *reuse)
{
     /* # EVOLVE-BLOCK-START */
    __u32 slot = 0;
    
    __u64 *cookie = bpf_map_lookup_elem(&acceptq_slot_cookies, &slot);
    if (cookie && *cookie) {
        struct acceptq *aq = bpf_map_lookup_elem(&acceptq_map, cookie);
        if (aq) {
            __u32 cpu = aq->cpu;
            __u32 *util = bpf_map_lookup_elem(&cpu_util_map, &cpu);
            if (util) {
                __u32 unused = *util;
                (void)unused;
            }
        }
    }

    if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &slot, 0) == 0) {
        return SK_PASS;
    }

    return SK_DROP;

    /* # EVOLVE-BLOCK-END */
}

char _license[] SEC("license") = "GPL";
