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


/* # EVOLVE-BLOCK-START */
SEC("sk_reuseport/selector")
enum sk_action agent_selector(struct sk_reuseport_md *reuse)
{
    /* We have exactly four worker sockets stored in slots 0-3.
     * Pick the one whose backing CPU currently shows the lowest utilisation.
     * The CPU utilisation map is asynchronously updated by cpuutil.c.
     */

    __u32 best_slot  = 0;
    __u32 best_util  = 0xffffffff; /* large number */

#pragma clang loop unroll(full)
    for (int i = 0; i < 4; i++) {
        __u32 idx = (__u32)i;

        /* Map from slot -> listener cookie */
        __u64 *cookie = bpf_map_lookup_elem(&acceptq_slot_cookies, &idx);
        if (!cookie || !*cookie)
            continue;

        /* Cookie -> accept queue entry -> CPU owning the socket */
        struct acceptq *aq = bpf_map_lookup_elem(&acceptq_map, cookie);
        if (!aq)
            continue;

        __u32 cpu = aq->cpu;
        __u32 *util_ptr = bpf_map_lookup_elem(&cpu_util_map, &cpu);
        __u32 util = util_ptr ? *util_ptr : 0;

        if (util < best_util) {
            best_util = util;
            best_slot = idx;
        }
    }

    /* Ask the kernel to steer this connection to the chosen socket.        */
    if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &best_slot, 0) == 0)
        return SK_PASS;

    /* Fallback: let the kernel’s default hash pick if our request failed.  */
    return SK_PASS;
}

/* # EVOLVE-BLOCK-END */

char _license[] SEC("license") = "GPL";
