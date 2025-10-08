//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64); // socket FD
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

/*
 * Always choose key 0 in the reuseport sockarray.
 * If key 0 isn't valid/matching for this incoming skb, we drop.
 */
SEC("sk_reuseport/selector")
enum sk_action pickfirst(struct sk_reuseport_md *reuse)
{
    __u32 key0 = 2;

    if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &key0, 0) == 0) {
        // Successfully selected socket at index 0
        return SK_PASS;
    }

    // Could not select key 0 (not present or doesn't match tuple) -> drop.
    return SK_DROP;
}

char _license[] SEC("license") = "GPL";
