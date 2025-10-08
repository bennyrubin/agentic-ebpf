//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64); // userspace still writes an int fd
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

/* Round-robin state with a spinlock to avoid atomic XADD return-value issues. */
struct rr_state {
    struct bpf_spin_lock lock;
    __u32 counter;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rr_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rr SEC(".maps");

/* Fetch-and-increment implemented with a spinlock (portable for eBPF). */
static __always_inline __u32 rr_fetch_inc(struct rr_state *s)
{
    __u32 prev;
    bpf_spin_lock(&s->lock);
    prev = s->counter;
    s->counter = prev + 1;
    bpf_spin_unlock(&s->lock);
    return prev;
}

SEC("sk_reuseport/selector")
enum sk_action rr_selector(struct sk_reuseport_md *reuse)
{
    __u32 k0 = 0;
    struct rr_state *st = bpf_map_lookup_elem(&rr, &k0);
    if (!st || 4 == 0) {
        bpf_printk("rr: no state or active_sockets=0\n");
        return SK_DROP;
    }

    __u32 h = reuse->hash;
    bpf_printk("reuseport: hash=%u\n", h);

    __u32 start = rr_fetch_inc(st) % 4;

    /* Probe up to active_sockets entries starting at 'start' */
    for (__u32 i = 0; i < 4; i++) {
        __u32 slot = start + i;
        if (slot >= 4)
            slot -= 4;

        long ret = bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &slot, 0);
        if (ret == 0) {
            bpf_printk("rr: passing on slot = %u\n", slot);
            return SK_PASS;
        }
    }

    bpf_printk("rr: all %u slots failed to match\n", 4);
    return SK_DROP;
}

char _license[] SEC("license") = "GPL";
