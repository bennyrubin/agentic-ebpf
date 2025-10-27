//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_udp_targets SEC(".maps");

struct rr_state {
    struct bpf_spin_lock lock;
    __u32 counter;
    __u32 active;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rr_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_rr_state SEC(".maps");

static __always_inline __u32 next_idx(struct rr_state *st)
{
    __u32 value;
    bpf_spin_lock(&st->lock);
    value = st->counter++;
    if (st->active == 0)
        value = 0;
    bpf_spin_unlock(&st->lock);
    return value;
}

SEC("sk_reuseport/selector")
enum sk_action rr_udp_selector(struct sk_reuseport_md *reuse)
{
    __u32 key = 0;
    struct rr_state *st = bpf_map_lookup_elem(&pebble_rr_state, &key);
    if (!st || st->active == 0)
        return SK_PASS;

    __u32 start = next_idx(st) % st->active;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 128; i++) {
        if (i >= st->active)
            break;

        __u32 slot = start + i;
        if (slot >= st->active)
            slot -= st->active;

        if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0) == 0)
            return SK_PASS;
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
