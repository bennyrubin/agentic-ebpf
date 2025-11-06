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

struct hash_state {
    __u32 active;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hash_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_hash_state SEC(".maps");


SEC("sk_reuseport/selector")
enum sk_action hash_udp_selector(struct sk_reuseport_md *reuse)
{
    __u32 key = 0;
    struct hash_state *state = bpf_map_lookup_elem(&pebble_hash_state, &key);
    if (!state || state->active == 0)
        return SK_PASS;

    __u32 active = state->active;
    if (active == 0)
        return SK_PASS;

    __u32 hash = reuse->hash;

    __u32 slot = hash % active;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 128; i++) {
        if (slot >= active)
            slot = 0;
        if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0) == 0)
            return SK_PASS;
        slot++;
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
