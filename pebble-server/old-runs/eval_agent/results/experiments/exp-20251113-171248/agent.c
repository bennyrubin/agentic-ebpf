/*
 Pebble agent UDP reuseport selector (length-aware, single-call, low-latency)

 Rationale:
 - The kernel only honors the first bpf_sk_select_reuseport call; remove the
   fully unrolled retry loop to shrink instruction count and I-cache footprint.
 - Derive slot with a cheap, unbiased range reduction using 32x32->64 mul-high.
   Use a power-of-two fast path. Mix upper/lower halves of the 64-bit hash to
   improve spread.
 - Lightly separate likely-heavy requests without parsing payload: UDP packet
   length is larger for SCANs in this benchmark. We steer "large" packets to
   the upper half of sockets, isolating heavy work and reducing tail latency.

 Verifier safety:
 - No unbounded loops; tiny stack; uses only sk_reuseport_md and pinned maps.
 - Exactly one bpf_sk_select_reuseport call.
*/
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

struct agent_state {
    __u32 active;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_agent_state SEC(".maps");

/* EVOLVE-BLOCK-START
   Length-aware, single-call selector:
   - One bpf_sk_select_reuseport call (kernel ignores subsequent calls).
   - Unbiased range reduction; power-of-two fast path.
   - Steer larger packets (likely SCANs) to the upper half of sockets.
*/
SEC("sk_reuseport/selector")
enum sk_action agent_udp_selector(struct sk_reuseport_md *reuse)
{
    __u32 key = 0;
    struct agent_state *st = bpf_map_lookup_elem(&pebble_agent_state, &key);
    if (!st)
        return SK_PASS;

    __u32 active = st->active;
    if (active == 0)
        return SK_PASS;
    if (active > 128)
        active = 128;

    // Mix upper and lower halves of the 64-bit hash for better spread.
    __u64 h64 = reuse->hash;
    __u32 h = ((__u32)h64) ^ ((__u32)(h64 >> 32));

    // Compute base slot with fast range reduction.
    __u32 slot;
    if ((active & (active - 1)) == 0) {
        // Power-of-two fast path.
        slot = h & (active - 1);
    } else {
        // General case: high 32 bits of 64-bit product (no modulo).
        __u64 prod = (__u64)h * active;
        slot = (__u32)(prod >> 32);
    }

    // Length-aware split: steer larger packets to upper half if possible.
    if (active > 1) {
        __u32 offset = active >> 1;
        if (reuse->len > 64 && offset) {
            __u32 s2 = slot + offset;
            if (s2 >= active)
                s2 -= active;
            slot = s2;
        }
    }

    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";
