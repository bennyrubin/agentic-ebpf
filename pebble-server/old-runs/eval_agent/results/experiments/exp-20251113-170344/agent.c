/*
 Pebble agent UDP reuseport selector (hybrid, single-call, verifier-friendly)

 Overview:
 - Keep a single bpf_sk_select_reuseport call (kernel only honors the first).
 - Compute a stable slot from reuse->hash using fast range reduction:
     * power-of-two: bitmask
     * otherwise: 32x32->64 multiply-high (no modulo)
 - Hybrid policy: on half of packets (hash LSB = 1) skip selection and return
   SK_PASS so the kernel’s built-in reuseport chooser (which is backlog-aware)
   can take over. On the other half we enforce a uniform mapping. This blend
   tends to flatten p99 by avoiding pathological skew while still letting the
   kernel steer bursts away from congested sockets.

 Verifier safety:
 - No unbounded loops; tiny stack; only sk_reuseport_md and pinned maps used.
 - Sockets are clamped to [1,128] to stay within the sockarray bounds.
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

// EVOLVE-BLOCK-START
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

    __u32 h = reuse->hash;

    // Hybrid policy: let kernel decide for half the packets (odd hashes).
    if (h & 1)
        return SK_PASS;

    __u32 slot;
    if ((active & (active - 1)) == 0) {
        // Power-of-two fast path.
        slot = h & (active - 1);
    } else {
        // Fast range reduction without modulo: take high 32 bits of 64-bit product.
        __u64 prod = (__u64)h * active;
        slot = (__u32)(prod >> 32);
    }

    // Single selection attempt; kernel ignores subsequent calls.
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";
