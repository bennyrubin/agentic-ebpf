/*
 Pebble agent UDP reuseport selector

 Approach:
 - Compute a single target slot via fast range reduction of reuse->hash.
 - Avoid loops and extra helper calls; the kernel only honors the first
   select attempt, so additional calls waste cycles and raise tail latency.
 - Clamp active to [1,128]; fall back to SK_PASS to preserve kernel behavior.

 Why it should help:
 - Fewer instructions than a 128-iteration unrolled probe loop.
 - No expensive modulo in the general case (use 32x32->64 multiply-high).
 - Lower I-cache pressure and fewer branches help p99 under high load.
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
   Agent UDP reuseport selector (single-shot, de-skewed)

   Problem we saw:
   - Using reuse->hash directly biased selections to low-index slots when
     the kernel’s hash occupied a narrow range, starving workers.

   Fix:
   - First whiten the 32-bit hash with a strong avalanche (Murmur3 fmix32).
   - Then compute the slot with a fast range reduction:
       * power-of-two active: bitmask
       * otherwise: 32x32->64 multiply-high (no expensive modulo)
   - Keep a single bpf_sk_select_reuseport call; always return SK_PASS.

   Expected effect:
   - Near-uniform spread across active sockets even if the original hash is
     biased, improving fairness and reducing per-worker backlog and p99.
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

    // Whiten the kernel-provided hash (Murmur3 fmix32).
    __u32 h = reuse->hash;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    __u32 slot;
    if ((active & (active - 1)) == 0) {
        slot = h & (active - 1);
    } else {
        __u64 prod = (__u64)h * active;
        slot = (__u32)(prod >> 32);
    }

    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";
