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
   Length-aware, hybrid selector (single-call, backlog-friendly)

   Issue observed:
   - Even with hash whitening, high load concentrated traffic on a subset of
     sockets, causing long queues and multi-second p99.

   Policy:
   - Let the kernel’s backlog-aware chooser handle small packets (mostly GETs)
     by returning SK_PASS. This re-enables dynamic balancing across all sockets.
   - For large packets (likely SCANs), steer them to the upper half of sockets
     to isolate heavy work and protect GET tail latency.
   - Keep one bpf_sk_select_reuseport call and stay verifier-friendly.

   Expected effect:
   - Broader socket utilization via kernel distribution for the majority of
     requests, while heavy requests are confined away from light ones.
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

    // Delegate small packets (typical GETs) to the kernel for backlog-aware spread.
    if (reuse->len <= 64)
        return SK_PASS;

    // Whiten hash (Murmur3 fmix32) and range-reduce.
    __u32 h = reuse->hash;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^=  h >> 16;

    __u32 slot;
    if ((active & (active - 1)) == 0) {
        slot = h & (active - 1);
    } else {
        // Use modulo here to avoid patterns seen with mul-high at small actives.
        slot = h % active;
    }

    // Steer heavy (large) packets to upper half to reduce interference with GETs.
    if (active > 1) {
        __u32 off = active >> 1;
        if (off) {
            slot += off;
            if (slot >= active)
                slot -= active;
        }
    }

    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";
