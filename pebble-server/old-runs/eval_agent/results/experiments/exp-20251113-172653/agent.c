/*
 Pebble agent UDP reuseport selector (single-shot, modulo-based)

 Approach summary:
 - Exactly one call to bpf_sk_select_reuseport; the kernel ignores extras.
 - Compute target slot as reuse->hash % active, matching the best-performing
   prior revision’s effective choice (its retry loop’s first iteration).
 - Clamp active to [1,128] to stay within the pinned sockarray bounds.
 - Keep the code tiny: no loops, minimal branches, no stack usage.

 Why this should improve p99:
 - Removes the unrolled 128-iteration loop and extra helper calls that the
   kernel ignores, cutting instruction count and I-cache pressure.
 - Preserves the modulo mapping that previously yielded the best curve in
   this benchmark, avoiding regressions seen with alternative reducers.
 - Returning SK_PASS after a single choose lets the kernel fall back cleanly
   if selection fails for any reason.

 Verifier notes:
 - No unbounded loops; one helper call; only sk_reuseport_md + pinned maps.
 - GPL license retained; map names/types unchanged so pin paths remain stable.
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

   Single-shot, modulo-based selector:
   - One bpf_sk_select_reuseport call (kernel ignores subsequent calls).
   - Use the same modulo mapping as the previous best performer, but without
     the wasted unrolled loop, for lower instruction count and latency.
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

    __u32 slot = (__u32)(reuse->hash % active);

    // Single selection attempt; kernel falls back if it cannot use the slot.
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";
