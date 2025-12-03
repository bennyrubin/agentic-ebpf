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

// EVOLVE-BLOCK-START
/*
 * Agent UDP selector: stateless per-packet randomized load balancing
 * using multiply-shift instead of division.
 *
 * Motivation
 * ----------
 * The previous version already removed flow-hash pinning by picking a
 * random slot per packet:
 *
 *     slot = bpf_get_prandom_u32() % active;
 *
 * This evenly utilized all workers even with very few client flows, which
 * fixed the worst hot-spotting issues. The next refinement is purely
 * micro-optimizations and minor robustness:
 *
 *   - Avoid 32-bit division/modulo in the hot path.
 *   - Keep a uniform distribution over [0, active) without bias.
 *   - Add a small amount of structure via reuse->hash mixing while
 *     retaining per-packet randomness (no flow affinity).
 *
 * Approach
 * --------
 * - agent_state.active is still the only knob and is written once at
 *   startup from Go to the number of active SO_REUSEPORT workers.
 * - Per packet:
 *     1. Load `active`; if 0 or > 128, fall back to SK_PASS.
 *     2. Draw a pseudo-random 32-bit value: rnd = bpf_get_prandom_u32().
 *     3. Mix in the kernel-provided flow hash:
 *
 *            mixed = rnd ^ reuse->hash;
 *
 *     4. Map `mixed` into [0, active) with 64-bit multiply-shift:
 *
 *            slot = ((__u64)mixed * active) >> 32;
 *
 *        This is a standard technique that avoids division while providing
 *        an (approximately) uniform integer in [0, active).
 * - Call bpf_sk_select_reuseport exactly once with this slot and always
 *   return SK_PASS so the kernel proceeds with the (possibly updated)
 *   selection.
 *
 * Properties
 * ----------
 * - Still stateless and self-contained: no new maps, no extra userspace
 *   configuration, and O(1) work per packet.
 * - Preserves per-packet randomized load balancing, so even a single
 *   high-rate flow is spread across all workers, avoiding queue hot spots.
 * - Multiply-shift removes the modulo/division cost while keeping a
 *   uniform distribution over the active sockets.
 */

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

SEC("sk_reuseport/selector")
enum sk_action agent_udp_selector(struct sk_reuseport_md *reuse)
{
    __u32 key = 0;
    struct agent_state *state = bpf_map_lookup_elem(&pebble_agent_state, &key);
    if (!state)
        return SK_PASS;

    __u32 active = state->active;
    /* Defensive: require a sane active range that matches pebble_udp_targets. */
    if (active == 0 || active > 128)
        return SK_PASS;

    /* Per-packet randomness, lightly mixed with the flow hash. */
    __u32 rnd = bpf_get_prandom_u32();
    __u32 mixed = rnd ^ reuse->hash;

    /* Uniform mapping to [0, active) via 64-bit multiply-shift, avoiding div/mod. */
    __u32 slot = ((__u64)mixed * active) >> 32;

    /* Single helper call; kernel ignores additional calls anyway. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";