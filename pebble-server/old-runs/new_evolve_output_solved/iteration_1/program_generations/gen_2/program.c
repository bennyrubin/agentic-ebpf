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
 * with fast index computation and defensive clamping.
 *
 * Motivation
 * ----------
 * The previous agent selector switched from flow-hash pinning to
 * per-packet random selection, eliminating underutilized workers and
 * hot-spot queues when there are few client flows. That design already
 * met the core goals:
 *
 *   - All SO_REUSEPORT workers receive traffic even with 1 client flow.
 *   - No flow affinity; each packet is independently balanced.
 *   - Simple, stateless logic using only pebble_agent_state + targets.
 *
 * The next refinement is small and focused:
 *
 *   1. Make the chosen range robust to any mismatch between the Go-side
 *      "Active" setting and the actual number of installed sockets by
 *      clamping against reuse->num_sks and the map's max size (128).
 *   2. Keep the per-packet random choice but use 64-bit multiply-shift
 *      instead of a modulo to avoid division while preserving a uniform
 *      distribution over [0, active).
 *
 * Approach
 * --------
 * - agent_state.active is still configured once at startup to the
 *   intended worker count.
 * - For each packet:
 *     1. Load state->active.
 *     2. Clamp:
 *          active = min(state->active, 128, reuse->num_sks (when non-zero)).
 *        If the result is 0, fall back to SK_PASS.
 *     3. Draw rnd = bpf_get_prandom_u32().
 *     4. Compute:
 *          slot = ((__u64)rnd * active) >> 32;
 *        This maps uniformly into [0, active) without a division.
 *     5. Call bpf_sk_select_reuseport once with this slot.
 *
 * This preserves the desirable behavior (per-packet randomized
 * load-balancing across all workers, no flow pinning) while making the
 * selector resilient to configuration drift and keeping the hot path
 * simple and fast.
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
    if (active == 0)
        return SK_PASS;

    /* Clamp to the REUSEPORT array size. */
    if (active > 128)
        active = 128;

    /*
     * Also clamp to the number of sockets the kernel says are in the
     * reuseport group. This makes us robust if userspace and the map
     * ever get out of sync.
     */
    __u32 num_sks = reuse->num_sks;
    if (num_sks && num_sks < active)
        active = num_sks;

    if (active == 0)
        return SK_PASS;

    /* Per-packet random selection over [0, active) via multiply-shift. */
    __u32 rnd = bpf_get_prandom_u32();
    __u32 slot = ((__u64)rnd * active) >> 32;

    /* Single helper call; kernel ignores additional calls anyway. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";