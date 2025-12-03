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
 * Agent UDP selector: stateless per-packet random load balancing.
 *
 * Motivation
 * ----------
 * The previous selector derived a socket index from reuse->hash and then
 * linearly probed:
 *
 *     slot = reuse->hash % active
 *
 * With a small number of client flows (often 1) and many SO_REUSEPORT
 * workers (default 64), this "flow-hash pinning" sends all packets from a
 * given flow to a single worker. That leaves most workers idle while one
 * builds a long UDP queue, causing drops and high tail latency.
 *
 * Approach
 * --------
 * - Keep a single configuration knob: agent_state.active, set once from Go
 *   to the number of active workers.
 * - For each packet, draw a pseudo-random 32-bit value using
 *   bpf_get_prandom_u32(), then compute:
 *
 *       slot = rnd % active;
 *
 * - Call bpf_sk_select_reuseport exactly once with this slot. If the helper
 *   fails for any reason, fall back to SK_PASS so the kernel's default
 *   selection can proceed.
 *
 * Properties
 * ----------
 * - Eliminates flow-hash pinning: even a single high-rate flow is spread
 *   across all active workers, avoiding per-socket queue hot spots and
 *   improving utilization.
 * - Simple, stateless, and self-contained: no new maps, no extra userspace
 *   wiring, and only O(1) work per packet (no loops).
 * - Provides a clean base for future refinements (e.g., GET/SCAN-specific
 *   logic or light feedback) without additional complexity today.
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

    /* Clamp to the maximum size of pebble_udp_targets for safety. */
    if (active > 128)
        active = 128;

    /* Per-packet random selection over [0, active). */
    __u32 rnd = bpf_get_prandom_u32();
    __u32 slot = rnd % active;

    /* Single helper call; kernel ignores additional calls anyway. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";