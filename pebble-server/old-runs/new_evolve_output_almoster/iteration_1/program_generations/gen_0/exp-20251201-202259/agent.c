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
 * Design:
 * -------
 * The previous selector implemented per-flow consistent hashing:
 *
 *     start = reuse->hash % active;
 *     probe linearly from `start`.
 *
 * Because reuse->hash is a pure function of the 4‑tuple, every client flow
 * was pinned to a fixed worker index. With only a handful of client UDP
 * flows (e.g., 7 send goroutines) and 6 server workers, this produced:
 *
 *   - Uneven worker utilization (some workers idle, others saturated).
 *   - Long per-worker UDP queues and drops on hot workers.
 *   - High GET/SCAN p99 latency at higher offered loads.
 *
 * Goal:
 * -----
 * Make worker selection independent of the number of client flows and
 * avoid concentrating traffic on a small subset of workers, while keeping
 * the program:
 *
 *   - Stateless (no per-flow or per-worker state).
 *   - O(1) per packet (no loops, no probing).
 *   - Within verifier limits (minimal stack, allowed helpers only).
 *   - Using the existing configuration map (agent_state) only.
 *
 * Approach:
 * ---------
 * We remove per-flow consistent hashing and instead pick a (pseudo‑)
 * random worker index for each packet:
 *
 *   1. Read `active` from pebble_agent_state (set by Go code to the
 *      current worker count, capped at the sockarray size).
 *   2. Combine the per-packet hash (reuse->hash) with bpf_get_prandom_u32()
 *      to derive a mixed value.
 *   3. Map this mixed value into [0, active) with a modulo.
 *   4. Call bpf_sk_select_reuseport once with that slot.
 *
 * This is intentionally *per-packet* selection rather than per-flow
 * selection. Packets from the same client flow are spread across all
 * workers instead of being pinned, which:
 *
 *   - Ensures all reuseport workers receive traffic even with a small
 *     number of client flows.
 *   - Shrinks per-worker UDP queues and reduces head-of-line blocking.
 *   - Spreads rare, long SCAN requests across workers instead of
 *     creating hotspots.
 *
 * The server and client are already fully stateless with respect to
 * which worker handles a given request (identified by reqID in the
 * payload), so reordering across workers is safe and preserves
 * correctness.
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

    /* Safety: don't index beyond the sockarray size even if misconfigured. */
    if (active > 128)
        active = 128;

    /*
     * Mix the per-packet hash with verifier-approved pseudo-randomness.
     * This breaks strict per-flow pinning while remaining stateless and O(1).
     */
    __u32 rnd = bpf_get_prandom_u32();
    __u32 mixed = reuse->hash ^ rnd;

    /* Simple LCG-style scramble before modulo to further decorrelate bits. */
    mixed = mixed * 1103515245u + 12345u;

    __u32 slot = mixed % active;

    /* Single reuseport selection; kernel ignores any additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}

// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";