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
 * The earlier selector used a per-packet pseudo-random number
 * (bpf_get_prandom_u32) mixed with reuse->hash to choose a worker. That
 * removed per-flow pinning, but introduced extra randomness and overhead
 * in the hot path, and empirically led to millisecond-scale p99 latency
 * even at moderate load.
 *
 * Goals for this revision:
 *
 *   - Still decouple selection from the number of client flows so that all
 *     reuseport workers are exercised even when there are only a few UDP
 *     flows.
 *   - Avoid concentrating traffic on a small subset of workers.
 *   - Keep the selector stateless and O(1) per packet, with no loops.
 *   - Remove explicit PRNG usage and rely only on deterministic data
 *     derived from the packet itself plus reuse->hash.
 *
 * Approach:
 * ---------
 * 1. The Go server writes the current worker count into pebble_agent_state
 *    (field `active`). We clamp this to [1, 128] to stay within the
 *    sockarray bounds.
 *
 * 2. For each packet, we take the kernel-provided 4‑tuple hash
 *    (reuse->hash) and mix it with a small, deterministic hash of the
 *    *payload*, specifically the last four bytes of the packet. In this
 *    workload those bytes include part of the textual reqID, which changes
 *    on every request even for a single UDP flow.
 *
 *    - If the payload length is < 4, we fall back to reuse->hash alone.
 *    - The payload hash is computed with a few byte loads and a simple
 *      multiplicative mix (FNV-style), no loops.
 *
 * 3. We map the mixed 32-bit value into [0, active) with a modulo and call
 *    bpf_sk_select_reuseport exactly once.
 *
 * This yields:
 *
 *   - Per-packet variation in the selected worker driven by the changing
 *     reqID, so even a single client flow will spread requests across all
 *     workers over time.
 *   - Deterministic behavior (no PRNG helper) and minimal arithmetic,
 *     staying well within verifier limits.
 *   - Better utilization of all workers and reduced chance of persistent
 *     hotspots, while preserving the server’s stateless semantics: any
 *     worker can safely handle any request because correctness is keyed by
 *     reqID in the payload.
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

    /* Safety: never index beyond the sockarray size even if misconfigured. */
    if (active > 128)
        active = 128;

    /* Base hash from 4‑tuple; provided by the kernel. */
    __u32 h = reuse->hash;

    /* Deterministically mix in the last 4 bytes of the UDP payload, if present. */
    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;

    /* Ensure payload length >= 4 without computing an explicit length. */
    if ((void *)((char *)data + 4) <= data_end) {
        unsigned char *tail = (unsigned char *)data_end - 4;

        /* Build a 32‑bit value from the last 4 bytes (big-endian style). */
        __u32 t = ((__u32)tail[0] << 24) |
                  ((__u32)tail[1] << 16) |
                  ((__u32)tail[2] << 8)  |
                  ((__u32)tail[3]);

        /* Simple FNV-style mix: cheap, branchless, and verifier-friendly. */
        h ^= t;
        h *= 16777619u;
        h += 2166136261u;
    }

    __u32 slot = h % active;

    /* Single reuseport selection; the kernel ignores any additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}

// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";