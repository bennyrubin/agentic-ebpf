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
 * Agent UDP selector: GET/SCAN-aware split with a dedicated scan worker.
 *
 * Approach
 * --------
 * Workload: ~99.5% GET, very rare but ~2ms SCANs. With purely random
 * balancing, a GET can frequently land behind a SCAN in the same worker's
 * queue, inflating GET tail latency once queues form.
 *
 * This selector keeps the original agent design (stateless, per-packet
 * random choice within the active worker set) but adds a minimal parser for
 * the UDP payload prefix:
 *
 *   - UDP payload = reuse->data + 8 (after UDP header).
 *   - Classify request by ASCII prefix:
 *       "GET "  -> GET
 *       "SCAN " -> SCAN
 *       other   -> UNKNOWN (falls back to unbiased random).
 *
 * Slot selection:
 *   - Let active = min(agent_state.active, 128).
 *   - If active <= 1, or classification fails: per-packet random over
 *     [0, active) as before.
 *   - If active >= 2:
 *       * Reserve exactly 1 worker (highest index) for SCAN traffic.
 *       * GET: random index in [0, active-1).
 *       * SCAN: random index in [active-1, active), which is always the
 *         last worker when there is just one SCAN slot.
 *
 * This isolates long SCANs on a dedicated worker, so GETs almost never sit
 * behind them, reducing GET p99 queueing while preserving overall throughput.
 *
 * Implementation notes
 * --------------------
 * - Only existing maps are used: pebble_agent_state and pebble_udp_targets.
 * - No additional state; per-packet logic is O(1) with a few byte loads.
 * - RNG -> index uses 32x32->64 multiply and upper-32-bit shift to avoid
 *   division while keeping uniformity.
 * - Verifier-friendly: no loops, bounded pointer checks against data_end,
 *   and a single bpf_sk_select_reuseport() call.
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

static __always_inline __u32 pick_slot(__u32 rnd, __u32 range)
{
    /* Map rnd uniformly into [0, range) without a division. */
    return ((__u64)rnd * range) >> 32;
}

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

    /* Clamp to the REUSEPORT array size (128). */
    if (active > 128)
        active = 128;

    if (active == 0)
        return SK_PASS;

    /* Pre-draw randomness for this packet. */
    __u32 rnd = bpf_get_prandom_u32();
    __u32 slot;

    /* If we cannot meaningfully split, retain unbiased random balancing. */
    if (active <= 1)
        goto random_all;

    /* Attempt minimal payload classification: "GET " vs "SCAN ". */
    __u8 *data = (__u8 *)(long)reuse->data;
    __u8 *data_end = (__u8 *)(long)reuse->data_end;

    /* Ensure UDP header (8 bytes) is present. */
    if (data + 8 > data_end)
        goto random_all;

    __u8 *payload = data + 8;

    /* Need at least 4 bytes for "GET " checks. */
    if (payload + 4 > data_end)
        goto random_all;

    __u8 c0 = payload[0];
    __u8 c1 = payload[1];
    __u8 c2 = payload[2];
    __u8 c3 = payload[3];

    int is_get = 0;
    int is_scan = 0;

    if (c0 == 'G' && c1 == 'E' && c2 == 'T' && c3 == ' ') {
        is_get = 1;
    } else if (payload + 5 <= data_end) {
        __u8 c4 = payload[4];
        if (c0 == 'S' && c1 == 'C' && c2 == 'A' && c3 == 'N' && c4 == ' ') {
            is_scan = 1;
        }
    }

    /* Reserve exactly one worker (highest index) for SCAN traffic. */
    if (is_scan) {
        __u32 scan_slots = 1;
        __u32 get_slots = active - scan_slots; /* >= 1 because active >= 2 */
        __u32 idx_in_scan = pick_slot(rnd, scan_slots);
        slot = get_slots + idx_in_scan;       /* in [get_slots, active) */
    } else if (is_get) {
        __u32 scan_slots = 1;
        __u32 get_slots = active - scan_slots;
        slot = pick_slot(rnd, get_slots);     /* in [0, get_slots) */
    } else {
        /* Unknown method: fall back to unbiased random over all workers. */
        goto random_all;
    }

    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;

random_all:
    slot = pick_slot(rnd, active);
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";