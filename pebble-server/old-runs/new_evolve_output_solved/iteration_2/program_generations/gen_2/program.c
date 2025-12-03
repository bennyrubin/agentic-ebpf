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
 * Agent UDP selector: GET/SCAN-aware split with a single dedicated SCAN worker.
 *
 * Approach
 * --------
 * Workload: ~99.5% GET, rare but ~2ms SCANs. Purely random balancing lets
 * GETs frequently land behind SCANs on the same worker, which blows up GET
 * tail latency once queues form.
 *
 * This selector is stateless and per-packet, but it peeks at the UDP payload
 * and treats long SCANs differently from short GETs:
 *
 *   - UDP payload starts at reuse->data + 8 (after UDP header).
 *   - Classify request by ASCII prefix:
 *       "GET "  -> treated as GET-like
 *       "SCAN " -> treated as SCAN
 *       other / malformed -> also treated as GET-like
 *
 *   - pebble_agent_state.Active (clamped to 128) is the total number of
 *     active reuseport slots.
 *
 *   - For active >= 2:
 *       * Reserve exactly one high-index worker for SCANs:
 *
 *             scan_slots = 1
 *             get_slots  = active - 1
 *
 *       * SCAN requests always go to that single SCAN worker at index
 *         get_slots (i.e., the last slot).
 *
 *       * GET and all "unknown"/misparsed payloads are randomly mapped into
 *         the GET subset [0, get_slots), never into the SCAN slot.
 *
 *   - For active <= 1 or missing state: fall back to unbiased random over
 *     [0, active) (or SK_PASS when active==0).
 *
 * Rationale
 * ---------
 * A previous variant that spread SCANs over multiple workers sacrificed too
 * much GET capacity: fewer workers remained available for GETs, so GET p99
 * inflated again at high load. This version returns to a single SCAN-only
 * worker, maximizing GET capacity while still isolating SCAN-induced head-of-
 * line blocking to one socket.
 *
 * Treating unknown payloads as GET-like keeps them out of the SCAN worker,
 * avoiding accidental reintroduction of SCAN latency into other traffic.
 *
 * Implementation details
 * ----------------------
 * - Uses only existing maps: pebble_agent_state and pebble_udp_targets.
 * - No additional state; O(1) per packet with a handful of byte loads.
 * - RNG -> index mapping uses a 32x32->64 multiply and high 32 bits to avoid
 *   divisions in the hot path.
 * - Single bpf_sk_select_reuseport() call per packet, no loops, verifier-safe
 *   bounds checks against data_end.
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

    /* Pre-draw randomness for this packet. */
    __u32 rnd = bpf_get_prandom_u32();
    __u32 slot;

    /* If we cannot meaningfully split, retain unbiased random balancing. */
    if (active <= 1)
        goto random_all;

    /*
     * Reserve exactly one worker (highest index) for SCAN traffic.
     * get_slots >= 1 because active >= 2 here.
     */
    __u32 scan_slots = 1;
    __u32 get_slots = active - scan_slots;

    /* Attempt minimal payload classification: "GET " vs "SCAN ". */
    __u8 *data = (__u8 *)(long)reuse->data;
    __u8 *data_end = (__u8 *)(long)reuse->data_end;

    /* Ensure UDP header (8 bytes) is present. If not, treat as GET-like. */
    if (data + 8 > data_end)
        goto get_like;

    __u8 *payload = data + 8;

    /* Need at least 4 bytes for "GET " / "SCAN" checks. */
    if (payload + 4 > data_end)
        goto get_like;

    __u8 c0 = payload[0];
    __u8 c1 = payload[1];
    __u8 c2 = payload[2];
    __u8 c3 = payload[3];
    int is_scan = 0;

    if (c0 == 'S' && c1 == 'C' && c2 == 'A' && c3 == 'N' &&
        payload + 5 <= data_end && payload[4] == ' ') {
        is_scan = 1;
    }

    if (is_scan) {
        /* SCAN: always send to the single reserved SCAN worker. */
        slot = get_slots; /* index in [get_slots, active), here exactly one */
        (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
        return SK_PASS;
    }

    /* GET or unknown/misparsed: treat as GET-like, never use SCAN slot. */
get_like:
    slot = pick_slot(rnd, get_slots);
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;

random_all:
    slot = pick_slot(rnd, active);
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";