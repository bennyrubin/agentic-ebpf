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
 * Agent UDP selector: GET/SCAN-aware split with a small SCAN subset.
 *
 * Approach
 * --------
 * Workload: ~99.5% GET, rare but ~2ms SCANs. Purely random balancing causes
 * GETs to frequently land behind SCANs on the same worker, inflating GET tail
 * latency once queues form.
 *
 * This selector keeps a stateless, per-packet random choice, but:
 *
 *   - Peeks at the UDP payload prefix (reuse->data + 8):
 *       "GET "  -> treated as GET
 *       "SCAN " -> treated as SCAN
 *       other / malformed -> treated as GET-like
 *
 *   - Uses pebble_agent_state.Active (clamped to 128) as the number of
 *     active reuseport slots.
 *
 *   - For active >= 2:
 *       * Reserve a *small* subset of high-index workers for SCAN traffic:
 *
 *             scan_slots = max(1, min(active - 1, active / 3))
 *             get_slots  = active - scan_slots
 *
 *         So with 6 workers: scan_slots=2, get_slots=4.
 *
 *       * SCAN requests are randomly mapped into the SCAN subset
 *         [get_slots, active).
 *
 *       * GET and all "unknown"/misparsed payloads are randomly mapped into
 *         the GET subset [0, get_slots), never into SCAN slots.
 *
 *   - For active <= 1 or missing state: we fall back to unbiased random over
 *     [0, active) (or SK_PASS when active==0).
 *
 * Rationale
 * ---------
 * Compared to the previous design that dedicated exactly one worker to SCANs,
 * this keeps most workers clean for GETs but lets SCAN load spread across a
 * small fraction of workers, reducing the risk that a single SCAN-only worker
 * saturates and limits capacity. Treating unknown/malformed packets as
 * GET-like (never mapped into SCAN slots) avoids reintroducing SCAN-induced
 * head-of-line blocking for those requests.
 *
 * Implementation details
 * ----------------------
 * - Uses only existing maps: pebble_agent_state and pebble_udp_targets.
 * - No additional state; O(1) per packet with a few byte loads.
 * - RNG -> index mapping uses a 32x32->64 multiply and high 32 bits to avoid
 *   divisions in the hot path.
 * - Single bpf_sk_select_reuseport() call, no loops, verifier-safe bounds
 *   checks against data_end.
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

    /*
     * Reserve a small subset of high-index workers for SCAN traffic.
     * Example: active=6 -> scan_slots=2, get_slots=4.
     */
    __u32 scan_slots = active / 3;  /* ~1/3 of workers for SCANs */
    if (scan_slots == 0)
        scan_slots = 1;
    if (scan_slots >= active)
        scan_slots = active - 1;    /* always leave at least 1 GET-only */
    __u32 get_slots = active - scan_slots;

    /* Attempt minimal payload classification. */
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

    if (is_scan) {
        /* SCAN: choose among the reserved SCAN workers [get_slots, active). */
        __u32 idx_in_scan = pick_slot(rnd, scan_slots);
        slot = get_slots + idx_in_scan;
        (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
        return SK_PASS;
    }

    /* GET or unknown/misparsed: treat as GET-like, never use SCAN slots. */
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