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
 * Approach
 * --------
 * End-to-end p99 latency is dominated by queueing in each worker’s UDP
 * socket. Each worker is effectively an M/G/1 queue handling both short
 * GETs (~10 µs) and long SCANs (~2 ms). When GETs share a worker with
 * SCANs, they suffer head-of-line blocking behind the long SCANs.
 *
 * We cannot see per-socket backlog from BPF, but we *can* cheaply classify
 * requests by parsing the UDP payload, whose format is fixed:
 *
 *   "GET  key [reqID]"
 *   "SCAN start limit [reqID]"
 *
 * Previous iteration:
 *   - Correctly classified GET vs SCAN.
 *   - But used `reuse->hash % active` (without extra randomness) to pick a
 *     worker. With a single client socket, `reuse->hash` is effectively
 *     constant, so almost all traffic mapped to one worker, causing huge
 *     queueing and multi-second p99.
 *
 * This version keeps the SCAN/GET classification but fixes distribution:
 *
 * 1) Robust GET/SCAN classification
 *    - Scan up to the first 64 bytes of the payload for the tokens "GET"
 *      or "SCAN" using sk_reuseport_md->data/data_end with full bounds
 *      checks and an unrolled loop so it satisfies the verifier.
 *    - If we see "SCAN" -> treat as a slow request.
 *      If we see "GET" or nothing -> treat as fast/unknown.
 *
 * 2) Two disjoint worker pools
 *    Let `active` be the number of configured workers (1..128):
 *      - SCAN pool (slow):  roughly 1/3 of workers, in the tail.
 *      - GET pool  (fast):  remaining workers, at the front.
 *
 *    We always ensure:
 *      - At least 1 fast worker.
 *      - At least 1 slow worker (when active > 1).
 *
 *    Layout:
 *      [ fast_workers ... ][ scan_workers ... ]
 *
 *    Selection:
 *      - Draw per-packet randomness with bpf_get_prandom_u32().
 *      - Compute a randomized hash: h = reuse->hash ^ rnd.
 *      - If SCAN:
 *          slot = fast_workers + (h % scan_workers);
 *        Else (GET/unknown):
 *          slot = h % fast_workers;
 *
 *    This:
 *      - Restores good utilization and avoids hot-spotting even with a
 *        single client flow (because of per-packet randomness).
 *      - Insulates GETs from SCAN-induced head-of-line blocking by never
 *        sending GETs to the SCAN pool.
 *      - Spreads SCANs across a smaller subset, keeping their queues
 *        manageable while preserving overall throughput.
 *
 * 3) Verifier friendliness
 *    - Only existing maps are used: pebble_udp_targets and
 *      pebble_agent_state.
 *    - Only one call to bpf_sk_select_reuseport.
 *    - Bounded, fully unrolled scan loop and minimal stack usage.
 *    - Deterministic except for verifier-approved randomness from
 *      bpf_get_prandom_u32().
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

/* Return 1 for SCAN, 0 for GET/unknown. */
static __always_inline int classify_scan(struct sk_reuseport_md *reuse)
{
    unsigned char *data = (unsigned char *)(long)reuse->data;
    unsigned char *data_end = (unsigned char *)(long)reuse->data_end;

    /* Need at least a few bytes to match tokens; otherwise treat as GET. */
    if (data + 4 > data_end)
        return 0;

    unsigned char *p = data;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        /* Ensure we can safely read up to 4 bytes from p. */
        if (p + 4 > data_end)
            break;

        __u8 c0 = p[0];
        __u8 c1 = p[1];
        __u8 c2 = p[2];
        __u8 c3 = p[3];

        /* Detect "GET" fast-path: treat as non-scan. */
        if (c0 == 'G' && c1 == 'E' && c2 == 'T')
            return 0;

        /* Detect "SCAN" (uppercase as used by the client). */
        if (c0 == 'S' && c1 == 'C' && c2 == 'A' && c3 == 'N')
            return 1;

        p++;
    }

    /* Default: if we didn't find "SCAN", treat as GET/unknown. */
    return 0;
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

    if (active > 128)
        active = 128;

    __u32 slot = 0;

    if (active == 1) {
        /* Only one worker; nothing to balance. */
        slot = 0;
    } else {
        int is_scan = classify_scan(reuse);

        /*
         * Partition workers into:
         *   [0 .. fast_workers-1]       : GET/fast pool
         *   [fast_workers .. active-1]  : SCAN/slow pool
         */
        __u32 scan_workers = active / 3;
        if (scan_workers == 0)
            scan_workers = 1;
        if (scan_workers >= active)
            scan_workers = active - 1;

        __u32 fast_workers = active - scan_workers; /* >= 1 */

        __u32 rnd = bpf_get_prandom_u32();
        __u32 h = reuse->hash ^ rnd;

        if (is_scan) {
            /* SCAN: route only within the tail SCAN pool. */
            __u32 idx = h % scan_workers;
            slot = fast_workers + idx;
        } else {
            /* GET/unknown: route only within the fast pool. */
            __u32 idx = h % fast_workers;
            slot = idx;
        }
    }

    /* Single reuseport selection; kernel ignores additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}

// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";