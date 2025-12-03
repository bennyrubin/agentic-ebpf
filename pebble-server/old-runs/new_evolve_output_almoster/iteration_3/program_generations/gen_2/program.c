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
 * Tail latency is dominated by queueing inside each worker’s UDP socket.
 * Every worker is a single-threaded M/G/1 queue that serves both fast GETs
 * (~10 µs) and slow SCANs (~2 ms). When GETs share a worker with SCANs,
 * they experience head-of-line blocking behind long SCANs, inflating p99
 * latency even though handler service times are stable.
 *
 * We can’t see kernel queue depths from BPF, but we *can* classify requests
 * cheaply by looking at the first word of the UDP payload. The client always
 * sends:
 *
 *   "GET  key [reqID]"
 *   "SCAN start limit [reqID]"
 *
 * (see cmd/workload_client/main.go).
 *
 * This program:
 *
 * 1) Classifies SCAN vs non-SCAN by inspecting only the first 4 bytes of
 *    the payload. If they are "SCAN", we treat it as a slow request;
 *    otherwise it is treated as fast/unknown (GET). This is constant-time,
 *    fully bounds-checked, and verifier-friendly.
 *
 * 2) Splits workers into two disjoint pools:
 *
 *      [0 .. fast_workers-1]       : GET/fast pool
 *      [fast_workers .. active-1]  : SCAN/slow pool
 *
 *    Let `active` be the configured worker count from pebble_agent_state:
 *
 *      - For active <= 3: exactly 1 SCAN worker, remaining fast.
 *      - For active >= 4: about half the workers are SCAN workers:
 *            scan_workers = active / 2
 *            fast_workers = active - scan_workers
 *
 *    We always ensure:
 *      - fast_workers >= 1
 *      - scan_workers >= 1
 *
 *    With the typical 6-worker setup this yields 3 fast + 3 scan workers.
 *    Compared to the previous 4-fast/2-scan split, this lowers utilization
 *    on the SCAN pool (and thus SCAN p99 and overall p99) while still
 *    isolating GETs from SCAN-induced head-of-line blocking.
 *
 * 3) Uses per-packet randomness to avoid hot-spotting:
 *
 *      h = reuse->hash ^ bpf_get_prandom_u32();
 *
 *    - For SCAN:        slot = fast_workers + (h % scan_workers);
 *    - For GET/unknown: slot = h % fast_workers;
 *
 *    This keeps utilization balanced even with a small number of client
 *    flows while ensuring GETs never land on SCAN-only workers.
 *
 * 4) Verifier constraints:
 *    - Only existing maps are used: pebble_udp_targets and pebble_agent_state.
 *    - Only one call to bpf_sk_select_reuseport.
 *    - No loops in the parser, minimal stack usage, and only allowed helpers.
 *    - Behavior is deterministic aside from verifier-approved randomness.
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

    /* Need at least 4 bytes to match "SCAN". Otherwise treat as GET. */
    if (data + 4 > data_end)
        return 0;

    __u8 c0 = data[0];
    __u8 c1 = data[1];
    __u8 c2 = data[2];
    __u8 c3 = data[3];

    /* Client sends uppercase tokens; detect "SCAN". */
    if (c0 == 'S' && c1 == 'C' && c2 == 'A' && c3 == 'N')
        return 1;

    /* Everything else (including "GET") is treated as non-scan. */
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
        __u32 scan_workers;

        if (active <= 3) {
            /* With very few workers, keep exactly one SCAN worker. */
            scan_workers = 1;
        } else {
            /* For 4+ workers, dedicate about half to SCANs. */
            scan_workers = active / 2;
        }

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