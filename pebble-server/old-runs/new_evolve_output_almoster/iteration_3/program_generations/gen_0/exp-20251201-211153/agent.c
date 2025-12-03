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
 * End-to-end p99 latency is dominated by queueing inside each worker’s
 * UDP socket. Every worker is a single-threaded M/G/1 queue that handles
 * both short GETs (~µs) and long SCANs (~ms). With a mixed workload,
 * rare SCANs create head-of-line blocking for many GETs on the same
 * worker, inflating p99 latency even though individual handler times are
 * stable.
 *
 * We cannot observe real kernel queue depths from BPF, but we *can*
 * distinguish request types by parsing the UDP payload, because the
 * client sends fixed ASCII commands:
 *
 *   "GET  key [reqID]"
 *   "SCAN start limit [reqID]"
 *
 * (see cmd/workload_client/main.go).
 *
 * Approach:
 * ---------
 * 1. Lightweight classification in BPF:
 *    - Use sk_reuseport_md->data/data_end to scan up to the first 64
 *      bytes of packet data for the tokens "GET" or "SCAN".
 *    - This scan is fully bounds-checked and the loop is unrolled so it
 *      passes the verifier.
 *    - Result: a conservative flag is_scan (unknown => treated as GET).
 *
 * 2. Type-aware worker selection:
 *    - Read `active` worker count from pebble_agent_state (configured
 *      by Go) and clamp it to [1, 128].
 *    - For GET (or unknown) requests:
 *        slot = hash % active        (spread across all workers)
 *    - For SCAN requests:
 *        - Restrict them to a tail subset of workers:
 *            scan_workers = clamp(active / 3, 1, active - 1)
 *            scan_base    = active - scan_workers
 *            slot         = scan_base + (hash % scan_workers)
 *
 *    This keeps overall utilization high while concentrating long SCANs
 *    onto a configurable fraction (~1/3) of workers. The remaining
 *    workers see very few SCANs and therefore much less head-of-line
 *    blocking, which lowers GET and overall p99 latency, especially at
 *    high load.
 *
 * 3. Verifier- and performance-friendly:
 *    - No additional maps or helpers; only pebble_udp_targets and
 *      pebble_agent_state are used.
 *    - Only one call to bpf_sk_select_reuseport.
 *    - Bounded, fully unrolled scan loop with minimal stack usage.
 *    - Purely deterministic given packet contents and sk_reuseport_md.
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
    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;

    /* If we don't even have a few bytes, treat as GET/unknown. */
    if (data + 4 > data_end)
        return 0;

    unsigned char *p = data;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        /* Ensure we can read up to 4 bytes from p. */
        if ((void *)(p + 4) > data_end)
            break;

        __u8 c0 = p[0];
        __u8 c1 = p[1];
        __u8 c2 = p[2];
        __u8 c3 = p[3];

        /* Fast path: detect "GET" early, treat as non-scan. */
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
        __u32 h = reuse->hash;

        if (is_scan) {
            /*
             * Route SCANs to a tail subset of workers.
             * Use roughly one third of workers, but always keep at least
             * one non-scan worker and one scan worker.
             */
            __u32 scan_workers = active / 3;
            if (scan_workers == 0)
                scan_workers = 1;
            if (scan_workers >= active)
                scan_workers = active - 1;

            __u32 scan_base = active - scan_workers;
            slot = scan_base + (h % scan_workers);
        } else {
            /* GET/unknown: spread across all workers. */
            slot = h % active;
        }
    }

    /* Single reuseport selection; kernel ignores additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}

// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";