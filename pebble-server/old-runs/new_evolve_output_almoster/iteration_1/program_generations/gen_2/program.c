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
 * The earlier agent selector that used per-flow hashing (reuse->hash %
 * active) caused uneven worker utilization: a small number of client UDP
 * flows were pinned to a subset of reuseport sockets, leaving other workers
 * idle and inflating tail latency once hot workers saturated.
 *
 * A later attempt tried to break this pinning by either:
 *   - XORing reuse->hash with bpf_get_prandom_u32(), or
 *   - Hashing only the first 4 payload bytes.
 *
 * Both variants underperformed:
 *   - PRNG-based selection introduced extra overhead and still produced
 *     millisecond-scale p99 latency.
 *   - Prefix hashing accidentally keyed on the static command prefix
 *     ("GET ", "SCAN"), effectively restoring per-flow pinning for each
 *     method.
 *
 * This revision:
 *
 *   - Keeps the selector stateless and O(1) per packet.
 *   - Avoids bpf_get_prandom_u32() entirely.
 *   - Uses per-packet payload diversity to spread load across all workers,
 *     independent of how many client UDPConns are in use.
 *
 * Design
 * ------
 * 1. Read `active` from pebble_agent_state (written by Go), clamped to
 *    [1, 128] to match the sockarray bounds.
 *
 * 2. Seed a 32-bit hash with reuse->hash (the kernel 4‑tuple hash).
 *
 * 3. Deterministically mix in the *tail* of the UDP payload:
 *      - Compute a safe view of [data, data_end).
 *      - If there are at least 4 bytes, take the last 4 bytes of the
 *        payload, which in this workload include part of the textual
 *        reqID that changes on every request.
 *      - Fold those 4 bytes into the hash with a simple FNV-style mix.
 *
 *    For a given UDP flow, reqID changes per request, so the last 4 bytes
 *    vary per packet. This breaks strict per-flow pinning but remains fully
 *    deterministic and verifier-friendly (no loops, byte-wise loads only).
 *
 * 4. Map the mixed hash into [0, active) and call bpf_sk_select_reuseport
 *    exactly once.
 *
 * Effects
 * -------
 * - Even a single client flow will distribute its requests across all
 *   workers over time (selection depends on reqID, not just 4‑tuple).
 * - Long SCAN requests are naturally spread across workers instead of
 *   piling up on a few sockets, which shrinks per-worker queues and
 *   reduces head-of-line blocking for GETs.
 * - The program remains simple, stateless, and within eBPF verifier limits.
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

    /*
     * Deterministically mix in the last 4 bytes of the UDP payload, if present.
     * In this workload those bytes include part of the changing reqID, which
     * varies per request even on a single UDP flow.
     */
    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;

    if (data && data_end) {
        char *d = (char *)data;
        char *de = (char *)data_end;

        /* Ensure payload length >= 4: (d + 4) <= de */
        if (d + 4 <= de) {
            unsigned char *tail = (unsigned char *)(de - 4);

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
    }

    __u32 slot = h % active;

    /* Single reuseport selection; the kernel ignores any additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}

// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";