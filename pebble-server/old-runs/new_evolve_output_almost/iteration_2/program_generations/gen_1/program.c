//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_udp_targets SEC(".maps");

// EVOLVE-BLOCK-START
/*
 * Agent UDP selector
 *
 * Approach
 * --------
 * We want to reduce head-of-line blocking for short GETs caused by rare but
 * long SCANs, without changing the userspace worker model or configuration.
 *
 * We implement a lightweight, request-type-aware selector using only:
 *   - sk_reuseport_md.{data,data_end} to classify packets as GET vs SCAN.
 *   - pebble_agent_state[0].active (seeded once by Go) plus a few extra
 *     fields we maintain entirely in BPF.
 *
 * Classification:
 *   - Traffic is IPv4 UDP from the synthetic client. We assume no IP options,
 *     so the UDP payload starts at offset 20 (IPv4) + 8 (UDP) = 28 bytes.
 *   - If we can safely read 4 bytes at that offset and they are "SCAN",
 *     we treat the request as a SCAN; everything else is treated as GET.
 *
 * Routing:
 *   - All workers participate in both GET and SCAN handling; we do NOT
 *     dedicate a single worker to SCANs, which previously caused extreme
 *     queuing for SCANs at high load.
 *
 *   - We keep two independent round‑robin counters:
 *       * get_rr  – next candidate worker for GETs.
 *       * scan_rr – next worker for SCANs (spreading SCAN load evenly).
 *
 *   - Additionally, we remember a small window of the most recent SCAN
 *     destinations (last_scan_slots[0..3]) in a circular buffer. When
 *     routing a GET, we:
 *
 *       1. Start from get_rr (wrapped into [0, active)).
 *       2. If this candidate worker matches any of the recent SCAN slots,
 *          we advance to the next worker (with wrap‑around) and check again.
 *       3. We bound this search to at most (1 + SCAN_RECENT_SLOTS) attempts,
 *          so the loop is small and verifier‑friendly.
 *
 *   - SCANs ignore the recent‑SCAN history and just use scan_rr, while
 *     updating the history window.
 *
 * Intuition:
 *   - SCANs are long (≈2ms); once a worker receives a SCAN, many GETs can
 *     arrive while it is busy. By preferentially sending GETs to workers
 *     that have not seen a very recent SCAN, we reduce the fraction of GETs
 *     that queue behind SCANs, without starving or over‑concentrating the
 *     SCAN traffic.
 *
 *   - All workers still receive SCANs via round‑robin, so SCAN throughput
 *     and latency remain close to the baseline program, preserving overall
 *     throughput and avoiding the pathological SCAN queueing that occurs
 *     when only a single worker handles SCANs.
 *
 * Verifier / performance notes:
 *   - No unbounded loops; both loops are over small, constant bounds and
 *     are amenable to unrolling.
 *   - No divisions; wrap‑around is implemented with compare‑and‑reset.
 *   - Stack usage is minimal; state lives in a single ARRAY map element.
 *   - Only one call to bpf_sk_select_reuseport is made per packet.
 */

struct agent_state {
    __u32 active;             /* number of active workers (slots [0, active)) */
    __u32 get_rr;             /* round‑robin counter for GETs */
    __u32 scan_rr;            /* round‑robin counter for SCANs */
    __u32 scan_ring_pos;      /* index into last_scan_slots[] (circular) */
    __u32 last_scan_slots[4]; /* small window of most recent SCAN targets */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_agent_state SEC(".maps");

#define MAX_TARGETS          128
#define IPV4_HDR_LEN         20  /* assuming no IP options */
#define UDP_HDR_LEN           8
#define UDP_PAYLOAD_OFFSET   (IPV4_HDR_LEN + UDP_HDR_LEN)
#define MIN_METHOD_LEN        4  /* "GET " or "SCAN" */
#define SCAN_RECENT_SLOTS     4

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

    if (active > MAX_TARGETS)
        active = MAX_TARGETS;

    __u32 slot = 0;

    if (active == 1) {
        /* Only one worker; nothing to balance. */
        slot = 0;
    } else {
        /* Classify request as SCAN vs. non‑SCAN (treated as GET). */
        bool is_scan = false;

        unsigned char *data_ptr =
            (unsigned char *)(unsigned long)reuse->data;
        unsigned char *data_end =
            (unsigned char *)(unsigned long)reuse->data_end;

        /* Ensure we can safely read the first 4 bytes of the UDP payload. */
        if (data_ptr + UDP_PAYLOAD_OFFSET + MIN_METHOD_LEN <= data_end) {
            unsigned char *p = data_ptr + UDP_PAYLOAD_OFFSET;

            /* Match uppercase "SCAN"; everything else is treated as GET. */
            if (p[0] == 'S' && p[1] == 'C' && p[2] == 'A' && p[3] == 'N')
                is_scan = true;
        }

        if (is_scan) {
            /* Spread SCANs evenly across all workers using scan_rr. */
            __u32 scan_rr = state->scan_rr;
            if (scan_rr >= active)
                scan_rr = 0;

            slot = scan_rr;
            state->scan_rr = scan_rr + 1;

            /* Record this SCAN destination in the recent‑SCAN ring. */
            __u32 pos = state->scan_ring_pos;
            if (pos >= SCAN_RECENT_SLOTS)
                pos = 0;
            state->last_scan_slots[pos] = slot;
            state->scan_ring_pos = pos + 1;
        } else {
            /*
             * GETs prefer workers that have not handled a very recent SCAN.
             * We start from get_rr and, for a few steps, skip indices that
             * appear in last_scan_slots[].
             */
            __u32 base = state->get_rr;
            if (base >= active)
                base = 0;

            __u32 candidate = base;

#pragma unroll
            for (int attempt = 0; attempt < (1 + SCAN_RECENT_SLOTS); attempt++) {
                bool conflict = false;

#pragma unroll
                for (int i = 0; i < SCAN_RECENT_SLOTS; i++) {
                    if (candidate == state->last_scan_slots[i]) {
                        conflict = true;
                    }
                }

                if (!conflict)
                    break;

                candidate++;
                if (candidate >= active)
                    candidate = 0;
            }

            slot = candidate;
            state->get_rr = candidate + 1;
        }
    }

    /* Single selection attempt; additional calls would be ignored by the kernel. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";