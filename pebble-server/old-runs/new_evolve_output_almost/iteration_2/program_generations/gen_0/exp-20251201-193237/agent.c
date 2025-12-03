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
 * Approach / rationale
 * --------------------
 * The workload mixes very short GETs (~10µs synthetic delay) with rare but
 * ~2ms SCANs on single‑threaded workers. With a uniform round‑robin over all
 * workers, GETs frequently queue behind SCANs on the same socket, creating
 * head‑of‑line (HoL) blocking and inflating p99 latency as load rises.
 *
 * This selector makes routing request‑type aware using only information
 * available in sk_reuseport_md:
 *
 *   - We parse just enough of the packet to look at the first four bytes of the
 *     UDP payload, which are "GET " or "SCAN" in the synthetic client. We do
 *     this with fixed offsets assuming IPv4 + UDP without IP options:
 *
 *         payload_offset = 20 (IPv4 header) + 8 (UDP header) = 28 bytes.
 *
 *     If the packet is too short, or the payload does not start with "SCAN",
 *     we treat it as a GET.
 *
 *   - We use the existing pebble_agent_state[0].active (set once by Go) as the
 *     total worker count and subdivide workers purely inside BPF:
 *
 *       * If active == 0: fall back to SK_PASS (kernel chooses).
 *       * If active == 1: all traffic goes to worker 0 (no choice).
 *       * If active >= 2:
 *           - Slots [0, active-1) form the GET pool.
 *           - Slot  active-1   is dedicated to SCANs.
 *
 *   - GETs are spread across the GET pool using a simple round‑robin counter
 *     stored in pebble_agent_state[0].get_rr. SCANs always go to the last
 *     worker. We clamp 'active' to the sockarray capacity (128) and never
 *     perform division; the round‑robin uses only compare‑and‑wrap.
 *
 * Benefits:
 *   - Short GETs almost never share a queue with long SCANs, greatly reducing
 *     HoL blocking and keeping GET p99 latency low and flat, even as SCANs
 *     become temporarily slow.
 *   - Throughput remains high: only a single worker is reserved for SCANs, so
 *     the remaining (active-1) workers are available for high‑rate GET traffic.
 *   - The design stays verifier‑friendly: no loops, minimal stack use, one
 *     small ARRAY map, and a single bpf_sk_select_reuseport call.
 *
 * Assumptions:
 *   - Traffic is IPv4 UDP without IP options (true for the synthetic client,
 *     which talks to 127.0.0.1:PORT).
 *   - Requests are ASCII "GET ..." or "SCAN ...". Non‑SCAN traffic is treated
 *     as GET for routing purposes.
 */

struct agent_state {
    __u32 active;    /* number of active workers (slots [0, active)) */
    __u32 get_rr;    /* round‑robin counter for GET pool */
    __u32 scan_rr;   /* reserved for future use (currently unused) */
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
            /*
             * Dedicate the last worker to SCANs. This keeps long SCANs from
             * blocking the GET pool, at the cost of one worker's capacity.
             */
            slot = active - 1;
        } else {
            /*
             * GETs use a round‑robin over [0, active-1). We avoid division by
             * using a compare‑and‑wrap pattern.
             */
            __u32 get_count = active - 1;
            __u32 next = state->get_rr;

            if (next >= get_count)
                next = 0;

            slot = next;
            state->get_rr = next + 1;
        }
    }

    /* Single selection attempt; additional calls would be ignored by the kernel. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";