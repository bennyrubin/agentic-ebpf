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
 * Agent UDP selector
 *
 * Design goals
 * ------------
 * 1) Drive all SO_REUSEPORT workers into steady use:
 *    - The baseline hash-based policy left 1–2 workers almost idle under
 *      single-sender workloads. Here we use simple round‑robin counters
 *      stored in pebble_agent_state so every packet advances an index and
 *      all [0..Active-1) workers get traffic over time.
 *
 * 2) Isolate long SCAN requests from short GETs:
 *    - SCANs (~0.5% of traffic but ~200x the cost of GET) consumed a large
 *      share of CPU and caused head‑of‑line blocking when mixed with GETs
 *      on the same workers.
 *    - Requests are ASCII and begin with "GET " or "SCAN " (see
 *      buildPayload in the client). In this hook, reuse->data points
 *      directly at the UDP payload, so we can classify a SCAN by checking
 *      the first four bytes for "SCAN".
 *    - For sufficiently large worker pools we dedicate a small tail subset
 *      of workers to SCANs, and round‑robin GETs only across the remaining
 *      workers. This confines SCAN-induced queuing to that subset.
 *
 * 3) Keep the selector verifier‑friendly and cheap:
 *    - One array map lookup (pebble_agent_state), no additional maps.
 *    - Straight‑line code with a single bounds check for payload access;
 *      no loops and minimal stack usage.
 *    - Exactly one bpf_sk_select_reuseport() call per packet.
 *    - Deterministic except for the kernel’s own reuse->hash; all mutable
 *      state is explicit in pebble_agent_state.
 *
 * 4) Respect existing control surfaces:
 *    - Go initializes pebble_agent_state key 0 with
 *      AgentSelectorAgentState{Active: workers} on each server start. We
 *      mirror that layout by placing `active` as the first field of our
 *      struct; additional fields (counters) are zero‑initialized and need
 *      no userspace awareness.
 *
 * Worker split policy
 * -------------------
 * Let Active be the number of workers:
 *
 *   - Active <= 3:
 *       Too small to split effectively. All traffic (GET and SCAN) is
 *       round‑robined across all workers [0..Active-1].
 *
 *   - Active >= 4:
 *       Reserve a fixed, small tail subset for SCANs, and use the
 *       remaining head subset for GETs:
 *
 *         if Active >= 5: scan_slots = 2
 *         else           : scan_slots = 1   (for Active == 4)
 *
 *         get_slots = Active - scan_slots   (>= 1)
 *
 *       GETs  : round‑robin over [0 .. get_slots-1]
 *       SCANs : round‑robin over [get_slots .. Active-1]
 *
 *   - For the common case Active == 6:
 *       get_slots=4 (workers 0–3) handle GETs
 *       scan_slots=2 (workers 4–5) handle SCANs
 *
 * This gives SCANs more than one core at higher worker counts while still
 * preserving enough GET capacity and keeping the logic constant‑time.
 */

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

struct agent_state {
    __u32 active;   /* number of configured workers (0..active-1) */
    __u32 get_rr;   /* round-robin counter for GET (and generic) */
    __u32 scan_rr;  /* round-robin counter for SCAN workers */
    __u32 pad;      /* reserved for future use / alignment */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct agent_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_agent_state SEC(".maps");

/* Return 1 if the payload clearly starts with "SCAN", else 0. */
static __always_inline int classify_scan(struct sk_reuseport_md *reuse)
{
    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;

    /* Need at least 4 bytes to check "SCAN". */
    if ((char *)data + 4 > (char *)data_end)
        return 0;

    char *p = data;

    if (p[0] == 'S' && p[1] == 'C' && p[2] == 'A' && p[3] == 'N')
        return 1;

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

    __u32 slot = 0;

    if (active <= 3) {
        /* Small pools: just round-robin across all workers. */
        __u32 rr = state->get_rr++;
        if (active > 1)
            slot = rr % active;
        else
            slot = 0;
    } else {
        /*
         * Larger pools: reserve a small tail subset of workers for SCANs
         * and use the head subset for GETs.
         */
        __u32 scan_slots;

        if (active >= 5)
            scan_slots = 2;
        else
            scan_slots = 1;

        if (scan_slots >= active)
            scan_slots = active - 1;

        __u32 get_slots = active - scan_slots; /* >= 1 */

        int is_scan = classify_scan(reuse);

        if (is_scan) {
            __u32 rr = state->scan_rr++;
            if (scan_slots > 1)
                slot = get_slots + (rr % scan_slots);
            else
                slot = get_slots; /* single dedicated SCAN worker */
        } else {
            __u32 rr = state->get_rr++;
            if (get_slots > 1)
                slot = rr % get_slots;
            else
                slot = 0; /* only worker 0 for GETs */
        }
    }

    if (slot >= active) {
        /* Safety clamp; should not normally trigger. */
        if (active > 0)
            slot %= active;
        else
            slot = 0;
    }

    /* Exactly one selection attempt; kernel ignores any additional calls. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";