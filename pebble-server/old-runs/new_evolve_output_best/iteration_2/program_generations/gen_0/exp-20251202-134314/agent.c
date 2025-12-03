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
 * Approach
 * --------
 * This selector intentionally does NOT special‑case GET vs SCAN or reserve
 * any workers for a particular verb. Instead, every incoming packet is
 * distributed in a simple, global round‑robin across all configured
 * SO_REUSEPORT workers.
 *
 * Motivation:
 *   - Under mixed GET/SCAN workloads, dedicating a subset of workers to
 *     SCANs leaves some cores under‑utilized when SCAN traffic is sparse,
 *     and causes localized queue build‑ups when SCANs surge.
 *   - By letting all N workers handle both short (GET) and long (SCAN)
 *     requests, we keep utilization more uniform and push the queueing
 *     knee closer to the true CPU limit.
 *   - We deliberately avoid per‑flow hashing so that occasional long SCANs
 *     are smeared across workers instead of all landing on one unlucky
 *     socket, which reduces tail latency at high load.
 *
 * Design:
 *   - The pebble_agent_state map stores:
 *
 *       struct agent_state {
 *           __u32 active;  // number of workers; written by Go once
 *           __u32 rr;      // global round‑robin counter; updated in BPF
 *       };
 *
 *     Go code already writes only the Active field; rr is naturally
 *     zero‑initialized on map update and then maintained entirely in BPF.
 *
 *   - For each packet:
 *       1) Read active. If zero, fall back to kernel selection (SK_PASS).
 *       2) Increment rr and compute slot = rr % active (or 0 if active==1).
 *       3) Call bpf_sk_select_reuseport exactly once with that slot.
 *
 * Properties:
 *   - Verb‑agnostic: does not inspect payloads at all.
 *   - Minimal state: one counter shared by all CPUs plus Active.
 *   - Straight‑line, verifier‑friendly logic (no loops, no complex parsing).
 *   - Cheap per packet: one map lookup, one 32‑bit increment, one 32‑bit
 *     division, and a single bpf_sk_select_reuseport() helper call.
 */

struct agent_state {
    __u32 active; /* number of configured workers (0..active-1) */
    __u32 rr;     /* global round-robin counter */
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

    /* Clamp to the sockarray size for safety, though Go should enforce this. */
    if (active > 128)
        active = 128;

    /* Global round-robin across [0 .. active-1]. Exact atomicity is not
     * required; approximate fairness is sufficient under load. */
    __u32 rr = state->rr++;
    __u32 slot = 0;

    if (active > 1)
        slot = rr % active;
    else
        slot = 0;

    /* Extra safety: ensure slot is in range even if Active changed between
     * reading it and using it. */
    if (slot >= active)
        slot = slot % active;

    /* Exactly one selection attempt; additional calls would be ignored. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";