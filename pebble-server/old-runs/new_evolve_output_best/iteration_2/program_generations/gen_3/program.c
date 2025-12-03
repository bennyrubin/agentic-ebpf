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
 * This selector sends every incoming UDP packet to one of the active
 * SO_REUSEPORT workers using a single global round‑robin counter stored in
 * pebble_agent_state. It is completely verb‑agnostic (no GET/SCAN parsing),
 * so all workers handle both short GETs and long SCANs.
 *
 * Goals satisfied:
 *   - No dedicated GET‑only or SCAN‑only workers: all N workers share the
 *     mixed workload, improving overall CPU utilization and pushing the
 *     queueing knee closer to the true CPU limit.
 *   - Load balanced by request count via a single, global RR counter, which
 *     is a good fit when per‑verb CPU costs are stable.
 *   - Extremely cheap per packet: one ARRAY lookup, one atomic
 *     fetch‑and‑increment (BPF_XADD), a few integer ops, and one
 *     bpf_sk_select_reuseport() call.
 *   - Minimal state and no new control surfaces: pebble_agent_state holds
 *     only:
 *
 *         struct agent_state {
 *             __u32 active;  // # of workers, written by Go
 *             __u32 rr;      // global round‑robin counter, in BPF
 *         };
 *
 *     Go continues to write only Active; rr is zero‑initialized and then
 *     maintained entirely in this program.
 *
 * Implementation
 * --------------
 *   1) Look up agent_state[0]. If missing or active==0, return SK_PASS so
 *      the kernel chooses a socket.
 *   2) Clamp active to the sockarray size (128) for safety.
 *   3) Atomically fetch‑and‑increment rr:
 *
 *         rr = __sync_fetch_and_add(&state->rr, 1);
 *
 *      LLVM lowers this to a BPF_XADD on the map value, which is safe under
 *      concurrency and verifier‑friendly.
 *
 *   4) Compute slot = rr % active (or 0 if active==1) and call
 *      bpf_sk_select_reuseport() exactly once. If the helper fails, the
 *      kernel falls back to its default selection logic.
 *
 * The logic is straight‑line, uses only allowed helpers, and keeps per‑packet
 * overhead tiny while spreading mixed GET/SCAN load across all workers.
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

    /* Safety clamp: sockarray is sized to 128 entries. */
    if (active > 128)
        active = 128;

    /* Atomically fetch-and-increment the global RR counter.
     * The returned value is the pre-increment snapshot we use
     * to compute the slot.
     */
    __u32 rr = __sync_fetch_and_add(&state->rr, 1);

    __u32 slot;
    if (active > 1)
        slot = rr % active;
    else
        slot = 0;

    /* Exactly one selection attempt; extra calls would be ignored. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";