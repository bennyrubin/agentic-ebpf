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
 * This selector sends every incoming UDP request to one of the active
 * SO_REUSEPORT workers using a single global round‑robin counter stored
 * in pebble_agent_state. It is completely verb‑agnostic (no GET/SCAN
 * parsing), so all workers handle both short GETs and long SCANs.
 *
 * Goals satisfied:
 *   - No dedicated GET‑only or SCAN‑only workers: all N workers share
 *     the mixed workload, improving overall CPU utilization and pushing
 *     the queueing knee closer to the true CPU limit.
 *   - Load balanced by request count: a simple global RR counter spreads
 *     requests evenly across workers, which is a good approximation to
 *     cost‑proportional balancing when request costs are fairly stable.
 *   - Extremely cheap per packet: one ARRAY lookup, one atomic counter
 *     increment (BPF_XADD), a few integer ops, and a single
 *     bpf_sk_select_reuseport() call.
 *   - Minimal state and no new control surfaces: pebble_agent_state
 *     continues to be written from Go with only the Active field; rr is
 *     maintained solely by this BPF program.
 *
 * State layout
 * ------------
 *   struct agent_state {
 *       __u32 active;  // # of active workers, written by Go once
 *       __u32 rr;      // global round‑robin counter, updated in BPF
 *   };
 *
 * Implementation
 * --------------
 *   1) Look up agent_state[0]. If missing or active==0, return SK_PASS so
 *      the kernel chooses a socket.
 *   2) Clamp active to the sockarray size (128) for safety.
 *   3) Snapshot rr and then atomically increment it using XADD:
 *
 *         rr = state->rr;
 *         (void)__sync_fetch_and_add(&state->rr, 1);
 *
 *      We intentionally ignore the atomic's return value so that LLVM
 *      lowers it to a pure BPF_XADD without backend issues.
 *
 *   4) Compute slot = rr % active (or 0 if active==1) and call
 *      bpf_sk_select_reuseport() exactly once. If it fails, the kernel
 *      falls back to its own selection logic.
 *
 * The logic is straight‑line, uses only allowed helpers, maintains a
 * single counter in pebble_agent_state, and keeps per‑packet overhead
 * minimal while spreading mixed GET/SCAN load across all workers.
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

    /* Snapshot the current RR value, then atomically bump it.
     * We ignore the __sync_fetch_and_add() return value so LLVM/BPF
     * emits a plain XADD and stays verifier-friendly.
     */
    __u32 rr = state->rr;
    (void)__sync_fetch_and_add(&state->rr, 1);

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