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
 * We distribute every incoming UDP request across *all* active SO_REUSEPORT
 * workers using a single global round‑robin counter stored in pebble_agent_state.
 * There is no verb awareness: both GET and SCAN requests are steered using the
 * same mechanism, so every worker can serve both short and long requests.
 *
 * This matches the goals:
 *   - No permanent GET‑only / SCAN‑only workers: all N workers share the full
 *     mixed workload, pushing the queueing knee closer to the true CPU limit.
 *   - Extremely cheap per packet: one array lookup, one atomic increment, a few
 *     integer ops, and a single bpf_sk_select_reuseport() call.
 *   - Minimal state: pebble_agent_state holds just:
 *
 *       struct agent_state {
 *           __u32 active;  // # of workers (written once by Go)
 *           __u32 rr;      // global round‑robin counter (maintained in BPF)
 *       };
 *
 *   - No userspace changes: Go continues to write only Active; rr starts at 0
 *     and is updated entirely inside the BPF program.
 *
 * Implementation details
 * ----------------------
 * 1) Load agent_state[0]. If missing or Active==0, fall back to SK_PASS and let
 *    the kernel pick a socket.
 *
 * 2) Atomically increment rr with __sync_fetch_and_add(). The return value of
 *    the built‑in is intentionally ignored so that LLVM/BPF can safely lower it
 *    to a pure BPF_XADD without triggering "Invalid usage of the XADD return
 *    value" in the backend. We read the pre‑increment value separately.
 *
 * 3) Mix in the current CPU ID to decorrelate selections coming from different
 *    CPUs while still using a single global counter:
 *
 *        slot = (rr + cpu_id) % active;
 *
 *    This keeps effective round‑robin fairness but reduces the chance that all
 *    CPUs momentarily contend for the same worker when the counter wraps or
 *    bursts arrive in lockstep.
 *
 * 4) Call bpf_sk_select_reuseport exactly once using that slot into the
 *    pebble_udp_targets sockarray. If the helper fails, the kernel will fall
 *    back to its own reuseport selection.
 *
 * The logic is straight‑line, uses only verifier‑approved helpers, and keeps
 * per‑packet overhead minimal while balancing load across all workers.
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
     * The LLVM BPF backend does not allow using the XADD return
     * value, so we:
     *   1) read state->rr into a local variable (non-atomic),
     *   2) issue an XADD via __sync_fetch_and_add(), ignoring
     *      its return value.
     *
     * This keeps contention low and satisfies the backend and
     * verifier constraints.
     */
    __u32 rr = state->rr;
    (void)__sync_fetch_and_add(&state->rr, 1);

    /* Use CPU ID as a phase offset so each CPU walks the ring
     * with a slightly different starting point. This keeps the
     * policy verb-agnostic but smooths cross-CPU contention.
     */
    __u32 cpu = bpf_get_smp_processor_id();

    __u32 slot;
    if (active > 1)
        slot = (rr + cpu) % active;
    else
        slot = 0;

    /* Exactly one helper call; extra calls would be ignored. */
    (void)bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";