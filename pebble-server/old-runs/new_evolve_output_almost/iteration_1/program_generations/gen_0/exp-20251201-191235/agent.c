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
 * Approach / rationale
 * --------------------
 * The previous selector derived a starting slot from sk_reuseport_md->hash and
 * then linearly probed the reuseport array. Because the kernel hash is
 * per-flow, this effectively pinned each 4‑tuple to a single worker. With the
 * workload using only a small number of UDP flows, this produced hot sockets
 * with long queues and high tail latency, while other workers were underused.
 *
 * This version removes dependence on the kernel hash and instead implements a
 * simple global round‑robin over the active workers:
 *
 *   - pebble_agent_state[0].counter is a global packet counter.
 *   - pebble_agent_state[0].active is the number of active workers (as before).
 *   - For each packet, we compute slot = counter % active and increment
 *     counter, then call bpf_sk_select_reuseport once for that slot.
 *
 * Consequences:
 *   - Even a single client flow is spread across all active workers, so CPU
 *     load and backlog are balanced, pushing the service ceiling closer to the
 *     true aggregate capacity and reducing tail latency under load.
 *   - The selector is extremely simple: one map lookup, a few ALU ops, one
 *     map write, and a single bpf_sk_select_reuseport call. There are no
 *     loops, minimal stack usage, and only verifier‑friendly helpers.
 *   - User space only needs to maintain the existing Active field; Counter is
 *     managed by the program itself and starts from zero when the map is
 *     created or replaced.
 */

struct agent_state {
    __u32 active;   /* number of active workers (slots [0, active)) */
    __u32 counter;  /* global packet counter for round-robin */
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
    /* Lookup global agent state (index 0). */
    __u32 key = 0;
    struct agent_state *state = bpf_map_lookup_elem(&pebble_agent_state, &key);
    if (!state)
        return SK_PASS;

    __u32 active = state->active;
    if (active == 0)
        return SK_PASS;

    /* Safety clamp: map holds at most 128 entries. */
    if (active > 128)
        active = 128;

    /* Global round-robin: slot = counter % active. */
    __u32 counter = state->counter;
    __u32 slot = counter % active;
    state->counter = counter + 1;

    /* Single selection attempt; kernel ignores any additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";