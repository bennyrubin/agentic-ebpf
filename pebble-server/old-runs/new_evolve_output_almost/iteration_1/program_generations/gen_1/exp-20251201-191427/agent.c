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
 * The kernel's default reuseport selection (and the original agent policy)
 * relied on sk_reuseport_md->hash, which is effectively per-flow. With only a
 * small number of UDP flows, that pins each 4‑tuple to one worker, causing hot
 * sockets with long queues and high tail latency, while other workers are idle.
 *
 * This selector ignores the kernel hash and implements a global round‑robin
 * over the active workers using a single counter stored in pebble_agent_state:
 *
 *   - pebble_agent_state[0].active is the number of active workers (slots
 *     [0, active)).
 *   - pebble_agent_state[0].counter holds the next slot index to use.
 *   - For each packet:
 *       * read active; if zero, fall back to SK_PASS.
 *       * clamp active to the sockarray capacity (128).
 *       * take 'next = counter'; if next >= active, wrap to 0.
 *       * select slot = next, then store counter = next + 1.
 *       * call bpf_sk_select_reuseport once with that slot.
 *
 * Properties:
 *   - Even with a single client flow, packets are spread across all active
 *     workers, balancing CPU and backlog and raising the effective throughput
 *     ceiling while keeping p99 latency low and flat under load.
 *   - The round‑robin is implemented without division (no modulo). We only use
 *     a compare‑and‑wrap step, which is cheaper in the BPF JIT than a 32‑bit
 *     divide, while still cycling deterministically over [0, active).
 *   - The design uses a single small ARRAY map value, one lookup, one write,
 *     and a single bpf_sk_select_reuseport call, staying well within verifier
 *     limits (no loops, minimal stack, no forbidden helpers).
 *   - User space continues to manage only the Active field; Counter is
 *     maintained by the BPF program and starts at zero when the map is
 *     (re)created or updated.
 */

struct agent_state {
    __u32 active;   /* number of active workers (slots [0, active)) */
    __u32 counter;  /* next slot index to use for round-robin */
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

    /*
     * Global round-robin without modulo:
     *
     *   next = state->counter;
     *   if next >= active: wrap to 0;
     *   slot = next;
     *   state->counter = next + 1;
     *
     * This cycles deterministically over [0, active) while avoiding a divide.
     */
    __u32 next = state->counter;
    if (next >= active)
        next = 0;

    __u32 slot = next;
    state->counter = next + 1;

    /* Single selection attempt; kernel ignores any additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";