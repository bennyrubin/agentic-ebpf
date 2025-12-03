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
 * See header comment for background.
 *
 * Implementation notes
 * --------------------
 * - We must never read from (data_end - X); the verifier treats data_end as
 *   a special "packet end" pointer that cannot be dereferenced or decremented.
 * - All payload accesses are done relative to `data` (the packet start)
 *   and are guarded with explicit bounds checks against `data_end`.
 *
 * The selector:
 *   1. Reads `active` from pebble_agent_state, clamped to [1, 128].
 *   2. Seeds a 32-bit hash with reuse->hash (kernel 4‑tuple hash).
 *   3. If there are at least 4 payload bytes, folds the first 4 bytes of the
 *      UDP payload into the hash using a simple FNV-style mix.
 *   4. Maps the mixed hash into [0, active) and calls bpf_sk_select_reuseport
 *      exactly once.
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
     * Deterministically mix in 4 bytes of the UDP payload, if present.
     * All accesses are done from `data` with bounds checks against
     * `data_end` to satisfy the verifier.
     */
    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;

    char *d = (char *)data;
    char *de = (char *)data_end;

    /* Ensure payload length >= 4: (d + 4) <= de */
    if (d + 4 <= de) {
        unsigned char *p = (unsigned char *)d;

        /* Build a 32‑bit value from the first 4 bytes (big-endian style). */
        __u32 t = ((__u32)p[0] << 24) |
                  ((__u32)p[1] << 16) |
                  ((__u32)p[2] << 8)  |
                  ((__u32)p[3]);

        /* Simple FNV-style mix: cheap, branchless, and verifier-friendly. */
        h ^= t;
        h *= 16777619u;
        h += 2166136261u;
    }

    __u32 slot = h % active;

    /* Single reuseport selection; the kernel ignores any additional calls. */
    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);

    return SK_PASS;
}

// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";