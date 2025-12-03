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
 *    - The previous policy used only reuse->hash % Active plus a linear
 *      probe. With a single UDPConn sender this produced a strong bias
 *      where 1–2 workers stayed almost idle even when others were
 *      saturated.
 *    - This version uses a simple round‑robin counter stored in
 *      pebble_agent_state so that every packet advances the index,
 *      ensuring that all [0..Active-1) workers see traffic regardless
 *      of the flow hash.
 *
 * 2) Isolate long SCAN requests from short GETs:
 *    - SCANs are rare but ~200x more expensive than GETs, so sharing
 *      workers causes head‑of‑line blocking for GETs and inflates p99.
 *    - We classify requests by peeking into the UDP payload: payloads
 *      begin with the ASCII verb "GET " or "SCAN " (see buildPayload
 *      in the client). We parse IPv4+UDP headers using ctx->data /
 *      ctx->data_end from struct sk_reuseport_md and check for "SCAN".
 *    - For Active >= 3, we dedicate a small tail subset of workers to
 *      SCAN requests (roughly 1/4 of the pool, clamped so at least one
 *      worker always handles GETs). GETs are round‑robined across the
 *      remaining workers; SCANs across the scan subset. For very small
 *      worker counts (<=2), we skip splitting and just round‑robin.
 *
 * 3) Keep the selector verifier‑friendly and cheap:
 *    - One array map lookup (pebble_agent_state), no additional maps.
 *    - No loops, only straight‑line bounds‑checked header parsing.
 *    - Exactly one bpf_sk_select_reuseport() call per packet.
 *    - All randomness‑free and deterministic; state is kept only in
 *      pebble_agent_state via simple 32‑bit counters.
 *
 * 4) Respect existing control surfaces:
 *    - The Go server writes AgentSelectorAgentState{Active: workers}
 *      into pebble_agent_state at key 0. We extend the C struct with
 *      extra fields for our counters; they are zero‑initialised on
 *      update, so behavior is well‑defined without any Go changes.
 */

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

struct agent_state {
    __u32 active;   /* number of configured workers (0..Active-1) */
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

static __always_inline int classify_scan(struct sk_reuseport_md *reuse)
{
    /* Default to "not a SCAN" unless we can confidently detect "SCAN". */
    int is_scan = 0;

    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;
    char *cursor = data;

    /* We assume data starts at the IPv4 header (consistent with sk_reuseport_md). */
    struct iphdr *iph = (struct iphdr *)cursor;
    if ((void *)(iph + 1) > data_end)
        return 0;

    if (iph->protocol != IPPROTO_UDP)
        return 0;

    __u32 ihl_len = (__u32)iph->ihl * 4;
    if (ihl_len < sizeof(*iph))
        return 0;

    cursor += ihl_len;
    if ((void *)cursor + sizeof(struct udphdr) > data_end)
        return 0;

    cursor += sizeof(struct udphdr);
    if ((void *)cursor + 4 > data_end)
        return 0;

    /* Payload begins with "GET " or "SCAN ". We only need to detect "SCAN". */
    if (cursor[0] == 'S' && cursor[1] == 'C' &&
        cursor[2] == 'A' && cursor[3] == 'N')
        is_scan = 1;

    return is_scan;
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

    /* Classify request type using UDP payload, if possible. */
    int is_scan = classify_scan(reuse);

    __u32 slot = 0;

    if (active <= 2) {
        /* Small pools: just round-robin across all workers. */
        __u32 rr = state->get_rr++;
        if (active > 1)
            slot = rr % active;
        else
            slot = 0;
    } else {
        /*
         * Larger pools: reserve a small tail subset of workers for SCAN.
         * - scan_slots ≈ active / 4, but at least 1 and at most active-1.
         * - Workers [0 .. get_slots-1]  : primarily GET traffic.
         * - Workers [get_slots .. active-1] : SCAN traffic.
         */
        __u32 scan_slots = active / 4;
        if (scan_slots == 0)
            scan_slots = 1;
        if (scan_slots >= active)
            scan_slots = active - 1;

        __u32 get_slots = active - scan_slots; /* >= 1 */

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