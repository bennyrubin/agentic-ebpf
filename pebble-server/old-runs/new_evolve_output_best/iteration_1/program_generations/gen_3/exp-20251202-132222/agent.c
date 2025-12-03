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
 * 1) Use a shared agent_state with:
 *      - active: number of SO_REUSEPORT workers (set by Go, kept as‑is).
 *      - get_rr: round‑robin counter for GET (and generic) traffic.
 *      - scan_rr: round‑robin counter for SCAN traffic.
 *
 *    Go only initializes `Active`; the extra fields are zero‑initialized
 *    automatically on map update. This respects the existing control
 *    surface while giving us cheap per‑packet state.
 *
 * 2) Drive all workers:
 *      - For small pools (active <= 3), we just round‑robin across the
 *        full [0..active-1] range using get_rr. This avoids wasting a
 *        worker on a split that would not meaningfully help.
 *
 *      - For larger pools (active >= 4), we reserve a small tail subset
 *        of workers for SCAN requests and use the head subset for GETs:
 *
 *            if (active >= 5)  scan_slots = 2;
 *            else              scan_slots = 1;   // active == 4
 *            get_slots = active - scan_slots;    // >= 1
 *
 *        GETs  : worker indices [0 .. get_slots-1]
 *        SCANs : worker indices [get_slots .. active-1]
 *
 *        With the common configuration active == 6, this yields:
 *          - 4 GET workers  (0–3)
 *          - 2 SCAN workers (4–5)
 *
 *        All workers are driven via simple round‑robin counters, so we
 *        avoid the hash‑bias that left some workers idle in the baseline.
 *
 * 3) Isolate long SCAN requests:
 *      - Client payloads begin with the ASCII verb "GET " or "SCAN ".
 *      - In sk_reuseport_md, reuse->data may point at different layers
 *        depending on kernel version (IPv4 header, UDP header, or UDP
 *        payload). Previous iterations assumed a single layout and
 *        misclassified all SCANs as GETs.
 *
 *      - Here we use a cheap, verifier‑friendly classifier that tries
 *        three interpretations of reuse->data, all under tight bounds:
 *
 *          a) IPv4 header -> UDP header -> payload
 *          b) UDP header  -> payload
 *          c) Payload directly
 *
 *        If any interpretation finds a payload starting with "SCAN", the
 *        packet is treated as SCAN; otherwise it is treated as GET.
 *
 * 4) Verifier‑friendly and cheap:
 *      - One array map lookup (pebble_agent_state).
 *      - No loops, only straight‑line code.
 *      - Minimal stack usage, no dynamic allocation.
 *      - Exactly one bpf_sk_select_reuseport() call per packet.
 *      - Deterministic logic; the only shared state is the two 32‑bit
 *        round‑robin counters in the map.
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

/* Check whether p (within [data, data_end)) starts with "SCAN". */
static __always_inline int has_scan_prefix(char *p, void *data_end)
{
    if (p + 4 > (char *)data_end)
        return 0;

    if (p[0] == 'S' && p[1] == 'C' && p[2] == 'A' && p[3] == 'N')
        return 1;

    return 0;
}

/*
 * Classify packet as SCAN (return 1) or not (return 0) by decoding enough
 * of the layout around reuse->data to find the UDP payload start.
 *
 * We support three possible layouts for reuse->data:
 *   1) IPv4 header       -> UDP header -> payload
 *   2) UDP header        -> payload
 *   3) Payload directly
 *
 * All paths are fully bounds-checked and loop-free.
 */
static __always_inline int classify_scan(struct sk_reuseport_md *reuse)
{
    void *data = (void *)(long)reuse->data;
    void *data_end = (void *)(long)reuse->data_end;
    char *cursor = (char *)data;

    /* Path 1: assume data points at an IPv4 header. */
    if (cursor + sizeof(struct iphdr) <= (char *)data_end) {
        struct iphdr *iph = (struct iphdr *)cursor;

        if (iph->version == 4 && iph->protocol == IPPROTO_UDP) {
            __u32 ihl = iph->ihl;
            if (ihl >= 5) {
                __u32 ip_hdr_len = ihl * 4;

                if (cursor + ip_hdr_len + sizeof(struct udphdr) <=
                    (char *)data_end) {
                    char *p = cursor + ip_hdr_len + sizeof(struct udphdr);
                    if (has_scan_prefix(p, data_end))
                        return 1;
                }
            }
        }
    }

    /* Path 2: assume data points at a UDP header. */
    cursor = (char *)data;
    if (cursor + sizeof(struct udphdr) <= (char *)data_end) {
        char *p = cursor + sizeof(struct udphdr);
        if (has_scan_prefix(p, data_end))
            return 1;
    }

    /* Path 3: assume data already points at the payload. */
    cursor = (char *)data;
    if (has_scan_prefix(cursor, data_end))
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
         *
         *   - For Active == 4: 3 GET, 1 SCAN
         *   - For Active >= 5: Active-2 GET, 2 SCAN
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