//go:build ignore

#include <linux/bpf.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_udp_targets SEC(".maps");

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

struct agent_slot_stats {
    __u64 last_assigned;
    __u64 last_scan;
    __u64 virtual_load;
    __u64 last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, struct agent_slot_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_agent_slots SEC(".maps");

#define FRESH_GAP (1ull << 60)
#define LOAD_DECAY_NS 500000ULL
#define LOAD_GET_WEIGHT 1ULL
#define LOAD_SCAN_WEIGHT 6ULL
#define LOAD_MAX 1000ULL
#define SCAN_PENALTY_NS 2000000ULL
#define SCAN_PENALTY_WEIGHT 2ULL

static __always_inline __u32 get_active_workers()
{
    __u32 key = 0;
    struct agent_state *state = bpf_map_lookup_elem(&pebble_agent_state, &key);
    if (!state)
        return 0;

    if (state->active == 0 || state->active > 128)
        return 0;

    return state->active;
}

static __always_inline __u32 mix_hash(__u32 hash)
{
    hash ^= hash >> 16;
    hash *= 0x7feb352d;
    hash ^= hash >> 15;
    hash *= 0x846ca68b;
    hash ^= hash >> 16;
    return hash;
}

static __always_inline __u64 compute_virtual_load(const struct agent_slot_stats *stats, __u64 now)
{
    if (!stats)
        return 0;

    __u64 current = stats->virtual_load;

    if (stats->last_update != 0 && now > stats->last_update) {
        __u64 elapsed = now - stats->last_update;
        __u64 decay = elapsed / LOAD_DECAY_NS;
        if (decay >= current)
            current = 0;
        else
            current -= decay;
    }

    return current;
}

static __always_inline void update_slot_stats(struct agent_slot_stats *stats, __u64 now, bool is_scan)
{
    if (!stats)
        return;

    __u64 current = compute_virtual_load(stats, now);
    __u64 weight = is_scan ? LOAD_SCAN_WEIGHT : LOAD_GET_WEIGHT;
    if (current >= LOAD_MAX - weight)
        current = LOAD_MAX;
    else
        current += weight;

    stats->virtual_load = current;
    stats->last_update = now;
    stats->last_assigned = now;
    if (is_scan)
        stats->last_scan = now;
}

static __always_inline char *udp_payload(struct sk_reuseport_md *reuse, __u32 needed)
{
    if (!reuse)
        return NULL;

    char *base = (char *)(reuse->data);
    void *end = reuse->data_end;

    if ((void *)(base + sizeof(struct udphdr)) > end)
        return NULL;

    char *payload = base + sizeof(struct udphdr);
    if ((void *)(payload + needed) > end)
        return NULL;

    return payload;
}

static __always_inline bool is_scan_request(struct sk_reuseport_md *reuse)
{
    char *payload = udp_payload(reuse, 4);
    if (!payload)
        return false;

    return payload[0] == 'S' && payload[1] == 'C' && payload[2] == 'A' && payload[3] == 'N';
}

SEC("sk_reuseport/selector")
enum sk_action agent_udp_selector(struct sk_reuseport_md *reuse)
{
    __u32 active = get_active_workers();

    __u32 hash = reuse->hash;
    if (hash == 0)
        hash = bpf_get_prandom_u32();

    bool is_scan = is_scan_request(reuse);
    if (is_scan)
        hash ^= 0x9e3779b9;

    __u64 now = bpf_ktime_get_ns();
    hash ^= (__u32)(now >> 17);
    hash = mix_hash(hash);

    if (active > 0) {
        __u32 search = active < 32 ? active : 32;
        __u32 start = hash % active;

        __u32 best_slot = 0;
        __u64 best_gap = 0;
        __u64 best_load = (~0ull);
        bool found = false;

        #pragma clang loop unroll(full)
        for (int i = 0; i < 32; i++) {
            if (i >= search)
                break;

            __u32 slot = start + (__u32)i;
            if (slot >= active)
                slot -= active;

            __u32 key = slot;
            struct agent_slot_stats *stats = bpf_map_lookup_elem(&pebble_agent_slots, &key);

            __u64 gap = FRESH_GAP;
            if (stats && stats->last_assigned != 0 && now > stats->last_assigned)
                gap = now - stats->last_assigned;

            __u64 load = compute_virtual_load(stats, now);
            if (is_scan && stats && stats->last_scan != 0 && now > stats->last_scan) {
                __u64 delta = now - stats->last_scan;
                if (delta < SCAN_PENALTY_NS)
                    load += SCAN_PENALTY_WEIGHT;
            }

            if (!found || load < best_load || (load == best_load && gap > best_gap)) {
                best_load = load;
                best_gap = gap;
                best_slot = slot;
                found = true;
            }
        }

        if (found) {
            __u32 candidate = best_slot;
            if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &candidate, 0) == 0) {
                __u32 key = candidate;
                struct agent_slot_stats *stats = bpf_map_lookup_elem(&pebble_agent_slots, &key);
                update_slot_stats(stats, now, is_scan);
                return SK_PASS;
            }
        }

        __u32 fallback_slot = start;
        #pragma clang loop unroll(full)
        for (int i = 0; i < 32; i++) {
            if (i >= search)
                break;

            __u32 slot = fallback_slot + (__u32)i;
            if (slot >= active)
                slot -= active;

            __u32 candidate = slot;
            if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &candidate, 0) == 0) {
                __u32 key = candidate;
                struct agent_slot_stats *stats = bpf_map_lookup_elem(&pebble_agent_slots, &key);
                update_slot_stats(stats, now, is_scan);
                return SK_PASS;
            }
        }
    }

    __u32 fallback = 0;
    if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &fallback, 0) == 0)
        return SK_PASS;
    return SK_PASS;
}