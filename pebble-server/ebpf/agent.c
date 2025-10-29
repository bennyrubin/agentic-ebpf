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

#define HEAVY_SCAN_THRESHOLD 80U
#define MAX_HEAVY_SLOTS 3U

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

static __always_inline bool parse_scan_details(struct sk_reuseport_md *reuse, __u32 *limit_out, __u32 *key_hash_out, bool *key_valid_out)
{
    if (!limit_out)
        return false;

    char *payload = udp_payload(reuse, 5);
    if (!payload)
        return false;

    if (payload[0] != 'S' || payload[1] != 'C' || payload[2] != 'A' || payload[3] != 'N')
        return false;

    char *cur = payload + 4;
    void *end = reuse->data_end;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++) {
        if ((void *)(cur + 1) > end)
            return false;
        if (*cur != ' ')
            break;
        cur++;
    }

    __u32 key_hash = 2166136261u;
    bool key_valid = false;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 32; i++) {
        if ((void *)(cur + 1) > end)
            return false;
        char c = *cur;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            break;
        key_valid = true;
        key_hash ^= (__u32)c;
        key_hash *= 16777619u;
        cur++;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++) {
        if ((void *)(cur + 1) > end)
            return false;
        if (*cur != ' ')
            break;
        cur++;
    }

    __u32 value = 0;
    bool any = false;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++) {
        if ((void *)(cur + 1) > end)
            break;
        char c = *cur;
        if (c < '0' || c > '9')
            break;
        any = true;
        value = value * 10 + (__u32)(c - '0');
        cur++;
    }

    if (!any)
        return false;

    *limit_out = value;
    if (key_hash_out)
        *key_hash_out = key_hash;
    if (key_valid_out)
        *key_valid_out = key_valid;

    return true;
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

    hash ^= (__u32)(bpf_ktime_get_ns() >> 17);
    hash = mix_hash(hash);

    if (active == 0)
        return SK_PASS;

    __u32 key_hash = 0;
    bool key_valid = false;
    bool heavy_scan = false;
    if (is_scan) {
        __u32 limit = 0;
        if (parse_scan_details(reuse, &limit, &key_hash, &key_valid)) {
            if (limit >= HEAVY_SCAN_THRESHOLD)
                heavy_scan = true;
        } else {
            heavy_scan = true;
        }
    }

    __u32 heavy_slots = 0;
    if (active > 2) {
        heavy_slots = active / 3;
        if (heavy_slots < 1)
            heavy_slots = 1;
        if (heavy_slots > MAX_HEAVY_SLOTS)
            heavy_slots = MAX_HEAVY_SLOTS;
        if (heavy_slots >= active)
            heavy_slots = active - 1;
    }

    __u32 normal_slots = active - heavy_slots;
    __u32 slot;

    if (heavy_scan && heavy_slots > 0) {
        __u32 heavy_hash = key_valid ? mix_hash(key_hash) : hash;
        slot = normal_slots + (heavy_hash % heavy_slots);
    } else {
        __u32 span = normal_slots > 0 ? normal_slots : active;
        slot = hash % span;
    }

    __u32 candidate = slot;
    if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &candidate, 0) == 0)
        return SK_PASS;

    __u32 fallback = hash % active;
    if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &fallback, 0) == 0)
        return SK_PASS;

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
