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

struct split_state {
    __u32 active;
    __u32 scan_counter;
    __u32 get_counter;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct split_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pebble_split_state SEC(".maps");

static __always_inline struct split_state *get_state()
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&pebble_split_state, &key);
}

static __always_inline char *udp_payload(struct sk_reuseport_md *reuse, __u32 needed)
{
    if (!reuse)
        return NULL;

    char *base = (char *)(__u64)reuse->data;
    void *end = (void *)(__u64)reuse->data_end;
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

static __always_inline __u32 clamp_scan_slots(__u32 active)
{
    if (active < 1)
        return active;
    return 1;
}

static __always_inline __u32 clamp_get_slots(__u32 active)
{
    if (active < 5)
        return active;
    return 5;
}

static __always_inline __u32 next_scan_index(struct split_state *state)
{
    __u32 value = state->scan_counter;
    state->scan_counter = value + 1;
    return value;
}

static __always_inline __u32 next_get_index(struct split_state *state)
{
    __u32 value = state->get_counter;
    state->get_counter = value + 1;
    return value;
}

SEC("sk_reuseport/selector")
enum sk_action split_udp_selector(struct sk_reuseport_md *reuse)
{
    struct split_state *state = get_state();
    if (!state)
        return SK_PASS;

    if (state->active == 0 || state->active > 128)
        return SK_PASS;

    __u32 active = state->active;
    bool scan = is_scan_request(reuse);

    __u32 slot = 0;

    if (scan) {
        __u32 scan_slots = clamp_scan_slots(active);
        if (scan_slots == 0)
            return SK_PASS;
        slot = next_scan_index(state) % scan_slots;
    } else {
        __u32 get_slots = clamp_get_slots(active);
        if (get_slots == 0)
            return SK_PASS;
        __u32 base = 0;
        if (active > get_slots)
            base = active - get_slots;
        slot = base + (next_get_index(state) % get_slots);
    }

    if (bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0) == 0)
        return SK_PASS;

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
