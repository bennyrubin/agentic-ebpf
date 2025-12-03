/*
 Pebble agent UDP reuseport selector (jittered, single-call, low-latency)

 What changed and why:
 - Prior “length split” never triggered: both GET and SCAN payloads are <50 B,
   so steering by reuse->len > 64 selected the same sockets and caused skew.
 - We instead spray packets uniformly by xoring reuse->hash with
   bpf_get_prandom_u32(), eliminating flow pinning when client flow count is
   small and keeping all workers busy.
 - Keep exactly one selection call and a cheap range reduction (pow2 mask or
   32x32->64 mul-high) to minimize instructions and tail latency.

 Verifier/compat notes:
 - No unbounded loops or stack use; only sk_reuseport_md/map helpers.
 - Map names/types unchanged; GPL license retained.
*/
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

/* EVOLVE-BLOCK-START
   Jittered, single-call selector:
   - h = reuse->hash ^ bpf_get_prandom_u32()
   - Fast range reduction (pow2 mask else mul-high).
   - Exactly one bpf_sk_select_reuseport; clamp active to [1,128].
*/
SEC("sk_reuseport/selector")
enum sk_action agent_udp_selector(struct sk_reuseport_md *reuse)
{
    __u32 key = 0;
    struct agent_state *st = bpf_map_lookup_elem(&pebble_agent_state, &key);
    if (!st)
        return SK_PASS;

    __u32 active = st->active;
    if (active == 0)
        return SK_PASS;
    if (active > 128)
        active = 128;
    if (active <= 1)
        return SK_PASS;

    __u32 h = reuse->hash ^ bpf_get_prandom_u32();

    __u32 slot;
    if ((active & (active - 1)) == 0) {
        slot = h & (active - 1);
    } else {
        __u64 prod = (__u64)h * active;
        slot = (__u32)(prod >> 32);
    }

    bpf_sk_select_reuseport(reuse, &pebble_udp_targets, &slot, 0);
    return SK_PASS;
}
// EVOLVE-BLOCK-END

char _license[] SEC("license") = "GPL";
