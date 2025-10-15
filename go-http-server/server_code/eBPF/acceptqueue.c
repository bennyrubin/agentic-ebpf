//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct acceptq {
    __u32 curr;
    __u32 max;
    __u32 cpu;
};

/* External maps shared with other programs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct acceptq);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acceptq_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acceptq_slot_cookies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64); // userspace still writes an int fd
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

SEC("sk_reuseport/selector")
enum sk_action acceptq_selector(struct sk_reuseport_md *reuse)
{
    /* Find slot with lowest accept queue utilization */
    __u32 best_slot = 0;
    __u32 lowest_util = 0xFFFFFFFF;

	for (__u32 i = 0; i < 4; i++) {
		__u64 *cookie = bpf_map_lookup_elem(&acceptq_slot_cookies, &i);
		if (!cookie || *cookie == 0) {
			bpf_printk("slot=%u no_cookie", i);
			continue;
		}

		struct acceptq *aq = bpf_map_lookup_elem(&acceptq_map, cookie);

		if (!aq) {
			bpf_printk("slot=%u cookie=0x%llx missing acceptq entry", i, *cookie);
			continue;
		}

		if (aq->max == 0)
			aq->max = 1;
		// Calculate utilization as percentage: (curr / max) * 100
		__u32 util = aq->curr;
		bpf_printk("slot=%u cookie=0x%llx curr=%u max=%u util=%u",
			   i, *cookie, aq->curr, aq->max, util);

		if (util < lowest_util) {
			lowest_util = util;
			best_slot = i;
        }
    }

    bpf_printk("acceptq: selected slot=%u util=%u", best_slot, lowest_util);

    long ret = bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &best_slot, 0);
    if (ret == 0) {
        return SK_PASS;
    }

    bpf_printk("acceptq: selection failed\n");
    return SK_DROP;
}

char _license[] SEC("license") = "GPL";
