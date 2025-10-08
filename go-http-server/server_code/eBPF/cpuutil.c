//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* External maps shared with other programs */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32); // CPU utilization * 100
} cpu_util_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64); // userspace still writes an int fd
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

SEC("sk_reuseport/selector")
enum sk_action cpuutil_selector(struct sk_reuseport_md *reuse)
{
    /* Slot to CPU mapping: slot 0->CPU 0, slot 1->CPU 2, slot 2->CPU 1, slot 3->CPU 3 */
    __u32 slot_to_cpu[4] = {0, 2, 4, 6};

    /* Find slot with lowest CPU utilization */
    __u32 best_slot = 0;
    __u32 lowest_util = 0xFFFFFFFF;

    for (__u32 i = 0; i < 4; i++) {
        __u32 cpu = slot_to_cpu[i];

        // Look up CPU utilization
        __u32 *util_p = bpf_map_lookup_elem(&cpu_util_map, &cpu);
        __u32 util = util_p ? *util_p : 0;

        bpf_printk("slot=%u cpu=%u util=%u", i, cpu, util);

        if (util < lowest_util) {
            lowest_util = util;
            best_slot = i;
        }
    }

    bpf_printk("cpuutil: selected slot=%u cpu=%u util=%u",
               best_slot, slot_to_cpu[best_slot], lowest_util);

    long ret = bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &best_slot, 0);
    if (ret == 0) {
        return SK_PASS;
    }

    bpf_printk("cpuutil: selection failed\n");
    return SK_DROP;
}

char _license[] SEC("license") = "GPL";
