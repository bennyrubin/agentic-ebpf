package ebpfutil

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g" -output-stem rrselector_bpf_nolock RrSelector ../../ebpf/round_robin.c -- -I../../ebpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g" AgentSelector ../../ebpf/agent.c -- -I../../ebpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g" ScanSplitSelector ../../ebpf/scan_split.c -- -I../../ebpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g" HashSelector ../../ebpf/hash.c -- -I../../ebpf
