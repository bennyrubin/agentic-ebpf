package ebpfutil

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g" RrSelector ../../ebpf/round_robin.c -- -I../../ebpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-O2 -g" AgentSelector ../../ebpf/agent.c -- -I../../ebpf
