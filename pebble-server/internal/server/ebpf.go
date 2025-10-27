package server

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"pebbleserver/internal/ebpfutil"
)

const targetMapPath = "/sys/fs/bpf/pebble_udp_targets"

type ebpfPolicy struct {
	name    string
	program *ebpf.Program
	close   func() error
}

func ensureRlimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("adjust memlock: %w", err)
	}
	return nil
}

func loadEBPF(policy string, workers int) (*ebpfPolicy, error) {
	switch policy {
	case "default", "":
		return &ebpfPolicy{name: "default"}, nil
	case "round_robin":
		return loadRoundRobin(workers)
	case "agent":
		return loadAgent()
	default:
		return nil, ErrInvalidConfig(fmt.Sprintf("unknown policy %q", policy))
	}
}

func loadRoundRobin(workers int) (*ebpfPolicy, error) {
	if err := ensureRlimit(); err != nil {
		return nil, err
	}
	var objs ebpfutil.RrSelectorObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	}
	if err := ebpfutil.LoadRrSelectorObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("load round robin objects: %w", err)
	}

	var key uint32 = 0
	state := ebpfutil.RrSelectorRrState{}
	if err := objs.PebbleRrState.Lookup(&key, &state); err != nil {
		state.Active = uint32(workers)
		state.Counter = 0
	} else {
		state.Active = uint32(workers)
	}
	if err := objs.PebbleRrState.Update(&key, &state, ebpf.UpdateAny); err != nil {
		objs.Close()
		return nil, fmt.Errorf("configure round robin state: %w", err)
	}

	return &ebpfPolicy{
		name:    "round_robin",
		program: objs.RrUdpSelector,
		close:   objs.Close,
	}, nil
}

func loadAgent() (*ebpfPolicy, error) {
	if err := ensureRlimit(); err != nil {
		return nil, err
	}
	var objs ebpfutil.AgentSelectorObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"},
	}
	if err := ebpfutil.LoadAgentSelectorObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("load agent objects: %w", err)
	}
	return &ebpfPolicy{
		name:    "agent",
		program: objs.AgentUdpSelector,
		close:   objs.Close,
	}, nil
}

func (p *ebpfPolicy) Close() error {
	if p == nil || p.close == nil {
		return nil
	}
	return p.close()
}

func (p *ebpfPolicy) attach(fd int) error {
	if p == nil || p.program == nil {
		return nil
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, p.program.FD()); err != nil {
		return fmt.Errorf("attach reuseport ebpf: %w", err)
	}
	return nil
}

func updateTargetsMap(slot uint32, fd int) error {
	m, err := ebpf.LoadPinnedMap(targetMapPath, nil)
	if err != nil {
		return fmt.Errorf("load target map: %w", err)
	}
	defer m.Close()

	value := uint32(fd)
	if err := m.Update(&slot, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update target map: %w", err)
	}
	return nil
}

func clearTargets(numSlots int) error {
	m, err := ebpf.LoadPinnedMap(targetMapPath, nil)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer m.Close()

	for i := 0; i < numSlots; i++ {
		key := uint32(i)
		if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("clear slot %d: %w", i, err)
		}
	}
	return nil
}
