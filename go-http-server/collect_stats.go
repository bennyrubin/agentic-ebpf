package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

// -------------------------------
// Configuration
// -------------------------------
var (
	cpuCores       = []int{0, 1, 2, 3}               // which cores to monitor
	updateInterval = 2 * time.Second                 // how often to update utilization
	alpha          = 0.25                            // smoothing factor for running average (0–1)
	mapPath        = "/sys/fs/bpf/tc/globals/cpu_util_map"      // pinned BPF map path
	maxCores       = 64                              // max entries in the map
)

// -------------------------------
// Types and helpers
// -------------------------------

type CPUStat struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal, Guest, GuestNice uint64
}

func readCPUStat() (map[int]CPUStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stats := make(map[int]CPUStat)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu") || line == "cpu " {
			continue
		}

		var cpu int
		var s CPUStat
		_, err := fmt.Sscanf(line, "cpu%d %d %d %d %d %d %d %d %d %d %d",
			&cpu, &s.User, &s.Nice, &s.System, &s.Idle,
			&s.IOWait, &s.IRQ, &s.SoftIRQ, &s.Steal, &s.Guest, &s.GuestNice)
		if err != nil {
			continue
		}
		stats[cpu] = s
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return stats, nil
}

func calculateUtilization(prev, curr CPUStat) float64 {
	prevIdle := prev.Idle + prev.IOWait
	currIdle := curr.Idle + curr.IOWait
	prevTotal := prev.User + prev.Nice + prev.System + prevIdle + prev.IRQ + prev.SoftIRQ + prev.Steal
	currTotal := curr.User + curr.Nice + curr.System + currIdle + curr.IRQ + curr.SoftIRQ + curr.Steal

	totald := float64(currTotal - prevTotal)
	idled := float64(currIdle - prevIdle)

	if totald == 0 {
		return 0.0
	}
	return (1.0 - idled/totald) * 100.0
}

// -------------------------------
// Map handling
// -------------------------------

func loadOrCreateMap(path string) (*ebpf.Map, error) {
	// Try to open the pinned map
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err == nil {
		log.Printf("Found pinned map at %s", path)
		return m, nil
	}

	log.Printf("Pinned map not found, creating new one at %s...", path)

	spec := &ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4, // float32
		MaxEntries: uint32(maxCores),
		Name:       "cpu_util_map",
	}

	m, err = ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create new map: %v", err)
	}

	if err := m.Pin(path); err != nil {
		return nil, fmt.Errorf("failed to pin map: %v", err)
	}

	log.Printf("Created and pinned map at %s", path)
	return m, nil
}

// -------------------------------
// Main
// -------------------------------

func main() {
	m, err := loadOrCreateMap(mapPath)
	if err != nil {
		log.Fatalf("Error setting up map: %v", err)
	}
	defer m.Close()

	fmt.Printf("Monitoring CPU cores %v\n", cpuCores)
	fmt.Printf("Update interval: %v, smoothing alpha: %.2f\n", updateInterval, alpha)

	prevStats, err := readCPUStat()
	if err != nil {
		log.Fatalf("failed to read /proc/stat: %v", err)
	}

	runningAvg := make(map[int]float64)

	for {
		time.Sleep(updateInterval)
		currStats, err := readCPUStat()
		if err != nil {
			log.Printf("error reading /proc/stat: %v", err)
			continue
		}

		for _, core := range cpuCores {
			prev, ok1 := prevStats[core]
			curr, ok2 := currStats[core]
			if !ok1 || !ok2 {
				continue
			}

			instUtil := calculateUtilization(prev, curr)
			oldAvg := runningAvg[core]
			newAvg := alpha*instUtil + (1-alpha)*oldAvg
			runningAvg[core] = newAvg

			var key uint32 = uint32(core)
			value := float32(newAvg)

			buf := new(bytes.Buffer)
			if err := binary.Write(buf, binary.LittleEndian, value); err != nil {
				log.Printf("failed to encode value for CPU %d: %v", core, err)
				continue
			}

			if err := m.Update(&key, buf.Bytes(), ebpf.UpdateAny); err != nil {
				log.Printf("failed to update BPF map for CPU %d: %v", core, err)
			} else {
				log.Printf("CPU %d: inst=%.1f%% avg=%.1f%%", core, instUtil, newAvg)
			}
		}

		prevStats = currStats
	}
}
