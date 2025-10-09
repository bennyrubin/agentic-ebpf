package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

var (
	updateInterval = 50 * time.Millisecond
	alpha          = 0.25
	mapPath        = "/sys/fs/bpf/cpu_util_map"
	acceptqMapPath = "/sys/fs/bpf/acceptq_per_cpu_map"
	acceptqProgObj = "server_code/eBPF/acceptq_bpf.o"
	acceptqProgPin = "/sys/fs/bpf/acceptq_bpf"
	maxCores       = 64
)

type CPUStat struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal, Guest, GuestNice uint64
}

type acceptqEntry struct {
	Curr uint32
	Max  uint32
	Cpu  uint32
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

func loadOrCreateMap(path string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err == nil {
		log.Printf("Found pinned map at %s", path)
		return m, nil
	}

	log.Printf("Pinned map not found, creating new one at %s...", path)

	spec := &ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
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

func ensureAcceptqProgramLoaded() (func(), error) {
	if _, err := os.Stat(acceptqProgPin); err == nil {
		log.Printf("Accept queue program already pinned at %s, not reloading", acceptqProgPin)
		return nil, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat %s: %w", acceptqProgPin, err)
	}

	objPath, err := filepath.Abs(acceptqProgObj)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path to %s: %w", acceptqProgObj, err)
	}

	cmd := exec.Command("sudo", "bpftool", "prog", "load",
		objPath, acceptqProgPin, "type", "kprobe", "autoattach")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("bpftool load failed: %v (output: %s)", err, strings.TrimSpace(string(output)))
	}

	log.Printf("Loaded accept queue BPF program from %s to %s", objPath, acceptqProgPin)

	cleanup := func() {
		cmd := exec.Command("sudo", "rm", "-f", acceptqProgPin)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("failed to remove pinned accept queue program %s: %v (output: %s)", acceptqProgPin, err, strings.TrimSpace(string(output)))
			return
		}
		log.Printf("Removed pinned accept queue program at %s", acceptqProgPin)
	}

	return cleanup, nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cpuCoresStr := flag.String("cpus", "0 1 2 3", "space-separated list of CPU cores to monitor (e.g., \"0 1 2 3\")")
	logDir := flag.String("logdir", "log", "directory where log files will be written")
	logPeriod := flag.Duration("period", time.Second, "interval between log snapshots")
	flag.Parse()

	cpuCores := []int{}
	for _, s := range strings.Fields(*cpuCoresStr) {
		core, err := strconv.Atoi(s)
		if err != nil {
			log.Fatalf("invalid CPU core number: %s", s)
		}
		cpuCores = append(cpuCores, core)
	}
	if len(cpuCores) == 0 {
		log.Fatalf("no CPU cores specified")
	}

	if err := os.MkdirAll(*logDir, 0o755); err != nil {
		log.Fatalf("failed to create log directory %s: %v", *logDir, err)
	}

	timestamp := time.Now().Format("20060102_150405")
	cpuLogPath := filepath.Join(*logDir, fmt.Sprintf("cpu_stats_%s.log", timestamp))
	acceptqLogPath := filepath.Join(*logDir, fmt.Sprintf("acceptq_stats_%s.log", timestamp))

	cpuLogFile, err := os.OpenFile(cpuLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("failed to open CPU log file: %v", err)
	}
	defer cpuLogFile.Close()
	cpuLogger := log.New(cpuLogFile, "", log.LstdFlags)

	acceptqLogFile, err := os.OpenFile(acceptqLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("failed to open accept queue log file: %v", err)
	}
	defer acceptqLogFile.Close()
	acceptqLogger := log.New(acceptqLogFile, "", log.LstdFlags)

	m, err := loadOrCreateMap(mapPath)
	if err != nil {
		log.Fatalf("Error setting up cpu util map: %v", err)
	}
	defer m.Close()

	acceptqCleanup, err := ensureAcceptqProgramLoaded()
	if err != nil {
		log.Fatalf("failed to ensure accept queue program is loaded: %v", err)
	}
	if acceptqCleanup != nil {
		defer acceptqCleanup()
	}

	var acceptqMap *ebpf.Map
	defer func() {
		if acceptqMap != nil {
			acceptqMap.Close()
		}
	}()

	log.Printf("Monitoring CPU cores %v", cpuCores)
	log.Printf("Update interval: %v, smoothing alpha: %.2f", updateInterval, alpha)
	log.Printf("CPU stats log path: %s", cpuLogPath)
	log.Printf("Accept queue stats log path: %s", acceptqLogPath)

	prevStats, err := readCPUStat()
	if err != nil {
		log.Fatalf("failed to read /proc/stat: %v", err)
	}

	runningAvg := make(map[int]float64)
	instUtilByCore := make(map[int]float64)
	mapValueByCore := make(map[int]uint32)

	updateTicker := time.NewTicker(updateInterval)
	defer updateTicker.Stop()

	ticker := time.NewTicker(*logPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Received shutdown signal, exiting")
			return
		case <-updateTicker.C:
		}

		currStats, err := readCPUStat()
		if err != nil {
			log.Printf("error reading /proc/stat: %v", err)
			continue
		}

		for _, coreID := range cpuCores {
			prev, ok1 := prevStats[coreID]
			curr, ok2 := currStats[coreID]
			if !ok1 || !ok2 {
				continue
			}

			instUtil := calculateUtilization(prev, curr)
			instUtilByCore[coreID] = instUtil

			oldAvg := runningAvg[coreID]
			newAvg := alpha*instUtil + (1-alpha)*oldAvg
			runningAvg[coreID] = newAvg

			var key uint32 = uint32(coreID)
			value := uint32(newAvg * 100)
			mapValueByCore[coreID] = value

			if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
				log.Printf("failed to update CPU map for core %d: %v", coreID, err)
			} else {
				log.Printf("CPU %d: inst=%.1f%% avg=%.1f%% (key=%d map=%d)", coreID, instUtil, newAvg, key, value)
			}
		}

		prevStats = currStats

		select {
		case <-ctx.Done():
			log.Println("Received shutdown signal, exiting")
			return
		case <-ticker.C:
			ts := time.Now().Format(time.RFC3339)
			for _, coreID := range cpuCores {
				cpuLogger.Printf("ts=%s cpu=%d inst=%.2f avg=%.2f map=%d", ts, coreID, instUtilByCore[coreID], runningAvg[coreID], mapValueByCore[coreID])
			}

			if acceptqMap == nil {
				if m, err := ebpf.LoadPinnedMap(acceptqMapPath, nil); err == nil {
					acceptqMap = m
					log.Printf("Connected to accept queue map at %s", acceptqMapPath)
				} else {
					acceptqLogger.Printf("ts=%s map_unavailable err=%v", ts, err)
					continue
				}
			}

			for _, coreID := range cpuCores {
				var key uint32 = uint32(coreID)
				var entry acceptqEntry
				if err := acceptqMap.Lookup(&key, &entry); err != nil {
					acceptqLogger.Printf("ts=%s cpu=%d lookup_err=%v", ts, coreID, err)
					continue
				}

				util := 0.0
				if entry.Max > 0 {
					util = float64(entry.Curr) / float64(entry.Max) * 100
				}
				acceptqLogger.Printf("ts=%s cpu=%d curr=%d max=%d util=%.2f", ts, coreID, entry.Curr, entry.Max, util)
			}
		default:
		}
	}
}
