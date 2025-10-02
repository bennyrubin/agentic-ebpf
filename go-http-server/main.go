package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reuseportlb eBPF/reuseportlb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go pickfirst eBPF/pickfirst.c

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, fmt.Sprintf("Hello from the %s server!\n", os.Args[1]))
}

func handleCpu(w http.ResponseWriter, r *http.Request) {
	// Simulate CPU intensive work
	const n = 50000
	result := 0
	for i := 0; i < n; i++ {
		result += i % 7
	}
	// Use result to prevent compiler optimization
	io.WriteString(w, fmt.Sprintf("CPU intensive result: %d\n", result))
	io.WriteString(w, fmt.Sprintf("Hello from the %s target!\n", os.Args[1]))
}

// Inspired by src/net/dial.go
func getListenConfig(prog *ebpf.Program, serverNum int, installProgram bool) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		// If Control is not nil, it is called after creating the network
		// connection but before binding it to the operating system.
		err := c.Control(func(fd uintptr) {
			// Set SO_REUSEPORT on the socket for both instances (because eBPF program works on socket with SO_REUSEPORT configured)
			// This sets the SO_REUSEPORT option on the socket, which allows multiple sockets to bind to the same port.
			// In "function" words, for fd on the SOL_SOCKET level, set the SO_REUSEPORT option to 1 (a.k.a. true/on).
			opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			// Set eBPF program to be invoked for socket selection
			if prog != nil && serverNum == 0 && installProgram {
				// SO_ATTACH_REUSEPORT_EBPF program defines how packets are assigned to the sockets in the reuseport group
				// That is, all sockets which have SO_REUSEPORT set and are using the same local address to receive packets.
				// In "function" words, for fd on the SOL_SOCKET lever, set the unix.SO_ATTACH_REUSEPORT_EBPF option to eBPF program file descriptor.
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD())
				if err != nil {
					opErr = fmt.Errorf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %w", err)
				} else {
					log.Println("eBPF program attached to the SO_REUSEPORT socket group!")
				}
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}}
	return lc
}

// GetFdFromListener get net.Listener's file descriptor.
func GetFdFromListener(l net.Listener) int {
	v := reflect.Indirect(reflect.ValueOf(l))
	netFD := reflect.Indirect(v.FieldByName("fd"))
	pfd := netFD.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

// ensureBpffsMounted mounts bpffs at the given path if it's not already mounted.
func ensureBpffsMounted(path string) error {
	// Ensure the mount point directory exists
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create bpffs mountpoint: %w", err)
	}
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err == nil {
		// 0xCAFE4A11 is BPF_FS_MAGIC from linux/magic.h
		const bpfFsMagic = 0xCAFE4A11
		if int64(statfs.Type) == int64(bpfFsMagic) {
			return nil // already mounted as bpffs
		}
	}
	// Not mounted as bpffs; try to mount
	if err := unix.Mount("bpffs", path, "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs at %s: %w", path, err)
	}
	return nil
}

type LoadedObjects struct {
	Program *ebpf.Program
	Map     *ebpf.Map
	Close   func() error
}

func loadPolicy(policy string) (LoadedObjects, error) {
	mapOptions := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/tc/globals"}}

	switch policy {

	case "round-robin":
		return LoadedObjects{}, fmt.Errorf("agent policy is not implemented")

	case "pickfirst":
		var objs pickfirstObjects
		if err := loadPickfirstObjects(&objs, &mapOptions); err != nil {
			return LoadedObjects{}, err
		}
		return LoadedObjects{
			Program: objs.pickfirstPrograms.Pickfirst,
			Map:     objs.pickfirstMaps.TcpBalancingTargets,
			Close:   objs.Close,
		}, nil

	case "agent":
		// Placeholder for agent policy, implement as needed
		return LoadedObjects{}, fmt.Errorf("agent policy is not implemented")

	default:
		validPolicies := []string{"default", "random", "round-robin", "agent"}
		log.Fatalf("Invalid policy: %q. Valid policies are: %v", policy, validPolicies)
	}
	return LoadedObjects{}, nil
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <server number> <policy>", os.Args[0])
	}
	serverNum, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Server number should be a number: %v", err)
	}
	policy := os.Args[2]

	// Ensure bpffs is mounted and pin directory exists
	if err := ensureBpffsMounted("/sys/fs/bpf"); err != nil {
		log.Fatalf("bpffs mount/setup failed: %v", err)
	}
	if err := os.MkdirAll("/sys/fs/bpf/tc/globals", 0700); err != nil {
		log.Fatalf("create pin directory failed: %v", err)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Print("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	// Map needs to be pinned, such that in case the primary target is shutdown, the standby target can still see the map
	var objs LoadedObjects
	if serverNum == 0 && policy != "default" {
		var err error
		log.Printf("Loading eBPF policy: %s", policy)
		objs, err = loadPolicy(policy)
		if err != nil {
			log.Fatalf("Loading eBPF objects failed: %v", err)
		}
	}

	defer objs.Close() // This only unloads the eBPF program (if it is not attached to kernel) and map, but doesn't remove the pin

	// Check if other instances are already running on the same port - because we are testing SO_REUSEPORT
	fs, _ := procfs.NewDefaultFS()
	netTCP, _ := fs.NetTCP()
	otherInstancesRunning := false
	for _, i := range netTCP {
		if i.LocalPort == 8080 {
			otherInstancesRunning = true
			break
		}
	}

	// Setup HTTP Server instance
	// We can't directly use http.ListenAndServe because it hides the socket implementation (which is what we are interested in with SetsockoptInt)
	http.HandleFunc("/hello", handleHello)
	http.HandleFunc("/cpu", handleCpu)
	server := http.Server{Addr: "127.0.0.1:8080", Handler: nil}

	installProgram := !otherInstancesRunning && policy != "default"
	lc := getListenConfig(objs.Program, serverNum, installProgram)
	ln, err := lc.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		log.Fatalf("Unable to listen of specified addr: %v", err)
	} else {
		log.Printf("Started listening in 127.0.0.1:8080 successfully! (serverNum = %d, policy = %s)", serverNum, policy)
	}

	if policy != "default" {
		// NOTE: Each process has its own file descriptor table, so don't get confused if the FDs are the same for both processes
		v := uint64(GetFdFromListener(ln))
		var k uint32 = uint32(serverNum)

		log.Printf("Updating with (key = %d , value = %d)", k, v)
		m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/tcp_balancing_targets", nil)
		if err != nil {
			log.Fatalf("Unable to load map: %v", err)
		}

		err = m.Update(&k, &v, ebpf.UpdateAny)
		if err != nil {
			log.Fatalf("Unable to update the map: %v", err)
		} else {
			log.Printf("Map update succeeded")
		}
	}

	err = server.Serve(ln)
	if err != nil {
		log.Fatalf("Unable to start HTTP server: %v", err)
	}
}
