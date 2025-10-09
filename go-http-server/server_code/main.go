package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go reuseportlb eBPF/reuseportlb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go pickfirst eBPF/pickfirst.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go roundrobin eBPF/roundrobin.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go cpuutil eBPF/cpuutil.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go acceptqueue eBPF/acceptqueue.c

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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
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
func getListenConfig(prog *ebpf.Program, installProgram bool) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var opErr error
		// If Control is not nil, it is called after creating the network
		// connection but before binding it to the operating system.
		err := c.Control(func(fd uintptr) {

			// Set SO_REUSEADDR on the socket to allow reuse of local addresses.
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				log.Println("setsockopt(SO_REUSEADDR) failed: %v", err)
				return
			}

			// Set SO_REUSEPORT on the socket for both instances (because eBPF program works on socket with SO_REUSEPORT configured)
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				log.Println("setsockopt(SO_REUSEPORT) failed: %v", err)
				return
			}
			// Set eBPF program to be invoked for socket selection
			if prog != nil && installProgram {
				// SO_ATTACH_REUSEPORT_EBPF program defines how packets are assigned to the sockets in the reuseport group
				// That is, all sockets which have SO_REUSEPORT set and are using the same local address to receive packets.
				// In "function" words, for fd on the SOL_SOCKET lever, set the unix.SO_ATTACH_REUSEPORT_EBPF option to eBPF program file descriptor.
				err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, prog.FD())
				if err != nil {
					log.Println("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %v", err)
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

type slowListener struct {
	net.Listener
	delay time.Duration
}

func (sl *slowListener) Accept() (net.Conn, error) {
	conn, err := sl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	time.Sleep(sl.delay)
	return conn, nil
}

// GetFdFromListener get net.Listener's file descriptor.
func GetFdFromListener(l net.Listener) int {
	v := reflect.Indirect(reflect.ValueOf(l))
	netFD := reflect.Indirect(v.FieldByName("fd"))
	pfd := netFD.FieldByName("pfd")
	fd := int(pfd.FieldByName("Sysfd").Int())
	return fd
}

func ListenerFD(l net.Listener) (int, error) {
	rc, ok := l.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return -1, fmt.Errorf("no SyscallConn")
	}
	var fd int
	var opErr error
	if raw, err := rc.SyscallConn(); err == nil {
		raw.Control(func(p uintptr) { fd = int(p) })
	} else {
		opErr = err
	}
	return fd, opErr
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
	mapOptions := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"}}

	switch policy {

	case "cpuutil":
		var objs cpuutilObjects
		if err := loadCpuutilObjects(&objs, &mapOptions); err != nil {
			return LoadedObjects{}, err
		}
		return LoadedObjects{
			Program: objs.cpuutilPrograms.CpuutilSelector,
			Map:     objs.cpuutilMaps.TcpBalancingTargets,
			Close:   objs.Close,
		}, nil

	case "acceptqueue":
		var objs acceptqueueObjects
		if err := loadAcceptqueueObjects(&objs, &mapOptions); err != nil {
			return LoadedObjects{}, err
		}
		return LoadedObjects{
			Program: objs.acceptqueuePrograms.AcceptqSelector,
			Map:     objs.acceptqueueMaps.TcpBalancingTargets,
			Close:   objs.Close,
		}, nil

	case "round-robin":
		var objs roundrobinObjects
		if err := loadRoundrobinObjects(&objs, &mapOptions); err != nil {
			return LoadedObjects{}, err
		}

		type rrState struct {
			Counter       uint32
			ActiveSockets uint32
		}
		k := uint32(0)
		s := rrState{Counter: 0, ActiveSockets: 4}
		objs.roundrobinMaps.Rr.Update(&k, &s, ebpf.UpdateAny)

		log.Printf("Added round robin state: key=%d, value={Counter: %d, ActiveSockets: %d} (only works with 4 servers)", k, s.Counter, s.ActiveSockets)

		return LoadedObjects{
			Program: objs.roundrobinPrograms.RrSelector,
			Map:     objs.roundrobinMaps.TcpBalancingTargets, // sockarray to be filled per-instance
			Close:   objs.Close,
		}, nil

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
		validPolicies := []string{"default", "pickfirst", "round-robin", "cpuutil", "acceptqueue", "agent"}
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
	if err := os.MkdirAll("/sys/fs/bpf", 0700); err != nil {
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

	// Setup HTTP Server instance
	// We can't directly use http.ListenAndServe because it hides the socket implementation (which is what we are interested in with SetsockoptInt)
	http.HandleFunc("/hello", handleHello)
	http.HandleFunc("/cpu", handleCpu)
	server := http.Server{Addr: "127.0.0.1:8080", Handler: nil}

	installProgram := serverNum == 0 && policy != "default"
	lc := getListenConfig(objs.Program, installProgram)
	ln, err := lc.Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		log.Fatalf("Unable to listen of specified addr: %v", err)
	} else {
		log.Printf("Started listening in 127.0.0.1:8080 successfully! (serverNum = %d, policy = %s)", serverNum, policy)
	}

	fd, err := ListenerFD(ln)
	if err != nil {
		log.Fatalf("get listener fd: %v", err)
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		log.Printf("getsockopt(SO_COOKIE) failed: %v", err)
	} else {
		log.Printf("Listener socket cookie: %d (0x%x)", cookie, cookie)
	}

	if policy != "default" {
		// NOTE: Each process has its own file descriptor table, so don't get confused if the FDs are the same for both processes
		//v := uint64(GetFdFromListener(ln))
		v := uint64(fd)
		var k uint32 = uint32(serverNum)

		log.Printf("Updating with (key = %d , value = %d)", k, v)
		m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tcp_balancing_targets", nil)
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

	err = server.Serve(&slowListener{Listener: ln, delay: 50 * time.Millisecond})
	if err != nil {
		log.Fatalf("Unable to start HTTP server: %v", err)
	}
}
