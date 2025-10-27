package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Server hosts UDP workers backed by Pebble.
type Server struct {
	cfg    Config
	store  *Store
	policy *ebpfPolicy
	logger *log.Logger

	conns []*net.UDPConn
	wg    sync.WaitGroup
}

// New instantiates the server and loads Pebble and optional eBPF policy.
func New(cfg Config, logger *log.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(os.Stdout, "[server] ", log.LstdFlags|log.Lmicroseconds)
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}

	policy, err := loadEBPF(cfg.Policy, cfg.Workers)
	if err != nil {
		store.Close()
		return nil, err
	}

	if policy != nil && policy.program != nil {
		if err := clearTargets(cfg.Workers); err != nil {
			store.Close()
			policy.Close()
			return nil, fmt.Errorf("clear reuseport map: %w", err)
		}
	}

	return &Server{
		cfg:    cfg,
		store:  store,
		policy: policy,
		logger: logger,
	}, nil
}

// Close shuts down sockets and underlying resources.
func (s *Server) Close() error {
	for _, conn := range s.conns {
		conn.Close()
	}
	if s.policy != nil {
		s.policy.Close()
	}
	return s.store.Close()
}

// Run launches workers and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	for i := 0; i < s.cfg.Workers; i++ {
		conn, fd, err := s.openWorker(i)
		if err != nil {
			return fmt.Errorf("open worker %d: %w", i, err)
		}

		if s.policy != nil && s.policy.program != nil {
			if err := updateTargetsMap(uint32(i), fd); err != nil {
				conn.Close()
				return fmt.Errorf("update reuseport map: %w", err)
			}
		}

		s.conns = append(s.conns, conn)
		s.spawnWorker(ctx, i, conn)
	}

	<-ctx.Done()
	s.wg.Wait()
	return nil
}

func (s *Server) openWorker(idx int) (*net.UDPConn, int, error) {
	attachPolicy := s.policy != nil && s.policy.program != nil && idx == 0
	var attachErr error

	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil && attachErr == nil {
				attachErr = fmt.Errorf("SO_REUSEADDR: %w", err)
				return
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil && attachErr == nil {
				attachErr = fmt.Errorf("SO_REUSEPORT: %w", err)
				return
			}
			if attachPolicy && attachErr == nil {
				if err := s.policy.attach(int(fd)); err != nil {
					attachErr = err
				}
			}
		})
	}}

	pc, err := lc.ListenPacket(context.Background(), "udp", s.cfg.ListenAddr)
	if err != nil {
		return nil, -1, err
	}
	if attachErr != nil {
		pc.Close()
		return nil, -1, attachErr
	}

	udpConn := pc.(*net.UDPConn)
	var fd int
	raw, err := udpConn.SyscallConn()
	if err != nil {
		udpConn.Close()
		return nil, -1, err
	}
	if err := raw.Control(func(value uintptr) {
		fd = int(value)
	}); err != nil {
		udpConn.Close()
		return nil, -1, err
	}

	return udpConn, fd, nil
}

func (s *Server) spawnWorker(ctx context.Context, idx int, conn *net.UDPConn) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 16*1024)

		for {
			if err := conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout)); err != nil {
				s.logger.Printf("worker=%d read deadline: %v", idx, err)
			}
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
				s.logger.Printf("worker=%d read error: %v", idx, err)
				continue
			}

			response := s.handleRequest(buf[:n])
			if response == nil {
				continue
			}

			if err := conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)); err != nil {
				s.logger.Printf("worker=%d write deadline: %v", idx, err)
			}
			if _, err := conn.WriteToUDP(response, addr); err != nil {
				s.logger.Printf("worker=%d write error: %v", idx, err)
			}
		}
	}()
}

const maxScanVisibleEntries = 10

func (s *Server) handleRequest(payload []byte) []byte {
	cmd, args, err := parseRequest(payload)
	if err != nil {
		return []byte(fmt.Sprintf("ERR %v", err))
	}

	switch cmd {
	case "GET":
		var reqID string
		if len(args) == 2 {
			reqID = args[1]
			args = args[:1]
		}
		key := []byte(args[0])
		val, ok, err := s.store.Get(key)
		if err != nil {
			return formatResponse("ERR", reqID, []byte(fmt.Sprintf("get %v", err)))
		}
		if !ok {
			return formatResponse("MISS", reqID, []byte(args[0]))
		}
		return formatResponse("VALUE", reqID, val)

	case "SCAN":
		var reqID string
		if len(args) == 3 {
			reqID = args[2]
			args = args[:2]
		}
		limit, err := strconv.Atoi(args[1])
		if err != nil || limit <= 0 {
			return formatResponse("ERR", reqID, []byte("invalid scan limit"))
		}
		if limit > s.cfg.MaxScanKeys {
			limit = s.cfg.MaxScanKeys
		}
		result, err := s.store.Scan([]byte(args[0]), limit)
		if err != nil {
			return formatResponse("ERR", reqID, []byte(fmt.Sprintf("scan %v", err)))
		}
		if len(result) > maxScanVisibleEntries {
			result = result[:maxScanVisibleEntries]
		}
		payload, ok := MarshalScan(result, maxScanResponseBytes)
		if !ok {
			return formatResponse("ERR", reqID, []byte("scan payload too large; reduce limit"))
		}
		return formatResponse("SCAN", reqID, payload)
	default:
		return []byte("ERR unknown command")
	}
}

func formatResponse(prefix, id string, payload []byte) []byte {
	data := []byte(prefix)
	if id != "" {
		data = append(data, ' ')
		data = append(data, id...)
	}
	if len(payload) > 0 {
		data = append(data, ' ')
		data = append(data, payload...)
	}
	return data
}
