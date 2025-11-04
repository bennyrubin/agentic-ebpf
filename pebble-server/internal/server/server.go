package server

import (
	"context"
	"errors"
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

	conns   []*net.UDPConn
	stats   []workerStats
	wg      sync.WaitGroup
	statsWG sync.WaitGroup
}

type workerStats struct {
	mu sync.Mutex

	getCount   uint64
	getHits    uint64
	getMisses  uint64
	getErrors  uint64
	getLatency time.Duration

	scanCount   uint64
	scanEntries uint64
	scanErrors  uint64
	scanLatency time.Duration
}

type workerStatsSnapshot struct {
	getCount   uint64
	getHits    uint64
	getMisses  uint64
	getErrors  uint64
	getLatency time.Duration

	scanCount   uint64
	scanEntries uint64
	scanErrors  uint64
	scanLatency time.Duration
}

func (ws *workerStats) reset() {
	ws.mu.Lock()
	ws.getCount = 0
	ws.getHits = 0
	ws.getMisses = 0
	ws.getErrors = 0
	ws.getLatency = 0
	ws.scanCount = 0
	ws.scanEntries = 0
	ws.scanErrors = 0
	ws.scanLatency = 0
	ws.mu.Unlock()
}

func (ws *workerStats) recordGet(duration time.Duration, hit bool, miss bool, err bool) {
	ws.mu.Lock()
	ws.getCount++
	ws.getLatency += duration
	if hit {
		ws.getHits++
	}
	if miss {
		ws.getMisses++
	}
	if err {
		ws.getErrors++
	}
	ws.mu.Unlock()
}

func (ws *workerStats) recordScan(duration time.Duration, entries int, err bool) {
	ws.mu.Lock()
	ws.scanCount++
	ws.scanLatency += duration
	if err {
		ws.scanErrors++
	} else {
		ws.scanEntries += uint64(entries)
	}
	ws.mu.Unlock()
}

func (ws *workerStats) snapshotAndReset() workerStatsSnapshot {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	snap := workerStatsSnapshot{
		getCount:   ws.getCount,
		getHits:    ws.getHits,
		getMisses:  ws.getMisses,
		getErrors:  ws.getErrors,
		getLatency: ws.getLatency,

		scanCount:   ws.scanCount,
		scanEntries: ws.scanEntries,
		scanErrors:  ws.scanErrors,
		scanLatency: ws.scanLatency,
	}

	ws.getCount = 0
	ws.getHits = 0
	ws.getMisses = 0
	ws.getErrors = 0
	ws.getLatency = 0
	ws.scanCount = 0
	ws.scanEntries = 0
	ws.scanErrors = 0
	ws.scanLatency = 0

	return snap
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
		stats:  make([]workerStats, cfg.Workers),
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
	if len(s.stats) != s.cfg.Workers {
		s.stats = make([]workerStats, s.cfg.Workers)
	}
	for i := range s.stats {
		s.stats[i].reset()
	}
	logCtx, logCancel := context.WithCancel(ctx)
	defer func() {
		logCancel()
		s.statsWG.Wait()
	}()
	s.startStatsLogger(logCtx)

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

		iters, err := s.store.NewWorkerIterators()
		if err != nil {
			conn.Close()
			return fmt.Errorf("worker %d iterator: %w", i, err)
		}

		s.conns = append(s.conns, conn)
		s.spawnWorker(ctx, i, conn, iters)
	}

	<-ctx.Done()
	for _, conn := range s.conns {
		conn.Close()
	}
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

func (s *Server) spawnWorker(ctx context.Context, idx int, conn *net.UDPConn, iters *WorkerIterators) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if iters != nil {
			defer iters.Close()
		}
		buf := make([]byte, 16*1024)

		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Printf("worker=%d read error: %v", idx, err)
				continue
			}

			response := s.handleRequest(idx, buf[:n], iters)
			if response == nil {
				continue
			}

			if _, err := conn.WriteToUDP(response, addr); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Printf("worker=%d write error: %v", idx, err)
			}
		}
	}()
}

const maxScanVisibleEntries = 10

func (s *Server) handleRequest(idx int, payload []byte, iters *WorkerIterators) []byte {
	cmd, args, err := parseRequest(payload)
	if err != nil {
		return []byte(fmt.Sprintf("ERR %v", err))
	}

	var stats *workerStats
	if idx >= 0 && idx < len(s.stats) {
		stats = &s.stats[idx]
	}

	switch cmd {
	case "GET":
		start := time.Now()
		var reqID string
		if len(args) == 2 {
			reqID = args[1]
			args = args[:1]
		}
		key := []byte(args[0])
		var (
			val    []byte
			ok     bool
			getErr error
		)
		if iters != nil {
			val, ok, getErr = iters.Get(key)
		} else {
			val, ok, getErr = s.store.Get(key)
		}
		if getErr != nil {
			if stats != nil {
				stats.recordGet(time.Since(start), false, false, true)
			}
			return formatResponse("ERR", reqID, []byte(fmt.Sprintf("get %v", getErr)))
		}
		if !ok {
			if stats != nil {
				stats.recordGet(time.Since(start), false, true, false)
			}
			return formatResponse("MISS", reqID, []byte(args[0]))
		}
		if stats != nil {
			stats.recordGet(time.Since(start), true, false, false)
		}
		return formatResponse("VALUE", reqID, val)

	case "SCAN":
		start := time.Now()
		var reqID string
		if len(args) == 3 {
			reqID = args[2]
			args = args[:2]
		}
		limit, err := strconv.Atoi(args[1])
		if err != nil || limit <= 0 {
			if stats != nil {
				stats.recordScan(time.Since(start), 0, true)
			}
			return formatResponse("ERR", reqID, []byte("invalid scan limit"))
		}
		if limit > s.cfg.MaxScanKeys {
			limit = s.cfg.MaxScanKeys
		}
		if iters == nil || iters.Scan == nil {
			if stats != nil {
				stats.recordScan(time.Since(start), 0, true)
			}
			return formatResponse("ERR", reqID, []byte("scan iterator unavailable"))
		}
		result, err := iters.Scan.Scan([]byte(args[0]), limit)
		if err != nil {
			if stats != nil {
				stats.recordScan(time.Since(start), 0, true)
			}
			return formatResponse("ERR", reqID, []byte(fmt.Sprintf("scan %v", err)))
		}
		if len(result) > maxScanVisibleEntries {
			result = result[:maxScanVisibleEntries]
		}
		payload, ok := MarshalScan(result, maxScanResponseBytes)
		if !ok {
			if stats != nil {
				stats.recordScan(time.Since(start), 0, true)
			}
			return formatResponse("ERR", reqID, []byte("scan payload too large; reduce limit"))
		}
		if stats != nil {
			stats.recordScan(time.Since(start), len(result), false)
		}
		return formatResponse("SCAN", reqID, payload)
	default:
		return []byte("ERR unknown command")
	}
}

func (s *Server) startStatsLogger(ctx context.Context) {
	if s.logger == nil || len(s.stats) == 0 {
		return
	}
	s.statsWG.Add(1)
	go func() {
		defer s.statsWG.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var total workerStatsSnapshot
				for i := range s.stats {
					snap := s.stats[i].snapshotAndReset()
					if snap.getCount > 0 || snap.scanCount > 0 {
						var workerAvgGet time.Duration
						if snap.getCount > 0 {
							workerAvgGet = time.Duration(int64(snap.getLatency) / int64(snap.getCount))
						}
						var workerAvgScan time.Duration
						if snap.scanCount > 0 {
							workerAvgScan = time.Duration(int64(snap.scanLatency) / int64(snap.scanCount))
						}
						s.logger.Printf(
							"[perf] worker=%d gets=%d hits=%d misses=%d errors=%d avg_get=%s scans=%d entries=%d scan_errors=%d avg_scan=%s",
							i,
							snap.getCount,
							snap.getHits,
							snap.getMisses,
							snap.getErrors,
							workerAvgGet,
							snap.scanCount,
							snap.scanEntries,
							snap.scanErrors,
							workerAvgScan,
						)
					}
					total.getCount += snap.getCount
					total.getHits += snap.getHits
					total.getMisses += snap.getMisses
					total.getErrors += snap.getErrors
					total.getLatency += snap.getLatency
					total.scanCount += snap.scanCount
					total.scanEntries += snap.scanEntries
					total.scanErrors += snap.scanErrors
					total.scanLatency += snap.scanLatency
				}
				if total.getCount == 0 && total.scanCount == 0 {
					continue
				}
				var avgGet time.Duration
				if total.getCount > 0 {
					avgGet = time.Duration(int64(total.getLatency) / int64(total.getCount))
				}
				var avgScan time.Duration
				if total.scanCount > 0 {
					avgScan = time.Duration(int64(total.scanLatency) / int64(total.scanCount))
				}
				s.logger.Printf(
					"[perf] interval=1s gets=%d hits=%d misses=%d errors=%d avg_get=%s scans=%d entries=%d scan_errors=%d avg_scan=%s",
					total.getCount,
					total.getHits,
					total.getMisses,
					total.getErrors,
					avgGet,
					total.scanCount,
					total.scanEntries,
					total.scanErrors,
					avgScan,
				)
			}
		}
	}()
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
