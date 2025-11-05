package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	idTimeHexLen = 16
	idSeqHexLen  = 8
	idTotalLen   = idTimeHexLen + idSeqHexLen + 1

	reqTypeGet  = byte('G')
	reqTypeScan = byte('S')
)

var hexDigits = [...]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

type latencyRecord struct {
	latency float64
	isGet   bool
}

type latencyAggregator struct {
	overall []float64
	get     []float64
	scan    []float64
}

func newLatencyAggregator() *latencyAggregator {
	return &latencyAggregator{
		overall: make([]float64, 0, 2048),
		get:     make([]float64, 0, 1024),
		scan:    make([]float64, 0, 1024),
	}
}

func (a *latencyAggregator) record(rec latencyRecord) {
	a.overall = append(a.overall, rec.latency)
	if rec.isGet {
		a.get = append(a.get, rec.latency)
	} else {
		a.scan = append(a.scan, rec.latency)
	}
}

func (a *latencyAggregator) totalRecv() int {
	return len(a.overall)
}

func main() {
	var (
		serverAddr  = flag.String("server", "127.0.0.1:9000", "UDP server address")
		duration    = flag.Duration("duration", 30*time.Second, "duration of the workload")
		targetRate  = flag.Float64("rate", 1000, "target send rate (requests per second)")
		getFrac     = flag.Float64("get-frac", 0.8, "fraction of GET requests; remainder are SCAN")
		scanLimit   = flag.Int("scan-limit", 500, "number of keys per SCAN request")
		keyPrefix   = flag.String("key-prefix", "key", "prefix used when generating keys")
		keySpace    = flag.Int("key-space", 100000, "upper bound (exclusive) for generated key numbers")
		logPath     = flag.String("log", "logs/client.log", "path to log file")
		sendWorkers = flag.Int("send-workers", 1, "number of concurrent send workers")
	)
	flag.Parse()

	workers := *sendWorkers
	if workers <= 0 {
		workers = 1
	}

	if *targetRate <= 0 {
		log.Fatalf("rate must be positive")
	}
	if *keySpace <= 0 {
		log.Fatalf("key-space must be positive")
	}
	if *getFrac < 0 || *getFrac > 1 {
		log.Fatalf("get-frac must be between 0 and 1")
	}

	if err := os.MkdirAll(filepathDir(*logPath), 0o755); err != nil {
		log.Fatalf("create log dir: %v", err)
	}
	lf, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}
	defer lf.Close()
	logger := log.New(lf, "[client] ", log.LstdFlags|log.Lmicroseconds)

	udpAddr, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil {
		logger.Fatalf("resolve server: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	logger.Printf("starting workload server=%s duration=%s rate=%.2f get_frac=%.2f", *serverAddr, duration.String(), *targetRate, *getFrac)

	rand.Seed(time.Now().UnixNano())

	limiter := rate.NewLimiter(rate.Limit(*targetRate), workers)
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	var (
		sendWG    sync.WaitGroup
		recvWG    sync.WaitGroup
		aggWG     sync.WaitGroup
		monitorWG sync.WaitGroup
	)

	latencyCh := make(chan latencyRecord, 8192)
	aggregator := newLatencyAggregator()

	var (
		sentTotal int64
		sentGet   int64
		sentScan  int64
		recvTotal int64
	)

	aggWG.Add(1)
	go func() {
		defer aggWG.Done()
		for rec := range latencyCh {
			aggregator.record(rec)
			atomic.AddInt64(&recvTotal, 1)
		}
	}()

	monitorDone := make(chan struct{})
	monitorWG.Add(1)
	go func() {
		defer monitorWG.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sent := atomic.LoadInt64(&sentTotal)
				recv := atomic.LoadInt64(&recvTotal)
				outstanding := sent - recv
				if outstanding > 0 {
					logger.Printf("outstanding=%d sent=%d recv=%d", outstanding, sent, recv)
				}
			case <-monitorDone:
				return
			}
		}
	}()

	quit := make(chan struct{})

	var seq uint64
	for i := 0; i < workers; i++ {
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			logger.Fatalf("dial udp worker=%d: %v", i, err)
		}
		defer conn.Close()

		seed := time.Now().UnixNano() + int64(i)
		rng := rand.New(rand.NewSource(seed))

		workerID := i

		sendWG.Add(1)
		go func(workerID int, conn *net.UDPConn, rng *rand.Rand) {
			defer sendWG.Done()
			buf := make([]byte, 0, 256)
			for {
				if err := limiter.Wait(ctx); err != nil {
					return
				}
				currSeq := atomic.AddUint64(&seq, 1) - 1
				isGet := true
				reqType := "GET"
				if rng.Float64() > *getFrac {
					reqType = "SCAN"
					isGet = false
				}
				// Capture timestamp, build payload, and send immediately
				reqID := makeReqID(time.Now().UnixNano(), currSeq, isGet)
				payload := buildPayload(rng, buf, reqType, reqID, *keyPrefix, *keySpace, *scanLimit)
				if _, err := conn.Write(payload); err != nil {
					logger.Printf("write error (worker=%d): %v", workerID, err)
					buf = payload[:0]
					continue
				}
				atomic.AddInt64(&sentTotal, 1)
				if isGet {
					atomic.AddInt64(&sentGet, 1)
				} else {
					atomic.AddInt64(&sentScan, 1)
				}
				buf = payload[:0]
			}
		}(workerID, conn, rng)

		recvWG.Add(1)
		go func(workerID int, conn *net.UDPConn) {
			defer recvWG.Done()
			buf := make([]byte, 64*1024)
			// Set read deadline once to avoid blocking forever
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			for {
				n, err := conn.Read(buf)
				// Capture receive timestamp immediately
				recvNano := time.Now().UnixNano()
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						// Reset deadline on timeout
						conn.SetReadDeadline(time.Now().Add(5 * time.Second))
						select {
						case <-quit:
							return
						default:
							continue
						}
					}
					if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
						return
					}
					logger.Printf("read error (worker=%d): %v", workerID, err)
					continue
				}

				fields := bytes.Fields(buf[:n])
				if len(fields) < 2 {
					continue
				}
				sendNano, isGet, ok := parseReqID(fields[1])
				if !ok {
					continue
				}
				latencyMs := float64(recvNano-sendNano) / 1e6
				select {
				case latencyCh <- latencyRecord{latency: latencyMs, isGet: isGet}:
				case <-quit:
					return
				}
			}
		}(workerID, conn)
	}

	sendWG.Wait()

	time.Sleep(2 * time.Second)
	close(quit)
	recvWG.Wait()

	close(latencyCh)
	aggWG.Wait()

	close(monitorDone)
	monitorWG.Wait()

	totalSent := atomic.LoadInt64(&sentTotal)
	totalRecv := aggregator.totalRecv()
	totalGet := int(atomic.LoadInt64(&sentGet))
	totalScan := int(atomic.LoadInt64(&sentScan))

	if totalSent > 0 && totalRecv < int(totalSent) {
		logger.Printf("warning: %d responses missing (sent=%d recv=%d)", int(totalSent)-totalRecv, totalSent, totalRecv)
	}

	logger.Printf("sent=%d recv=%d", totalSent, totalRecv)

	if totalRecv == 0 {
		fmt.Println("No responses received; unable to compute latency stats")
		return
	}

	durationSeconds := duration.Seconds()
	if durationSeconds <= 0 {
		durationSeconds = 1
	}
	throughput := float64(totalRecv) / durationSeconds

	fmt.Printf("Total sent: %d (GET=%d SCAN=%d)\n", totalSent, totalGet, totalScan)
	fmt.Printf("Total received: %d (GET=%d SCAN=%d)\n", totalRecv, len(aggregator.get), len(aggregator.scan))
	fmt.Printf("Throughput: %.2f req/s\n", throughput)
	reportLatencyStats("Overall", aggregator.overall)
	reportLatencyStats("GET", aggregator.get)
	reportLatencyStats("SCAN", aggregator.scan)
}

func makeReqID(sendNano int64, seq uint64, isGet bool) string {
	var buf [idTotalLen]byte
	writeHex(buf[:idTimeHexLen], uint64(sendNano))
	writeHex(buf[idTimeHexLen:idTimeHexLen+idSeqHexLen], seq)
	if isGet {
		buf[idTotalLen-1] = reqTypeGet
	} else {
		buf[idTotalLen-1] = reqTypeScan
	}
	return string(buf[:])
}

func parseReqID(id []byte) (int64, bool, bool) {
	if len(id) < idTotalLen {
		return 0, false, false
	}
	sendNano, ok := parseHex(id[:idTimeHexLen])
	if !ok {
		return 0, false, false
	}
	typeByte := id[len(id)-1]
	switch typeByte {
	case reqTypeGet:
		return int64(sendNano), true, true
	case reqTypeScan:
		return int64(sendNano), false, true
	default:
		return 0, false, false
	}
}

func writeHex(dst []byte, value uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = hexDigits[value&0xF]
		value >>= 4
	}
}

func parseHex(src []byte) (uint64, bool) {
	var v uint64
	for _, b := range src {
		switch {
		case '0' <= b && b <= '9':
			v = (v << 4) | uint64(b-'0')
		case 'a' <= b && b <= 'f':
			v = (v << 4) | uint64(b-'a'+10)
		case 'A' <= b && b <= 'F':
			v = (v << 4) | uint64(b-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

func buildPayload(rng *rand.Rand, buf []byte, reqType, reqID, prefix string, keySpace, scanLimit int) []byte {
	buf = buf[:0]
	buf = append(buf, reqType...)
	buf = append(buf, ' ')
	keyIdx := rng.Intn(keySpace)
	buf = appendKey(buf, prefix, keyIdx)
	if reqType == "SCAN" {
		buf = append(buf, ' ')
		buf = strconv.AppendInt(buf, int64(scanLimit), 10)
	}
	buf = append(buf, ' ')
	buf = append(buf, reqID...)
	return buf
}

func appendKey(buf []byte, prefix string, keyIdx int) []byte {
	buf = append(buf, prefix...)
	if keyIdx < 100000000 {
		start := len(buf)
		buf = append(buf, '0', '0', '0', '0', '0', '0', '0', '0')
		for i := 7; i >= 0; i-- {
			buf[start+i] = byte('0' + keyIdx%10)
			keyIdx /= 10
		}
		return buf
	}
	return strconv.AppendInt(buf, int64(keyIdx), 10)
}

func percentile(data []float64, p float64) float64 {
	if len(data) == 0 {
		return math.NaN()
	}
	if p <= 0 {
		return data[0]
	}
	if p >= 100 {
		return data[len(data)-1]
	}
	rank := (p / 100) * float64(len(data)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		return data[lower]
	}
	weight := rank - float64(lower)
	return data[lower]*(1-weight) + data[upper]*weight
}

func average(data []float64) float64 {
	if len(data) == 0 {
		return math.NaN()
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func reportLatencyStats(label string, data []float64) {
	if len(data) == 0 {
		fmt.Printf("%s latency: no data\n", label)
		return
	}
	sorted := append([]float64(nil), data...)
	sort.Float64s(sorted)
	fmt.Printf("%s latency p50: %.3f ms\n", label, percentile(sorted, 50))
	fmt.Printf("%s latency p90: %.3f ms\n", label, percentile(sorted, 90))
	fmt.Printf("%s latency p99: %.3f ms\n", label, percentile(sorted, 99))
	fmt.Printf("%s latency avg: %.3f ms\n", label, average(sorted))
}

func filepathDir(p string) string {
	dir := filepath.Dir(p)
	if dir == "" || dir == "." {
		return "."
	}
	return dir
}
