package main

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type requestRecord struct {
	sent    time.Time
	reqType string
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

	var (
		mu          sync.Mutex
		outstanding = make(map[string]requestRecord)
		latencies   []float64
		latByType   = map[string][]float64{
			"GET":  {},
			"SCAN": {},
		}
		sentCount  int
		recvCount  int
		sentByType = map[string]int{
			"GET":  0,
			"SCAN": 0,
		}
		recvByType = map[string]int{
			"GET":  0,
			"SCAN": 0,
		}
	)

	limiter := rate.NewLimiter(rate.Limit(*targetRate), workers)
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	var sendWG sync.WaitGroup
	var seq uint64
	for i := 0; i < workers; i++ {
		sendWG.Add(1)
		seed := time.Now().UnixNano() + int64(i)
		rng := rand.New(rand.NewSource(seed))
		go func(rng *rand.Rand) {
			defer sendWG.Done()
			buf := make([]byte, 0, 256)
			for {
				if err := limiter.Wait(ctx); err != nil {
					return
				}
				id := int(atomic.AddUint64(&seq, 1) - 1)
				reqType := "GET"
				if rng.Float64() > *getFrac {
					reqType = "SCAN"
				}
				reqID := makeReqID(id)
				payload := buildPayload(rng, buf, reqType, reqID, *keyPrefix, *keySpace, *scanLimit)
				now := time.Now()
				mu.Lock()
				outstanding[reqID] = requestRecord{sent: now, reqType: reqType}
				sentCount++
				sentByType[reqType]++
				mu.Unlock()
				if _, err := conn.Write(payload); err != nil {
					logger.Printf("write error: %v", err)
					mu.Lock()
					delete(outstanding, reqID)
					mu.Unlock()
				}
				buf = payload[:0]
			}
		}(rng)
	}

	quit := make(chan struct{})
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
					return
				}
				logger.Printf("set read deadline: %v", err)
			}
			n, err := conn.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
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
				logger.Printf("read error: %v", err)
				continue
			}
			resp := string(buf[:n])
			fields := strings.Fields(resp)
			if len(fields) < 1 {
				continue
			}
			reqID := ""
			if len(fields) > 1 {
				reqID = fields[1]
			}
			mu.Lock()
			rec, ok := outstanding[reqID]
			if ok {
				lat := time.Since(rec.sent).Seconds() * 1000
				latencies = append(latencies, lat)
				latByType[rec.reqType] = append(latByType[rec.reqType], lat)
				delete(outstanding, reqID)
				recvCount++
				recvByType[rec.reqType]++
			}
			mu.Unlock()
		}
	}()

	sendWG.Wait()

	time.Sleep(2 * time.Second)
	close(quit)

	mu.Lock()
	for _, rec := range outstanding {
		logger.Printf("request %s outstanding for %s", rec.reqType, time.Since(rec.sent))
	}
	mu.Unlock()

	logger.Printf("sent=%d recv=%d", sentCount, recvCount)

	if len(latencies) == 0 {
		fmt.Println("No responses received; unable to compute latency stats")
		return
	}

	sort.Float64s(latencies)
	throughput := float64(recvCount) / duration.Seconds()

	fmt.Printf("Total sent: %d (GET=%d SCAN=%d)\n", sentCount, sentByType["GET"], sentByType["SCAN"])
	fmt.Printf("Total received: %d (GET=%d SCAN=%d)\n", recvCount, recvByType["GET"], recvByType["SCAN"])
	fmt.Printf("Throughput: %.2f req/s\n", throughput)
	reportLatencyStats("Overall", latencies)
	reportLatencyStats("GET", latByType["GET"])
	reportLatencyStats("SCAN", latByType["SCAN"])
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

func makeReqID(seq int) string {
	return "req-" + strconv.FormatInt(int64(seq), 10)
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
