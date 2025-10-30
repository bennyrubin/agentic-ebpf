package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"pebbleserver/internal/server"
)

func main() {
	var (
		dbPath       = flag.String("db", "", "path to Pebble database")
		listen       = flag.String("listen", "127.0.0.1:9000", "UDP listen address")
		workers      = flag.Int("workers", 4, "number of reuseport workers")
		policy       = flag.String("policy", "default", "load-balancing policy: default|round_robin|agent|scan_split")
		maxScan      = flag.Int("max-scan", 1000, "maximum keys returned for SCAN")
		logDir       = flag.String("log-dir", "logs/server", "directory for server logs")
		resultsDir   = flag.String("results-dir", "results", "directory to store experiment artefacts")
		readTimeout  = flag.Duration("read-timeout", 2*time.Second, "per-request read deadline")
		writeTimeout = flag.Duration("write-timeout", 2*time.Second, "per-request write deadline")
	)
	flag.Parse()

	if err := os.MkdirAll(*logDir, 0o755); err != nil {
		log.Fatalf("create log dir: %v", err)
	}
	if err := os.MkdirAll(*resultsDir, 0o755); err != nil {
		log.Fatalf("create results dir: %v", err)
	}

	logFile := filepath.Join(*logDir, "server.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}
	defer f.Close()

	logger := log.New(f, "", log.LstdFlags|log.Lmicroseconds)

	cfg := server.Config{
		DBPath:       *dbPath,
		ListenAddr:   *listen,
		Workers:      *workers,
		Policy:       *policy,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		MaxScanKeys:  *maxScan,
		LogDir:       *logDir,
		ResultsDir:   *resultsDir,
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		log.Fatalf("initialise server: %v", err)
	}
	defer srv.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Printf("server starting addr=%s workers=%d policy=%s", cfg.ListenAddr, cfg.Workers, cfg.Policy)

	if err := srv.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	logger.Println("server stopped")
}
