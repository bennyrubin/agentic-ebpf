# Pebble Server Playground

This repository hosts a small UDP key/value service backed by the
[`pebble`](https://github.com/cockroachdb/pebble) storage engine. It is designed
as a sandbox for experimenting with reuseport-based load-balancing, eBPF
policies, and workload measurements that separately track `GET` and `SCAN`
latencies.

The Go codebase is intentionally compact: a single server binary speaks a tiny
text protocol, a dataset loader initialises a Pebble database, and a workload
client fires open-loop requests while collecting latency stats.

---

## Directory Layout

```
pebble-server/
├── cmd/                  # Go entrypoints
│   ├── pebble_server/    # UDP server binary (`-db`, `-policy`, `-workers`, …)
│   ├── setupdb/          # Dataset loader (populates Pebble with random KV pairs)
│   └── workload_client/  # Open-loop client that records GET/SCAN latencies
├── ebpf/                 # C programs compiled to CO-RE eBPF bytecode
├── internal/
│   ├── ebpfutil/         # Auto-generated go-ebpf bindings + pinned-map helpers
│   └── server/           # Core server code (config, request handler, Pebble store)
├── scripts/              # Helper scripts invoked by run.sh
│   ├── build_ebpf.sh     # Rebuilds eBPF assets into internal/ebpfutil
│   ├── launch_server.sh  # Builds and launches the UDP server in the background
│   └── setup_db.sh       # Thin wrapper around cmd/setupdb
├── workload/             # Convenience wrapper to drive the client in isolation
├── run.sh                # Orchestrates “build eBPF → load data → run workload”
├── run/                  # PID file for the background server
├── logs/                 # Default server logs (one subdir per run)
├── results/              # Experiment artefacts (`experiment.json`, summary, logs)
├── pebble.data/          # Default Pebble data directory (created by setupdb)
└── go.mod / go.sum       # Go module definition (module name: `pebbleserver`)
```

---

## Components

### Server (`cmd/pebble_server`)

- Listens on UDP (default `127.0.0.1:9000`).
- Supports two commands:
  - `GET <key> [request-id]`
  - `SCAN <start_key> <limit> [request-id]`
- Responses echo the optional request id, making it easy to correlate latency
  samples on the client side.
- Storage is provided by `internal/server/store.go`, a thin wrapper around
  Pebble that exposes `Get` and forward iteration for scans.
- Request parsing lives in `internal/server/handler.go`; the main worker loop is
  in `internal/server/server.go`.
- Optional eBPF policies (default, `round_robin`, `agent`) are loaded from the
  assets in `internal/ebpfutil`. The round-robin policy keeps a pinned array map
  at `/sys/fs/bpf/pebble_rr_state`; both policies reuse
  `/sys/fs/bpf/pebble_udp_targets`.

Command-line flags (see `cmd/pebble_server/main.go`):

```
-db              path to the Pebble database (required)
-listen          UDP listen address (default 127.0.0.1:9000)
-workers         reuseport workers (default 4)
-policy          default | round_robin | agent
-max-scan        max keys returned per SCAN (default 100)
-log-dir         destination for server logs (default logs/server)
-results-dir     location for experiment metadata (default results)
-read-timeout    per-request read deadline (default 2s)
-write-timeout   per-request write deadline (default 2s)
```

### Dataset Loader (`cmd/setupdb`)

Populates a Pebble database with random hex values.

Useful flags:

```
-db           destination directory (default ./pebble.data)
-keys         number of KV pairs (default 10,000)
-value-bytes  value size in bytes (default 256)
-key-prefix   string prefix for generated keys (default "key")
-destroy      wipe the destination directory before loading
```

### Workload Client (`cmd/workload_client`)

Generates a constant-rate stream of UDP requests and records latencies. At the
end of each run it prints:

- Throughput (responses / test duration)
- Overall latency p50/p90/p99/average
- Separate GET and SCAN latency percentiles so you can spot divergent tails

Key flags:

```
-server       UDP endpoint (default 127.0.0.1:9000)
-duration     run length (default 30s)
-rate         target send rate in requests/sec (default 1000)
-get-frac     fraction of GET requests (default 0.8)
-scan-limit   number of keys per SCAN (default 500)
-key-prefix   matches the dataset loader prefix (default "key")
-key-space    upper bound on numeric suffix (default 100000)
-log          client log output (default logs/client.log)
-send-workers concurrent send goroutines (default runtime.NumCPU())
```

> Tip: with the higher default `-scan-limit`, scans intentionally walk a much
> larger swath of the keyspace so their latency distribution stands out from
> point GETs. Dial the value up or down depending on how much contrast you need.

---

## Orchestrated Workflow (`run.sh`)

`run.sh` wires everything together:

1. `scripts/build_ebpf.sh` – compiles the C programs in `ebpf/` into CO-RE
   objects and regenerates `internal/ebpfutil/*`.
2. `scripts/setup_db.sh` – builds and runs `cmd/setupdb` to populate
   `<db-path>` (defaults to `pebble.data` in the repo root). The script caches
   the last load parameters; unless you pass `--destroy-db` or change
   `--keys/--value-bytes/--key-prefix`, subsequent runs reuse the existing
   dataset for quicker iterations.
3. `scripts/launch_server.sh` – builds `cmd/pebble_server`, starts it in the
   background, and records its PID under `run/server.pid`.
4. `cmd/workload_client` – runs with the provided rate/duration arguments and
   writes a concise summary to `results/<run-id>/workload_summary.txt`.
5. Shuts down the background server and reports where artefacts were stored.

Typical usage:

```bash
./run.sh \
  --threads 4 \
  --policy round_robin \
  --rate 500 \
  --duration 15 \
  --destroy-db
```

Every invocation creates a fresh `results/run-<timestamp>/` directory containing:

- `experiment.json` – the parameters used for the run.
- `logs/` – the server log for that execution.
- `workload_summary.txt` – human-readable latency/throughput snapshot.

---

## Manual Invocation

If you prefer to run individual pieces yourself:

```bash
# Build binaries (outputs to ./bin)
go build -o bin/pebble_server ./cmd/pebble_server
go build -o bin/setupdb ./cmd/setupdb
go build -o bin/workload_client ./cmd/workload_client

# Rebuild eBPF maps/programs (requires clang/llvm)
./scripts/build_ebpf.sh

# Prepare a Pebble dataset
./bin/setupdb -db ./pebble.data -keys 50000 -destroy

# Launch the server
./bin/pebble_server \
    -db ./pebble.data \
    -workers 4 \
    -policy default

# In another terminal, run the workload
./bin/workload_client \
    -server 127.0.0.1:9000 \
    -duration 10s \
    -rate 250 \
    -get-frac 0.7
```

---

## eBPF Requirements

The eBPF programs are built with `clang` (CO-RE) and require root privileges to
pin maps under `/sys/fs/bpf`. Ensure:

- Linux kernel with BPF support (`bpftool` is handy for inspection).
- `clang`/`llvm-strip`/`llc` available in `PATH`.
- Sufficient RLIMIT_MEMLOCK (handled by `internal/server/ebpf.go`).

Pinned maps created:

- `/sys/fs/bpf/pebble_udp_targets` – reuseport socket array shared by policies.
- `/sys/fs/bpf/pebble_rr_state` – (round robin only) a single entry storing
  worker count and counter.

Use `bpftool map show` to inspect them after launches.

---

## Generated Artefacts & Clean-up

- `pebble.data/` contains the on-disk Pebble database. Use `setupdb -destroy`
  or remove the directory manually to start from scratch.
- `logs/` and `results/` accumulate data per run. Remove subdirectories once you
  have extracted the information you need.
- `run/server.pid` tracks the background server spawned by `launch_server.sh`.
  It is cleared automatically by `run.sh`, but double-check before rerunning if
  you abort early.

---

## Prerequisites

- Go 1.22 or newer.
- clang/llvm toolchain (for eBPF builds).
- Linux with `/sys/fs/bpf` mounted (e.g. `sudo mount bpffs /sys/fs/bpf -t bpf`).

Optional tools:

- `bpftool` for debugging pinned maps/programs.
- `perf` / `bcc` utilities if you wish to extend observability.

---

## Extending the Playground

Ideas for further exploration:

- Experiment with new eBPF policies: drop additional `.c` files in `ebpf/`,
  extend `internal/server/ebpf.go` to load them, and supplement `build_ebpf.sh`.
- Modify `cmd/workload_client` to issue `SET`/`DELETE` commands and track write
  latency profiles.
- Evolve the request protocol (add JSON, experiment with framing, etc.) and
  update `internal/server/handler.go` accordingly.
- Integrate metrics exporters or tracing to observe refill/scan behaviour.

Pull requests that keep the focus on Pebble-backed reuseport experiments are
especially welcome.

---

Happy hacking! If you run into issues with the eBPF build or Pebble storage
layer, the `scripts/` folder is a useful starting point for debugging the
invocation chain. Feel free to open an issue with logs or `bpftool` output. ***
