# Pebble Server Playground

This repository hosts a compact UDP service that understands a tiny text
protocol and exposes two operations:

- `GET <key> [request-id]`
- `SCAN <start_key> <limit> [request-id]`

The original version of this project backed those calls with a Pebble key/value
store. The current incarnation simulates storage behaviour by sleeping for a
configurable amount of time on each request (default: 10µs for GET, 2ms for
SCAN) while keeping the rest of the infrastructure – workload generator,
eBPF-based load balancers, Docker helpers, and experiment orchestration – intact.

---

## Directory Layout

```
pebble-server/
├── cmd/
│   ├── pebble_server/    # UDP server entrypoint
│   └── workload_client/  # Open-loop client that records GET/SCAN latencies
├── docker/               # Container image and helper entrypoint
├── ebpf/                 # CO-RE programs compiled into internal/ebpfutil/*
├── internal/
│   ├── ebpfutil/         # Auto-generated go-ebpf bindings + pinned-map helpers
│   └── server/           # Config, request handler, worker loop, stats
├── run.sh                # Orchestrates “build eBPF → launch server → run workload”
├── scripts/              # Helper scripts invoked by run.sh/docker entrypoints
│   ├── build_ebpf.sh     # Rebuilds eBPF assets into internal/ebpfutil
│   └── launch_server.sh  # Builds and launches the UDP server in the background
├── results/              # Experiment artefacts (`experiment.json`, summary, logs)
├── logs/                 # Default server logs (one subdir per run)
└── go.mod / go.sum       # Go module definition (module name: `pebbleserver`)
```

---

## Server (`cmd/pebble_server`)

- Listens on UDP (default `127.0.0.1:9000`) with a configurable number of
  SO_REUSEPORT workers.
- Every GET request sleeps for `get-delay` before echoing the requested key
  back to the client (`VALUE <key>`). The optional request id is mirrored in the
  response to simplify latency attribution.
- Every SCAN request validates the limit, sleeps for `scan-delay`, and responds
  with the placeholder payload `EMPTY`.
- Worker-local statistics are aggregated once per second and written to the log
  directory so you can correlate synthetic latency with workload parameters.
- Optional eBPF policies (`default`, `round_robin`, `agent`, `scan_split`) are
  loaded from `internal/ebpfutil`. Policies that attach to SO_REUSEPORT continue
  to use the pinned map at `/sys/fs/bpf/pebble_udp_targets`.

Command-line flags (see `cmd/pebble_server/main.go`):

```
-listen          UDP listen address (default 127.0.0.1:9000)
-workers         reuseport workers (default 4)
-policy          default | round_robin | agent | scan_split
-max-scan        max keys accepted per SCAN (default 100000)
-log-dir         destination for server logs (default logs/server)
-results-dir     location for experiment metadata (default results)
-read-timeout    per-request read deadline (default 2s)
-write-timeout   per-request write deadline (default 2s)
-get-delay       synthetic GET latency (default 10µs)
-scan-delay      synthetic SCAN latency (default 2ms)
```

---

## Workload Client (`cmd/workload_client`)

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
-key-prefix   prefix for generated keys (default "key")
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
2. `scripts/launch_server.sh` – builds `cmd/pebble_server`, starts it in the
   background, and records its PID under `run/server.pid`.
3. `cmd/workload_client` – runs with the provided rate/duration arguments and
   writes a concise summary to `results/<run-id>/workload_summary.txt`.
4. Aggregates per-iteration metrics into `workload_summary.json`.
5. Shuts down the background server and reports where artefacts were stored.

CPU pinning is baked into the workflow: the server and client each receive an
exclusive CPU set carved from NUMA node 0. If you omit `--server-cores` and
`--client-cores`, `run.sh` defaults to the worker counts (`--threads` for the
server, `--send-workers` for the client); provide explicit values when you need a
different allocation. The script still refuses to start if the request cannot be
satisfied.

```bash
./run.sh \
  --server-cores 8 \
  --client-cores 8 \
  --threads 4 \
  --policy round_robin \
  --rate 500 \
  --duration 15
```

Every invocation creates a fresh `results/run-<timestamp>/` directory containing:

- `experiment.json` – the parameters used for the run, including
  `server_cores`, `client_cores`, and the resolved cpusets.
- `logs/` – the server log for that execution.
- `workload_summary.txt` – human-readable latency/throughput snapshot.
- `workload_summary.json` – machine-readable summary.

---

## Manual Invocation

If you prefer to run individual pieces yourself:

```bash
# Build binaries (outputs to ./bin)
go build -o bin/pebble_server ./cmd/pebble_server
go build -o bin/workload_client ./cmd/workload_client

# Rebuild eBPF maps/programs (requires clang/llvm)
./scripts/build_ebpf.sh

# Launch the server with custom synthetic delays
./bin/pebble_server \
    -workers 4 \
    -policy default \
    -get-delay 15us \
    -scan-delay 5ms

# In another terminal, run the workload
./bin/workload_client \
    -server 127.0.0.1:9000 \
    -duration 10s \
    -rate 250 \
    -get-frac 0.7
```

---

## Docker-based Experiments

To accelerate large experiment sweeps on a single host, a container image is
provided that bundles the compiled binaries. Each container keeps its own
logs/results under `/results`, while sharing the same eBPF build cache.

1. **Build the image**

   ```bash
   make docker-build IMAGE_NAME=pebble-server:latest
   ```

2. **Launch parallel runs**

   ```bash
   make docker-dispatch IMAGE_NAME=pebble-server:latest \
     RUN_SCRIPT_ARGS="--server-cores 8 --client-cores 8 --threads 4 --rate 60000"
   ```

   The helper script spins up multiple containers, each invoking `run.sh` with
   its own output directory. It validates the requested core counts against
   NUMA node 0 and refuses to start if `--max-parallel` would overcommit the
   available CPUs. To adjust synthetic latencies, add flags such as
   `--get-delay 15us --scan-delay 2ms` inside `ARGS="..."`.

3. **Inspect results**

   ```bash
   make docker-run IMAGE_NAME=pebble-server:latest \
     RUN_SCRIPT_ARGS="--server-cores 8 --client-cores 8 --threads 2 --duration 20"
   ```

   The container prints the location of the aggregated logs before exiting.

---

## Notes

- The UDP protocol is intentionally bare-bones to keep the focus on latency and
  load-balancing behaviour. Feel free to extend it with additional commands if
  your experiments need them.
- eBPF policies assume the reuseport target map is pinned at
  `/sys/fs/bpf/pebble_udp_targets`. The name is kept for compatibility with
  existing tooling, even though the storage layer is synthetic.
- If you update the eBPF programs, rebuild them with `scripts/build_ebpf.sh`
  before relaunching the server.

Happy benchmarking!
