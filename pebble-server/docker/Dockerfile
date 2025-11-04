############################
# Builder stage
############################
FROM golang:1.22-bookworm AS builder

ARG APP_HOME=/src
WORKDIR ${APP_HOME}

# Install clang for eBPF generation.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    linux-libc-dev \
    libbpf-dev \
    make \
    && ln -s /usr/include/$(gcc -dumpmachine)/asm /usr/include/asm || true \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate eBPF assets (expects clang in PATH).
RUN scripts/build_ebpf.sh

# Build binaries we need at runtime.
RUN CGO_ENABLED=0 go build -o bin/pebble_server ./cmd/pebble_server
RUN CGO_ENABLED=0 go build -o bin/workload_client ./cmd/workload_client
RUN CGO_ENABLED=0 go build -o bin/setupdb ./cmd/setupdb

############################
# Runtime stage
############################
FROM debian:bookworm-slim AS runtime

ARG APP_HOME=/opt/app
ARG DATA_HOME=/opt/pebble-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    iproute2 \
    iputils-ping \
    python3 \
    rsync \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${APP_HOME}

# Copy application source (without Go toolchain).
COPY --from=builder /src/internal ./internal
COPY --from=builder /src/scripts ./scripts
COPY --from=builder /src/run.sh ./run.sh
COPY --from=builder /src/run_exp.py ./run_exp.py
COPY --from=builder /src/bin ./bin
COPY --from=builder /src/pebble.data ${DATA_HOME}
COPY docker/run_experiment.sh /usr/local/bin/run_experiment.sh

RUN chmod +x /usr/local/bin/run_experiment.sh \
    ./run.sh \
    ./scripts/*.sh

ENV SKIP_EBPF_BUILD=true \
    BUILD_SERVER_BIN=false \
    OUTPUT_ROOT=/results \
    RUN_STATE_DIR=/tmp/runstate \
    RESULTS_DIR=/results \
    PATH="${APP_HOME}/bin:${PATH}"

VOLUME ["/results"]

ENTRYPOINT ["/usr/local/bin/run_experiment.sh"]
