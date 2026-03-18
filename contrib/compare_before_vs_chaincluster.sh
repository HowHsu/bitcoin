#!/usr/bin/env bash
# Compare before_chaincluster vs chaincluster: memory (RSS, GetMainMemoryUsage, massif) and time performance.
# Uses txgraph-replay (WITH_TXGRAPH_TRACING) with a trace file.
#
# Usage:
#   TXGRAPH_TRACE_FILE=/path/to/txgraph.trace ./contrib/compare_before_vs_chaincluster.sh [method]
#
# Methods:
#   rss      - Process RSS via /usr/bin/time -v (default)
#   getmain  - GetMainMemoryUsage (Cluster::TotalMemoryUsage) via --memory-csv
#   massif   - Valgrind heap profile (slow, needs Debug build)
#   time     - Wall-clock elapsed time (no memory measurement)
#
# Requires:
#   - Docker container (default: happy_shannon), source at /work/bitcoin (volume-mounted from host)
#   - Git on host: branch switching is done on host; build/run in container
#   - TXGRAPH_TRACE_FILE: path to trace file inside container (e.g. /work/txgraph.trace)
#
# No-chain-cluster baseline:
#   python3 contrib/txgraph_tracing/rewrite_trace_no_chain_clusters.py <trace> <trace.no_chain>
#   TXGRAPH_TRACE_FILE=/work/txgraph.trace.no_chain_clusters ./contrib/compare_before_vs_chaincluster.sh getmain
#
# Override container: BITCOIN_DOCKER_CONTAINER=my_container ./contrib/compare_before_vs_chaincluster.sh
#
# getmain note: --memory-csv and "GetMainMemoryUsage (final)" output exist in chaincluster.
# If before_chaincluster lacks them, cherry-pick the txgraph_replay.cpp changes from chaincluster.

set -e

CONTAINER="${BITCOIN_DOCKER_CONTAINER:-happy_shannon}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE_DIR="/work/bitcoin"
BUILD_DIR="${SOURCE_DIR}/build"
BASE_DIR="/tmp/bitcoin_mem_compare"
TRACE_FILE="${TXGRAPH_TRACE_FILE:-/work/txgraph.trace}"

method="${1:-rss}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

run_in_container() {
    docker exec "$CONTAINER" bash -c "$@"
}

# Git checkout on host (source is volume-mounted; container has no git)
git_checkout() {
    local branch="$1"
    log "git checkout $branch (on host)..."
    git -C "$REPO_ROOT" checkout "$branch"
}

main() {
    log "Compare before_chaincluster vs chaincluster (method=$method)"
    mkdir -p "$BASE_DIR"
    INITIAL_BRANCH=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)

    case "$method" in
        rss)
            _measure_rss
            ;;
        getmain)
            _measure_getmain
            ;;
        massif)
            _measure_massif
            ;;
        time)
            _measure_time
            ;;
        *)
            echo "Usage: TXGRAPH_TRACE_FILE=/path/to/trace $0 [rss|getmain|massif|time]"
            echo ""
            echo "  rss     - Process RSS via time -v (fastest)"
            echo "  getmain - TxGraph GetMainMemoryUsage (internal accounting, more accurate)"
            echo "  massif  - Valgrind heap profile (slow, needs Debug build)"
            echo "  time    - Wall-clock elapsed time (no memory measurement)"
            echo ""
            echo "Trace file: $TRACE_FILE (set TXGRAPH_TRACE_FILE to override)"
            exit 1
            ;;
    esac

    if [ -n "$INITIAL_BRANCH" ]; then
        log "Restoring branch: $INITIAL_BRANCH"
        git -C "$REPO_ROOT" checkout "$INITIAL_BRANCH" 2>/dev/null || true
    fi
    log "Done."
}

_measure_rss() {
    # 使用 txgraph-replay 回放 trace，负载可重复
    log "Building before_chaincluster (WITH_TXGRAPH_TRACING=ON)..."
    git_checkout before_chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running txgraph-replay on before_chaincluster..."
    run_in_container "cd $SOURCE_DIR && /usr/bin/time -v $BUILD_DIR/bin/txgraph-replay $TRACE_FILE 2>&1" | tee "$BASE_DIR/before_chaincluster_time.txt" | tail -25

    log "Building chaincluster..."
    git_checkout chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running txgraph-replay on chaincluster..."
    run_in_container "cd $SOURCE_DIR && /usr/bin/time -v $BUILD_DIR/bin/txgraph-replay $TRACE_FILE 2>&1" | tee "$BASE_DIR/chaincluster_time.txt" | tail -25

    echo ""
    log "=== Results (Maximum resident set size, kB) ==="
    before_rss=$(grep "Maximum resident set size" "$BASE_DIR/before_chaincluster_time.txt" | awk '{print $6}')
    chain_rss=$(grep "Maximum resident set size" "$BASE_DIR/chaincluster_time.txt" | awk '{print $6}')
    echo "  before_chaincluster: $before_rss kB"
    echo "  chaincluster:       $chain_rss kB"
    if [ -n "$before_rss" ] && [ -n "$chain_rss" ] && [ "$before_rss" -gt 0 ]; then
        diff=$((chain_rss - before_rss))
        pct=$(( (diff * 100) / before_rss ))
        echo "  difference:          $diff kB ($pct%)"
    fi
}

_measure_getmain() {
    # GetMainMemoryUsage via txgraph-replay --memory-csv (see chain-cluster-memory.zh.html)
    log "Building before_chaincluster (WITH_TXGRAPH_TRACING=ON)..."
    git_checkout before_chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running txgraph-replay --memory-csv on before_chaincluster..."
    run_in_container "cd $SOURCE_DIR && $BUILD_DIR/bin/txgraph-replay --memory-csv=/work/mem_before.csv $TRACE_FILE 2>&1" | tee "$BASE_DIR/before_chaincluster_getmain.txt" | tail -30 || true

    log "Building chaincluster..."
    git_checkout chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running txgraph-replay --memory-csv on chaincluster..."
    run_in_container "cd $SOURCE_DIR && $BUILD_DIR/bin/txgraph-replay --memory-csv=/work/mem_chain.csv $TRACE_FILE 2>&1" | tee "$BASE_DIR/chaincluster_getmain.txt" | tail -30

    echo ""
    log "=== Results (GetMainMemoryUsage, bytes) ==="
    before_bytes=$(grep "GetMainMemoryUsage (final)" "$BASE_DIR/before_chaincluster_getmain.txt" 2>/dev/null | grep -oE '[0-9]+')
    chain_bytes=$(grep "GetMainMemoryUsage (final)" "$BASE_DIR/chaincluster_getmain.txt" 2>/dev/null | grep -oE '[0-9]+')
    if [ -n "$before_bytes" ]; then
        echo "  before_chaincluster: $before_bytes bytes ($(awk "BEGIN{printf \"%.1f\", $before_bytes/1024}") KB)"
    else
        echo "  before_chaincluster: N/A (branch lacks --memory-csv; cherry-pick txgraph_replay.cpp from chaincluster)"
    fi
    if [ -n "$chain_bytes" ]; then
        echo "  chaincluster:       $chain_bytes bytes ($(awk "BEGIN{printf \"%.1f\", $chain_bytes/1024}") KB)"
    else
        echo "  chaincluster:       N/A"
    fi
    if [ -n "$before_bytes" ] && [ -n "$chain_bytes" ] && [ "$before_bytes" -gt 0 ]; then
        diff=$((chain_bytes - before_bytes))
        pct=$(( (diff * 100) / before_bytes ))
        echo "  difference:          $diff bytes ($pct%)"
    fi
    echo ""
    log "CSV files: /work/mem_before.csv, /work/mem_chain.csv (use plot_memory_curve.py to plot)"
}

_measure_massif() {
    log "Building Debug + WITH_TXGRAPH_TRACING (required for massif)..."
    git_checkout before_chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DCMAKE_BUILD_TYPE=Debug -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running massif on before_chaincluster (this may take 5-15 min)..."
    run_in_container "cd $SOURCE_DIR && valgrind --tool=massif --massif-out-file=/work/massif_before.out --stacks=no $BUILD_DIR/bin/txgraph-replay $TRACE_FILE 2>/dev/null" || true

    run_in_container "ms_print /work/massif_before.out 2>/dev/null" > "$BASE_DIR/massif_before.txt" || true

    log "Building chaincluster..."
    git_checkout chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DCMAKE_BUILD_TYPE=Debug -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running massif on chaincluster..."
    run_in_container "cd $SOURCE_DIR && valgrind --tool=massif --massif-out-file=/work/massif_chaincluster.out --stacks=no $BUILD_DIR/bin/txgraph-replay $TRACE_FILE 2>/dev/null" || true

    run_in_container "ms_print /work/massif_chaincluster.out 2>/dev/null" > "$BASE_DIR/massif_chaincluster.txt" || true

    log "Massif output saved to $BASE_DIR/massif_*.txt"
    echo ""
    log "Peak heap snapshots:"
    grep -A1 "snapshot" "$BASE_DIR/massif_before.txt" 2>/dev/null | head -20
    echo "---"
    grep -A1 "snapshot" "$BASE_DIR/massif_chaincluster.txt" 2>/dev/null | head -20
    echo ""
    log "Compare with: diff $BASE_DIR/massif_before.txt $BASE_DIR/massif_chaincluster.txt"
}

_measure_time() {
    log "Building before_chaincluster (WITH_TXGRAPH_TRACING=ON)..."
    git_checkout before_chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running txgraph-replay on before_chaincluster..."
    before_start=$(date +%s)
    run_in_container "cd $SOURCE_DIR && $BUILD_DIR/bin/txgraph-replay $TRACE_FILE 2>&1" | tee "$BASE_DIR/before_chaincluster_time.txt" | tail -30
    before_end=$(date +%s)
    before_elapsed=$((before_end - before_start))

    log "Building chaincluster..."
    git_checkout chaincluster
    run_in_container "cd $SOURCE_DIR && cmake -B $BUILD_DIR -DWITH_TXGRAPH_TRACING=ON 2>/dev/null && cmake --build $BUILD_DIR -j\$(nproc) -t txgraph-replay 2>/dev/null" || true

    log "Running txgraph-replay on chaincluster..."
    chain_start=$(date +%s)
    run_in_container "cd $SOURCE_DIR && $BUILD_DIR/bin/txgraph-replay $TRACE_FILE 2>&1" | tee "$BASE_DIR/chaincluster_time.txt" | tail -30
    chain_end=$(date +%s)
    chain_elapsed=$((chain_end - chain_start))

    echo ""
    log "=== Results (Wall-clock elapsed time, seconds) ==="
    echo "  before_chaincluster: $before_elapsed s"
    echo "  chaincluster:       $chain_elapsed s"
    if [ -n "$before_elapsed" ] && [ -n "$chain_elapsed" ] && [ "$before_elapsed" -gt 0 ]; then
        diff=$((chain_elapsed - before_elapsed))
        pct=$(( (diff * 100) / before_elapsed ))
        echo "  difference:          $diff s ($pct%)"
    fi
    echo ""
    log "TOTAL (us) from replay summary:"
    grep "TOTAL" "$BASE_DIR/before_chaincluster_time.txt" 2>/dev/null || true
    grep "TOTAL" "$BASE_DIR/chaincluster_time.txt" 2>/dev/null || true
}

main
