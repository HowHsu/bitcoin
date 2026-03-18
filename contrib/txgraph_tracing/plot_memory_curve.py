#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Plot TxGraph GetMainMemoryUsage curve from txgraph-replay --memory-csv output.

Usage:
    txgraph-replay --memory-csv=mem.csv /path/to/trace
    python3 contrib/txgraph_tracing/plot_memory_curve.py mem.csv [--output=curve.png]

Reads CSV with columns: commit_index, usage_bytes
Downsamples to at most 10000 points for display if needed.
"""

import argparse
import sys

def load_csv(path):
    commit_indices = []
    usage_bytes = []
    with open(path) as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                commit_indices.append(int(parts[0]))
                usage_bytes.append(int(parts[1]))
    return commit_indices, usage_bytes

def main():
    parser = argparse.ArgumentParser(description="Plot TxGraph memory usage curve")
    parser.add_argument("csv", nargs="+", help="CSV file(s) from txgraph-replay --memory-csv")
    parser.add_argument("--output", "-o", default="memory_curve.png", help="Output image path")
    parser.add_argument("--labels", nargs="+", help="Labels for each CSV (default: filenames)")
    parser.add_argument("--max-points", type=int, default=10000,
                        help="Max points to plot (downsample if exceeded)")
    args = parser.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Error: matplotlib required. Install with: pip install matplotlib", file=sys.stderr)
        return 1

    colors = ["#0066cc", "#cc6600", "#00aa66"]
    fig, ax = plt.subplots(figsize=(12, 6))

    for i, csv_path in enumerate(args.csv):
        commit_indices, usage_bytes = load_csv(csv_path)
        n = len(commit_indices)
        if n == 0:
            print(f"Error: no data in {csv_path}", file=sys.stderr)
            return 1
        print(f"Loaded {n} samples from {csv_path}")

        if n > args.max_points:
            step = n // args.max_points
            idx = list(range(0, n, step))
            if idx[-1] != n - 1:
                idx.append(n - 1)
            commit_indices = [commit_indices[j] for j in idx]
            usage_bytes = [usage_bytes[j] for j in idx]

        usage_mb = [b / (1024 * 1024) for b in usage_bytes]
        label = args.labels[i] if args.labels and i < len(args.labels) else csv_path
        ax.plot(commit_indices, usage_mb, linewidth=0.8, color=colors[i % len(colors)], label=label)

    ax.set_xlabel("COMMIT_STAGING index")
    ax.set_ylabel("GetMainMemoryUsage (MB)")
    ax.set_title("TxGraph memory usage over replay (every 100th COMMIT_STAGING)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_xlim(left=0)

    plt.tight_layout()
    plt.savefig(args.output, dpi=150)
    print(f"Saved plot to {args.output}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
