#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Rewrite a TxGraph trace file to eliminate chain-shaped clusters.

Adds extra ADD_DEP edges to break chain topology. A cluster is "chain-shaped"
if every transaction has at most one parent and one child (linear A->B->C...).
After rewriting, no size>=3 chain clusters remain. Size-2 chains are left unchanged.

Use the output trace with txgraph-replay to measure ChainCluster optimization
when there are no chain clusters (baseline: optimization should show little
or no benefit).

Usage:
    python3 rewrite_trace_no_chain_clusters.py <input_trace> <output_trace> [--limit=N] [--jobs=N]
    --limit=N  Only process first N COMMIT_STAGING (for quick testing)
    --jobs=N   Use N parallel workers (default: 1). Requires two passes.
"""

import argparse
import multiprocessing
import struct
import sys
from collections import defaultdict

# Opcodes (must match TxGraphTraceOp in txgraph_tracing.h)
INIT = 0x00
ADD_TX = 0x01
REMOVE_TX = 0x02
ADD_DEP = 0x03
SET_FEE = 0x04
UNLINK_REF = 0x05
GET_ANCESTORS_UNION = 0x15
GET_DESCENDANTS_UNION = 0x16
COUNT_DISTINCT = 0x19
START_STAGING = 0x20
ABORT_STAGING = 0x21
COMMIT_STAGING = 0x22

FIXED_PAYLOAD = {
    INIT: 20,
    ADD_TX: 16,
    REMOVE_TX: 4,
    ADD_DEP: 8,
    SET_FEE: 12,
    UNLINK_REF: 4,
    0x10: 0,   # GET_BLOCK_BUILDER
    0x11: 8,   # DO_WORK
    0x12: 8,   # COMPARE_MAIN_ORDER
    0x13: 5,   # GET_ANCESTORS
    0x14: 5,   # GET_DESCENDANTS
    0x17: 5,   # GET_CLUSTER
    0x18: 4,   # GET_CHUNK_FEERATE
    0x1a: 0,   # GET_MEMORY_USAGE
    0x1b: 0,   # GET_WORST_CHUNK
    0x1c: 0,   # GET_DIAGRAMS
    0x1d: 0,   # TRIM
    0x1e: 1,   # IS_OVERSIZED
    0x1f: 5,   # EXISTS
    0x23: 4,   # GET_INDIVIDUAL_FEERATE
    0x24: 1,   # GET_TX_COUNT
    START_STAGING: 0,
    ABORT_STAGING: 0,
    COMMIT_STAGING: 0,
}

VAR_LENGTH_OPS = {GET_ANCESTORS_UNION, GET_DESCENDANTS_UNION, COUNT_DISTINCT}


class Graph:
    """Track live transactions and dependency edges."""

    def __init__(self):
        self.live = set()
        self.parents = defaultdict(set)
        self.children = defaultdict(set)

    def add_tx(self, idx):
        self.live.add(idx)

    def remove_tx(self, idx):
        self.live.discard(idx)
        for p in list(self.parents.get(idx, ())):
            self.children[p].discard(idx)
        for c in list(self.children.get(idx, ())):
            self.parents[c].discard(idx)
        self.parents.pop(idx, None)
        self.children.pop(idx, None)

    def add_dep(self, parent, child):
        if parent in self.live and child in self.live:
            self.parents[child].add(parent)
            self.children[parent].add(child)

    def copy(self):
        g = Graph()
        g.live = set(self.live)
        g.parents = defaultdict(set, {k: set(v) for k, v in self.parents.items()})
        g.children = defaultdict(set, {k: set(v) for k, v in self.children.items()})
        return g

    def get_chain_clusters(self):
        """Return list of (component, is_chain) where component is ordered [root..leaf] for chains."""
        visited = set()
        result = []

        for tx in self.live:
            if tx in visited:
                continue
            component = []
            queue = [tx]
            while queue:
                node = queue.pop()
                if node in visited:
                    continue
                visited.add(node)
                component.append(node)
                for p in self.parents.get(node, ()):
                    if p in self.live and p not in visited:
                        queue.append(p)
                for c in self.children.get(node, ()):
                    if c in self.live and c not in visited:
                        queue.append(c)

            comp_set = set(component)
            is_chain = all(
                len(self.parents.get(n, set()) & comp_set) <= 1
                and len(self.children.get(n, set()) & comp_set) <= 1
                for n in component
            )
            if is_chain and len(component) >= 2:
                # Topological order: roots first, then descendants
                ordered = []
                remaining = set(component)
                while remaining:
                    roots = [n for n in remaining if not (self.parents.get(n, set()) & remaining)]
                    if not roots:
                        break
                    for n in roots:
                        ordered.append(n)
                        remaining.discard(n)
                if len(ordered) == len(component):
                    result.append(ordered)
                else:
                    result.append(component)

        return result


def edges_to_break_chains(chain_clusters):
    """Generate (parent, child) edges to add. Only break chains of size >= 3.
    Size-2 chains are left unchanged."""
    extra = []
    for chain in chain_clusters:
        if len(chain) >= 3:
            # Add first->third to create diamond (e.g. A->B->C becomes A->B, A->C, B->C)
            extra.append((chain[0], chain[2]))
    return extra


def read_var_payload(f):
    raw = f.read(4)
    if len(raw) < 4:
        return None
    count = struct.unpack('<I', raw)[0]
    payload = raw + f.read(count * 4 + 1)
    return payload if len(payload) == 4 + count * 4 + 1 else None


def has_topology_mutation(staging_buf):
    """True if staging contains ADD_TX, ADD_DEP, REMOVE_TX, or UNLINK_REF."""
    for op, _ in staging_buf:
        if op in (ADD_TX, ADD_DEP, REMOVE_TX, UNLINK_REF):
            return True
    return False


def apply_mutations(graph, staging_buf, extra_edges):
    """Apply staging_buf and extra_edges to graph."""
    for mop, mraw in staging_buf:
        if mop == ADD_TX and len(mraw) >= 4:
            graph.add_tx(struct.unpack('<I', mraw[0:4])[0])
        elif mop in (REMOVE_TX, UNLINK_REF) and len(mraw) >= 4:
            graph.remove_tx(struct.unpack('<I', mraw)[0])
        elif mop == ADD_DEP and len(mraw) >= 8:
            parent, child = struct.unpack('<II', mraw)
            graph.add_dep(parent, child)
    for parent, child in extra_edges:
        graph.add_dep(parent, child)


def process_segment(args):
    """Worker: process segment from start_offset for segment_commits commits.
    Returns (segment_data, extra_edges_count, next_graph) for next segment."""
    inp_path, start_offset, segment_commits, initial_graph, segment_idx, is_first = args
    if initial_graph is not None:
        graph = initial_graph.copy()
    else:
        graph = Graph()

    output_chunks = []
    extra_count = 0
    commit_count = 0

    with open(inp_path, 'rb') as fin:
        fin.seek(start_offset)
        staging_buf = None

        while commit_count < segment_commits:
            b = fin.read(1)
            if not b:
                break
            op = b[0]

            if op in VAR_LENGTH_OPS:
                payload = read_var_payload(fin)
                if payload is None:
                    break
                if staging_buf is not None:
                    staging_buf.append((op, payload))
                else:
                    output_chunks.append(b + payload)
                continue

            psize = FIXED_PAYLOAD.get(op, -1)
            if psize < 0:
                break
            raw = fin.read(psize) if psize else b''
            if len(raw) < psize:
                break

            if op == INIT:
                if is_first:
                    output_chunks.append(b + raw)
                continue

            if op == START_STAGING:
                staging_buf = [(START_STAGING, raw)]
                continue

            if op == ABORT_STAGING:
                for mop, mraw in staging_buf:
                    output_chunks.append(bytes([mop]) + mraw)
                output_chunks.append(b + raw)
                staging_buf = None
                continue

            if op == COMMIT_STAGING:
                commit_count += 1
                if has_topology_mutation(staging_buf):
                    apply_mutations(graph, staging_buf, [])
                    chain_clusters = graph.get_chain_clusters()
                    extra_edges = edges_to_break_chains(chain_clusters)
                    valid_edges = [(p, c) for p, c in extra_edges if p in graph.live and c in graph.live]
                    extra_count += len(valid_edges)
                    apply_mutations(graph, [], valid_edges)
                else:
                    valid_edges = []
                    apply_mutations(graph, staging_buf, [])

                for mop, mraw in staging_buf:
                    output_chunks.append(bytes([mop]) + mraw)
                for parent, child in valid_edges:
                    output_chunks.append(bytes([ADD_DEP]) + struct.pack('<II', parent, child))
                output_chunks.append(b + raw)
                staging_buf = None
                continue

            if staging_buf is not None:
                staging_buf.append((op, raw))
            else:
                if op == ADD_TX and len(raw) >= 4:
                    graph.add_tx(struct.unpack('<I', raw[0:4])[0])
                elif op in (REMOVE_TX, UNLINK_REF) and len(raw) >= 4:
                    graph.remove_tx(struct.unpack('<I', raw)[0])
                elif op == ADD_DEP and len(raw) >= 8:
                    parent, child = struct.unpack('<II', raw)
                    graph.add_dep(parent, child)
                output_chunks.append(b + raw)

        next_offset = fin.tell()

    return (b''.join(output_chunks), extra_count, graph, next_offset)


def build_checkpoints_and_run(inp_path, out_path, num_jobs, commit_limit, total_commits):
    """Build checkpoints in first pass, then process segments in parallel."""
    commits_per_segment = (total_commits + num_jobs - 1) // num_jobs
    checkpoints = []  # [(offset, graph), ...]
    header = b''

    with open(inp_path, 'rb') as fin:
        magic = fin.read(8)
        if magic != b'TXGTRACE':
            print("Invalid trace file (bad magic)", file=sys.stderr)
            return 1
        ver = fin.read(4)
        header = magic + ver

        graph = Graph()
        staging_buf = None
        commit_count = 0
        next_save = commits_per_segment

        while commit_count < total_commits:
            b = fin.read(1)
            if not b:
                break
            op = b[0]

            if op in VAR_LENGTH_OPS:
                payload = read_var_payload(fin)
                if payload is None:
                    break
                if staging_buf is not None:
                    staging_buf.append((op, payload))
                continue

            psize = FIXED_PAYLOAD.get(op, -1)
            if psize < 0:
                break
            raw = fin.read(psize) if psize else b''
            if len(raw) < psize:
                break

            if op == INIT:
                continue
            if op == START_STAGING:
                staging_buf = [(START_STAGING, raw)]
                continue
            if op == ABORT_STAGING:
                staging_buf = None
                continue
            if op == COMMIT_STAGING:
                commit_count += 1
                if staging_buf is not None:
                    for mop, mraw in staging_buf:
                        if mop == ADD_TX and len(mraw) >= 4:
                            graph.add_tx(struct.unpack('<I', mraw[0:4])[0])
                        elif mop in (REMOVE_TX, UNLINK_REF) and len(mraw) >= 4:
                            graph.remove_tx(struct.unpack('<I', mraw)[0])
                        elif mop == ADD_DEP and len(mraw) >= 8:
                            parent, child = struct.unpack('<II', mraw)
                            graph.add_dep(parent, child)
                staging_buf = None

                if commit_count == next_save and len(checkpoints) < num_jobs - 1:
                    checkpoints.append((fin.tell(), graph.copy()))
                    next_save += commits_per_segment
                    if (len(checkpoints) + 1) % 5 == 0:
                        print(f"  Checkpoint {len(checkpoints)}/{num_jobs - 1} at commit {commit_count}",
                              file=sys.stderr)
                continue

            if staging_buf is not None:
                staging_buf.append((op, raw))
            else:
                if op == ADD_TX and len(raw) >= 4:
                    graph.add_tx(struct.unpack('<I', raw[0:4])[0])
                elif op in (REMOVE_TX, UNLINK_REF) and len(raw) >= 4:
                    graph.remove_tx(struct.unpack('<I', raw)[0])
                elif op == ADD_DEP and len(raw) >= 8:
                    parent, child = struct.unpack('<II', raw)
                    graph.add_dep(parent, child)

    # Build segment args
    segment_args = []
    segment_args.append((inp_path, 12, commits_per_segment, None, 0, True))
    for i, (offset, ckpt_graph) in enumerate(checkpoints):
        segment_args.append((inp_path, offset, commits_per_segment, ckpt_graph, i + 1, False))

    # Last segment may have fewer commits
    last_commits = total_commits - (num_jobs - 1) * commits_per_segment
    if last_commits < commits_per_segment and len(segment_args) > 1:
        segment_args[-1] = (inp_path, segment_args[-1][1], last_commits,
                            segment_args[-1][3], segment_args[-1][4], segment_args[-1][5])

    print(f"  Running {num_jobs} workers in parallel...", file=sys.stderr)
    with multiprocessing.Pool(num_jobs) as pool:
        results = pool.map(process_segment, segment_args)

    total_extra = sum(r[1] for r in results)
    with open(out_path, 'wb') as fout:
        fout.write(header)
        for r in results:
            fout.write(r[0])

    return total_extra


def main():
    parser = argparse.ArgumentParser(description="Rewrite trace to eliminate chain clusters")
    parser.add_argument("input", help="Input trace file")
    parser.add_argument("output", help="Output trace file")
    parser.add_argument("--limit", type=int, default=0,
                        help="Only process first N COMMIT_STAGING (0=all)")
    parser.add_argument("--jobs", "-j", type=int, default=1,
                        help="Number of parallel workers (default: 1)")
    args = parser.parse_args()

    inp_path = args.input
    out_path = args.output
    commit_limit = args.limit
    num_jobs = max(1, args.jobs)

    if num_jobs > 1:
        print("Counting commits...", file=sys.stderr)
        total_commits = 0
        with open(inp_path, 'rb') as f:
            f.read(12)
            while True:
                b = f.read(1)
                if not b:
                    break
                op = b[0]
                if op == COMMIT_STAGING:
                    total_commits += 1
                if op in VAR_LENGTH_OPS:
                    raw = f.read(4)
                    if len(raw) < 4:
                        break
                    n = struct.unpack('<I', raw)[0]
                    f.read(n * 4 + 1)
                else:
                    p = FIXED_PAYLOAD.get(op, -1)
                    if p < 0:
                        break
                    f.read(p)
        if commit_limit:
            total_commits = min(total_commits, commit_limit)
        print(f"Total commits: {total_commits}, building checkpoints with {num_jobs} workers...",
              file=sys.stderr)
        total_extra_edges = build_checkpoints_and_run(
            inp_path, out_path, num_jobs, commit_limit, total_commits)
        print(f"Wrote {out_path}")
        print(f"Total extra ADD_DEP edges added to break chains: {total_extra_edges}")
        return

    with open(inp_path, 'rb') as fin, open(out_path, 'wb') as fout:
        # Copy header
        magic = fin.read(8)
        if magic != b'TXGTRACE':
            print("Invalid trace file (bad magic)", file=sys.stderr)
            sys.exit(1)
        fout.write(magic)
        ver = fin.read(4)
        fout.write(ver)

        graph = Graph()
        staging_buf = []  # list of (op_byte, raw_payload)
        total_extra_edges = 0
        commit_count = 0

        while True:
            b = fin.read(1)
            if not b:
                break
            op = b[0]

            if op in VAR_LENGTH_OPS:
                payload = read_var_payload(fin)
                if payload is None:
                    break
                if staging_buf is not None:
                    staging_buf.append((op, payload))
                else:
                    fout.write(b)
                    fout.write(payload)
                continue

            psize = FIXED_PAYLOAD.get(op, -1)
            if psize < 0:
                print(f"Unknown opcode 0x{op:02x}", file=sys.stderr)
                break
            raw = fin.read(psize) if psize else b''
            if len(raw) < psize:
                break

            if op == INIT:
                fout.write(b)
                fout.write(raw)
                continue

            if op == START_STAGING:
                staging_buf = [(START_STAGING, raw)]
                continue

            if op == ABORT_STAGING:
                for mop, mraw in staging_buf:
                    fout.write(bytes([mop]) + mraw)
                fout.write(b)
                fout.write(raw)
                staging_buf = None
                continue

            if op == COMMIT_STAGING:
                commit_count += 1
                if commit_limit and commit_count > commit_limit:
                    valid_edges = []
                elif not has_topology_mutation(staging_buf):
                    valid_edges = []
                else:
                    if commit_count % 500 == 0:
                        print(f"  Processed {commit_count} commits, {total_extra_edges} extra edges so far...",
                              file=sys.stderr)
                    sim = graph.copy()
                    apply_mutations(sim, staging_buf, [])
                    chain_clusters = sim.get_chain_clusters()
                    extra_edges = edges_to_break_chains(chain_clusters)
                    valid_edges = [(p, c) for p, c in extra_edges if p in sim.live and c in sim.live]
                    total_extra_edges += len(valid_edges)

                # Write staging: original mutations + extra ADD_DEPs (staging_buf includes START_STAGING)
                for mop, mraw in staging_buf:
                    fout.write(bytes([mop]))
                    fout.write(mraw)
                for parent, child in valid_edges:
                    fout.write(bytes([ADD_DEP]))
                    fout.write(struct.pack('<II', parent, child))
                fout.write(b)
                fout.write(raw)

                apply_mutations(graph, staging_buf, valid_edges)
                staging_buf = None
                continue

            if staging_buf is not None:
                staging_buf.append((op, raw))
            else:
                if op == ADD_TX and len(raw) >= 4:
                    graph.add_tx(struct.unpack('<I', raw[0:4])[0])
                elif op in (REMOVE_TX, UNLINK_REF) and len(raw) >= 4:
                    graph.remove_tx(struct.unpack('<I', raw)[0])
                elif op == ADD_DEP and len(raw) >= 8:
                    parent, child = struct.unpack('<II', raw)
                    graph.add_dep(parent, child)
                fout.write(b)
                fout.write(raw)

    print(f"Wrote {out_path}")
    print(f"Total extra ADD_DEP edges added to break chains: {total_extra_edges}")
    print("Verify with: python3 analyze_trace.py " + out_path)


if __name__ == '__main__':
    main()
