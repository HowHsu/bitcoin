// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXGRAPH_TRACING_H
#define BITCOIN_TXGRAPH_TRACING_H

#include <txgraph.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

/** Opcodes for the TxGraph binary trace format.
 *
 * Trace file layout:
 * - Header: 8-byte magic "TXGTRACE" + uint32_t version = 1
 * - INIT record: opcode 0x00 + construction parameters
 * - Sequence of operation records, each beginning with a 1-byte opcode
 *
 * All multi-byte integers are little-endian.
 * Level encoding: TOP=0, MAIN=1 (matching TxGraph::Level enum values).
 */
enum class TxGraphTraceOp : uint8_t {
    // Initialisation (recorded once after header)
    INIT                  = 0x00, //!< [uint32 max_cluster_count][uint64 max_cluster_size][uint64 acceptable_cost]

    // Mutations
    ADD_TX                = 0x01, //!< [uint32 graph_idx][int64 fee][int32 size]
    REMOVE_TX             = 0x02, //!< [uint32 graph_idx]
    ADD_DEP               = 0x03, //!< [uint32 parent][uint32 child]
    SET_FEE               = 0x04, //!< [uint32 graph_idx][int64 fee]
    UNLINK_REF            = 0x05, //!< [uint32 graph_idx]  — Ref destroyed

    // Trigger operations (any method that may call ApplyDependencies internally)
    GET_BLOCK_BUILDER     = 0x10, //!< (no payload)
    DO_WORK               = 0x11, //!< [uint64 max_cost]
    COMPARE_MAIN_ORDER    = 0x12, //!< [uint32 idx_a][uint32 idx_b]
    GET_ANCESTORS         = 0x13, //!< [uint32 idx][uint8 level]
    GET_DESCENDANTS       = 0x14, //!< [uint32 idx][uint8 level]
    GET_ANCESTORS_UNION   = 0x15, //!< [uint32 count][uint32 idx * count][uint8 level]
    GET_DESCENDANTS_UNION = 0x16, //!< [uint32 count][uint32 idx * count][uint8 level]
    GET_CLUSTER           = 0x17, //!< [uint32 idx][uint8 level]
    GET_CHUNK_FEERATE     = 0x18, //!< [uint32 idx]
    COUNT_DISTINCT        = 0x19, //!< [uint32 count][uint32 idx * count][uint8 level]
    GET_MEMORY_USAGE      = 0x1a, //!< (no payload)
    GET_WORST_CHUNK       = 0x1b, //!< (no payload)
    GET_DIAGRAMS          = 0x1c, //!< (no payload)
    TRIM                  = 0x1d, //!< (no payload)
    IS_OVERSIZED          = 0x1e, //!< [uint8 level]
    EXISTS                = 0x1f, //!< [uint32 idx][uint8 level]
    GET_INDIVIDUAL_FEERATE = 0x23, //!< [uint32 idx]
    GET_TX_COUNT          = 0x24, //!< [uint8 level]

    // Staging
    START_STAGING         = 0x20, //!< (no payload)
    ABORT_STAGING         = 0x21, //!< (no payload)
    COMMIT_STAGING        = 0x22, //!< (no payload)
};

/** Callback invoked by ~Ref() to emit UNLINK_REF trace records.
 *  Set by TracingTxGraph constructor, cleared by its destructor. */
extern void (*g_txgraph_on_unlink_ref)(uint32_t);

/** Wrap a TxGraph implementation with binary trace recording.
 *
 * If trace_path is null or empty, returns impl unchanged.
 * Otherwise returns a TracingTxGraph that records every API call to a binary
 * trace file, while forwarding all operations to the inner implementation.
 *
 * The trace file can later be replayed with the txgraph-replay tool to measure
 * per-entry-point timing on different TxGraph implementations.
 */
std::unique_ptr<TxGraph> MakeTracingTxGraph(
    std::unique_ptr<TxGraph> impl,
    unsigned max_cluster_count,
    uint64_t max_cluster_size,
    uint64_t acceptable_cost,
    const char* trace_path) noexcept;

#endif // BITCOIN_TXGRAPH_TRACING_H
