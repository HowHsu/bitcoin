// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txgraph_tracing.h>

#include <util/check.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <utility>

// Global callback, defined here, declared extern in txgraph_tracing.h and txgraph.cpp.
void (*g_txgraph_on_unlink_ref)(uint32_t) = nullptr;

namespace {

// Module-level FILE* used by the unlink callback (mirrors TracingTxGraph::m_file).
FILE* s_trace_file = nullptr;

// ---------------------------------------------------------------------------
// Little-endian binary I/O helpers
// ---------------------------------------------------------------------------

void WriteBytes(FILE* f, const void* buf, size_t n) { fwrite(buf, 1, n, f); }

template <typename T>
void WriteLE(FILE* f, T val)
{
    uint8_t buf[sizeof(T)];
    for (size_t i = 0; i < sizeof(T); ++i) {
        buf[i] = static_cast<uint8_t>(val >> (8 * i));
    }
    WriteBytes(f, buf, sizeof(T));
}

void WriteLE_i64(FILE* f, int64_t val)
{
    uint64_t u;
    memcpy(&u, &val, sizeof(u));
    WriteLE(f, u);
}

void WriteLE_i32(FILE* f, int32_t val)
{
    uint32_t u;
    memcpy(&u, &val, sizeof(u));
    WriteLE(f, u);
}

void WriteOp(FILE* f, TxGraphTraceOp op)
{
    uint8_t b = static_cast<uint8_t>(op);
    WriteBytes(f, &b, 1);
}

void TraceUnlinkRef(uint32_t index)
{
    WriteOp(s_trace_file, TxGraphTraceOp::UNLINK_REF);
    WriteLE(s_trace_file, index);
}

// ---------------------------------------------------------------------------
// TracingTxGraph — decorator that records a binary trace while forwarding
// ---------------------------------------------------------------------------

class TracingTxGraph final : public TxGraph
{
    std::unique_ptr<TxGraph> m_impl;
    FILE* m_file;

public:
    TracingTxGraph(std::unique_ptr<TxGraph> impl, FILE* file) noexcept
        : m_impl(std::move(impl)), m_file(file)
    {
        s_trace_file = file;
        g_txgraph_on_unlink_ref = TraceUnlinkRef;
    }

    ~TracingTxGraph() override
    {
        g_txgraph_on_unlink_ref = nullptr;
        s_trace_file = nullptr;
        if (m_file) {
            fflush(m_file);
            fclose(m_file);
        }
    }

    // === Mutations (trace + forward) ===

    void AddTransaction(Ref& arg, const FeePerWeight& feerate) noexcept override
    {
        m_impl->AddTransaction(arg, feerate);
        GraphIndex idx = GetRefIndex(arg);
        WriteOp(m_file, TxGraphTraceOp::ADD_TX);
        WriteLE(m_file, idx);
        WriteLE_i64(m_file, feerate.fee);
        WriteLE_i32(m_file, feerate.size);
    }

    void RemoveTransaction(const Ref& arg) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::REMOVE_TX);
        WriteLE(m_file, GetRefIndex(arg));
        m_impl->RemoveTransaction(arg);
    }

    void AddDependency(const Ref& parent, const Ref& child) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::ADD_DEP);
        WriteLE(m_file, GetRefIndex(parent));
        WriteLE(m_file, GetRefIndex(child));
        m_impl->AddDependency(parent, child);
    }

    void SetTransactionFee(const Ref& arg, int64_t fee) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::SET_FEE);
        WriteLE(m_file, GetRefIndex(arg));
        WriteLE_i64(m_file, fee);
        m_impl->SetTransactionFee(arg, fee);
    }

    // === Trigger operations (trace + forward) ===

    std::unique_ptr<BlockBuilder> GetBlockBuilder() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_BLOCK_BUILDER);
        return m_impl->GetBlockBuilder();
    }

    bool DoWork(uint64_t max_cost) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::DO_WORK);
        WriteLE(m_file, max_cost);
        return m_impl->DoWork(max_cost);
    }

    std::strong_ordering CompareMainOrder(const Ref& a, const Ref& b) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::COMPARE_MAIN_ORDER);
        WriteLE(m_file, GetRefIndex(a));
        WriteLE(m_file, GetRefIndex(b));
        return m_impl->CompareMainOrder(a, b);
    }

    std::vector<Ref*> GetAncestors(const Ref& arg, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_ANCESTORS);
        WriteLE(m_file, GetRefIndex(arg));
        WriteBytes(m_file, &level, 1);
        return m_impl->GetAncestors(arg, level);
    }

    std::vector<Ref*> GetDescendants(const Ref& arg, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_DESCENDANTS);
        WriteLE(m_file, GetRefIndex(arg));
        WriteBytes(m_file, &level, 1);
        return m_impl->GetDescendants(arg, level);
    }

    std::vector<Ref*> GetAncestorsUnion(std::span<const Ref* const> args, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_ANCESTORS_UNION);
        WriteLE<uint32_t>(m_file, static_cast<uint32_t>(args.size()));
        for (const Ref* r : args) {
            WriteLE(m_file, GetRefIndex(*r));
        }
        WriteBytes(m_file, &level, 1);
        return m_impl->GetAncestorsUnion(args, level);
    }

    std::vector<Ref*> GetDescendantsUnion(std::span<const Ref* const> args, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_DESCENDANTS_UNION);
        WriteLE<uint32_t>(m_file, static_cast<uint32_t>(args.size()));
        for (const Ref* r : args) {
            WriteLE(m_file, GetRefIndex(*r));
        }
        WriteBytes(m_file, &level, 1);
        return m_impl->GetDescendantsUnion(args, level);
    }

    std::vector<Ref*> GetCluster(const Ref& arg, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_CLUSTER);
        WriteLE(m_file, GetRefIndex(arg));
        WriteBytes(m_file, &level, 1);
        return m_impl->GetCluster(arg, level);
    }

    FeePerWeight GetMainChunkFeerate(const Ref& arg) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_CHUNK_FEERATE);
        WriteLE(m_file, GetRefIndex(arg));
        return m_impl->GetMainChunkFeerate(arg);
    }

    GraphIndex CountDistinctClusters(std::span<const Ref* const> args, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::COUNT_DISTINCT);
        WriteLE<uint32_t>(m_file, static_cast<uint32_t>(args.size()));
        for (const Ref* r : args) {
            WriteLE(m_file, GetRefIndex(*r));
        }
        WriteBytes(m_file, &level, 1);
        return m_impl->CountDistinctClusters(args, level);
    }

    size_t GetMainMemoryUsage() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_MEMORY_USAGE);
        return m_impl->GetMainMemoryUsage();
    }

    std::pair<std::vector<Ref*>, FeePerWeight> GetWorstMainChunk() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_WORST_CHUNK);
        return m_impl->GetWorstMainChunk();
    }

    std::pair<std::vector<FeeFrac>, std::vector<FeeFrac>> GetMainStagingDiagrams() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_DIAGRAMS);
        return m_impl->GetMainStagingDiagrams();
    }

    std::vector<Ref*> Trim() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::TRIM);
        return m_impl->Trim();
    }

    // === Staging (trace + forward) ===

    void StartStaging() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::START_STAGING);
        m_impl->StartStaging();
    }

    void AbortStaging() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::ABORT_STAGING);
        m_impl->AbortStaging();
    }

    void CommitStaging() noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::COMMIT_STAGING);
        m_impl->CommitStaging();
    }

    // === Pure queries (forward only) ===

    bool HaveStaging() const noexcept override { return m_impl->HaveStaging(); }
    bool IsOversized(Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::IS_OVERSIZED);
        WriteBytes(m_file, &level, 1);
        return m_impl->IsOversized(level);
    }
    bool Exists(const Ref& arg, Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::EXISTS);
        WriteLE(m_file, GetRefIndex(arg));
        WriteBytes(m_file, &level, 1);
        return m_impl->Exists(arg, level);
    }
    FeePerWeight GetIndividualFeerate(const Ref& arg) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_INDIVIDUAL_FEERATE);
        WriteLE(m_file, GetRefIndex(arg));
        return m_impl->GetIndividualFeerate(arg);
    }
    GraphIndex GetTransactionCount(Level level) noexcept override
    {
        WriteOp(m_file, TxGraphTraceOp::GET_TX_COUNT);
        WriteBytes(m_file, &level, 1);
        return m_impl->GetTransactionCount(level);
    }

    // === Sanity check (forward only) ===

    void SanityCheck() const override { m_impl->SanityCheck(); }

    // === Protected virtual overrides ===
    // Ref.m_graph points to m_impl, so these are never called on the wrapper.
    // UNLINK_REF tracing is handled by the g_txgraph_on_unlink_ref callback in ~Ref().

    void UpdateRef(GraphIndex, Ref&) noexcept override { Assume(false); }
    void UnlinkRef(GraphIndex) noexcept override { Assume(false); }
};

} // namespace

std::unique_ptr<TxGraph> MakeTracingTxGraph(
    std::unique_ptr<TxGraph> impl,
    unsigned max_cluster_count,
    uint64_t max_cluster_size,
    uint64_t acceptable_cost,
    const char* trace_path) noexcept
{
    if (!trace_path || trace_path[0] == '\0') return impl;

    FILE* f = fopen(trace_path, "wb");
    if (!f) {
        fprintf(stderr, "TxGraph tracing: cannot open '%s' for writing, tracing disabled.\n", trace_path);
        return impl;
    }

    // Write header.
    static const uint8_t magic[8] = {'T','X','G','T','R','A','C','E'};
    WriteBytes(f, magic, 8);
    WriteLE<uint32_t>(f, 1); // version

    // Write INIT record.
    WriteOp(f, TxGraphTraceOp::INIT);
    WriteLE<uint32_t>(f, max_cluster_count);
    WriteLE(f, max_cluster_size);
    WriteLE(f, acceptable_cost);

    fflush(f);

    return std::make_unique<TracingTxGraph>(std::move(impl), f);
}
