// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/** Standalone tool that replays a TxGraph binary trace file and reports
 *  per-entry-point timing statistics. Used to compare TxGraph performance
 *  across different implementations (e.g. before/after optimisations).
 *
 *  Usage: txgraph-replay [--memory-csv=<file>] <trace_file>
 *
 *  --memory-csv: After each COMMIT_STAGING, call GetMainMemoryUsage() and append
 *  (commit_index, usage_bytes) to the CSV. Samples every 100th COMMIT_STAGING to
 *  yield ~17.6k points for txgraph.trace.4.5days.final. Use plot_memory_curve.py.
 */

#include <txgraph.h>
#include <txgraph_tracing.h>
#include <util/translation.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

// ---------------------------------------------------------------------------
// Minimal I/O helpers (little-endian)
// ---------------------------------------------------------------------------

static bool ReadBytes(FILE* f, void* buf, size_t n)
{
    return fread(buf, 1, n, f) == n;
}

template <typename T>
static bool ReadLE(FILE* f, T& out)
{
    uint8_t buf[sizeof(T)];
    if (!ReadBytes(f, buf, sizeof(T))) return false;
    out = T{};
    for (size_t i = 0; i < sizeof(T); ++i) {
        out |= T(buf[i]) << (8 * i);
    }
    return true;
}

static bool ReadLE_i64(FILE* f, int64_t& out)
{
    uint64_t u{};
    if (!ReadLE(f, u)) return false;
    memcpy(&out, &u, sizeof(out));
    return true;
}

static bool ReadLE_i32(FILE* f, int32_t& out)
{
    uint32_t u{};
    if (!ReadLE(f, u)) return false;
    memcpy(&out, &u, sizeof(out));
    return true;
}

// ---------------------------------------------------------------------------
// Per-entry-point timing accumulator
// ---------------------------------------------------------------------------

struct TimingStats {
    const char* name{nullptr};
    uint64_t calls{0};
    uint64_t total_us{0};
};

using Clock = std::chrono::steady_clock;

static uint64_t ElapsedUs(Clock::time_point start)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    const char* trace_file = nullptr;
    const char* memory_csv = nullptr;
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (strncmp(arg, "--memory-csv=", 13) == 0) {
            memory_csv = arg + 13;
        } else if (arg[0] != '-') {
            trace_file = arg;
        }
    }
    if (!trace_file) {
        fprintf(stderr, "Usage: %s [--memory-csv=<file>] <trace_file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(trace_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", trace_file);
        return 1;
    }

    FILE* mem_csv = nullptr;
    if (memory_csv) {
        mem_csv = fopen(memory_csv, "w");
        if (!mem_csv) {
            fprintf(stderr, "Error: cannot create '%s'\n", memory_csv);
            fclose(f);
            return 1;
        }
        fprintf(mem_csv, "commit_index,usage_bytes\n");
    }

    // ------------------------------------------------------------------
    // Validate header
    // ------------------------------------------------------------------
    uint8_t magic[8];
    if (!ReadBytes(f, magic, 8)) {
        fprintf(stderr, "Error: file too short for magic\n");
        fclose(f);
        return 1;
    }
    static const uint8_t expected_magic[8] = {'T','X','G','T','R','A','C','E'};
    if (memcmp(magic, expected_magic, 8) != 0) {
        fprintf(stderr, "Error: invalid magic bytes\n");
        fclose(f);
        return 1;
    }
    uint32_t version{};
    if (!ReadLE(f, version)) {
        fprintf(stderr, "Error: file too short for version\n");
        fclose(f);
        return 1;
    }
    if (version != 1) {
        fprintf(stderr, "Error: unsupported trace version %u\n", version);
        fclose(f);
        return 1;
    }

    // ------------------------------------------------------------------
    // Read INIT record
    // ------------------------------------------------------------------
    uint8_t init_op{};
    if (!ReadBytes(f, &init_op, 1) || init_op != static_cast<uint8_t>(TxGraphTraceOp::INIT)) {
        fprintf(stderr, "Error: expected INIT record after header\n");
        fclose(f);
        return 1;
    }
    uint32_t max_cluster_count{};
    uint64_t max_cluster_size{};
    uint64_t acceptable_cost{};
    if (!ReadLE(f, max_cluster_count) || !ReadLE(f, max_cluster_size) || !ReadLE(f, acceptable_cost)) {
        fprintf(stderr, "Error: truncated INIT record\n");
        fclose(f);
        return 1;
    }

    printf("TxGraph parameters: max_cluster_count=%u, max_cluster_size=%llu, acceptable_cost=%llu\n",
           max_cluster_count,
           (unsigned long long)max_cluster_size,
           (unsigned long long)acceptable_cost);

    // ------------------------------------------------------------------
    // Create TxGraph
    // ------------------------------------------------------------------
    auto cmp = [](const TxGraph::Ref& a, const TxGraph::Ref& b) -> std::strong_ordering {
        return &a <=> &b;
    };
    auto graph = MakeTxGraph(max_cluster_count, max_cluster_size, acceptable_cost, cmp);

    // Map from recorded GraphIndex -> live Ref.
    // Uses unique_ptr because Ref has deleted move-assignment.
    std::unordered_map<uint32_t, std::unique_ptr<TxGraph::Ref>> refs;

    // ------------------------------------------------------------------
    // Per-entry-point timing stats (indexed by TxGraphTraceOp)
    // ------------------------------------------------------------------
    static constexpr size_t NUM_OPS = 0x30;
    TimingStats stats[NUM_OPS]{};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_BLOCK_BUILDER)]     = {"GetBlockBuilder"};
    stats[static_cast<size_t>(TxGraphTraceOp::DO_WORK)]               = {"DoWork"};
    stats[static_cast<size_t>(TxGraphTraceOp::COMPARE_MAIN_ORDER)]    = {"CompareMainOrder"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_ANCESTORS)]         = {"GetAncestors"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_DESCENDANTS)]       = {"GetDescendants"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_ANCESTORS_UNION)]   = {"GetAncestorsUnion"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_DESCENDANTS_UNION)] = {"GetDescendantsUnion"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_CLUSTER)]           = {"GetCluster"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_CHUNK_FEERATE)]     = {"GetMainChunkFeerate"};
    stats[static_cast<size_t>(TxGraphTraceOp::COUNT_DISTINCT)]        = {"CountDistinctClusters"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_MEMORY_USAGE)]      = {"GetMainMemoryUsage"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_WORST_CHUNK)]       = {"GetWorstMainChunk"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_DIAGRAMS)]          = {"GetMainStagingDiagrams"};
    stats[static_cast<size_t>(TxGraphTraceOp::TRIM)]                  = {"Trim"};
    stats[static_cast<size_t>(TxGraphTraceOp::IS_OVERSIZED)]           = {"IsOversized"};
    stats[static_cast<size_t>(TxGraphTraceOp::EXISTS)]                 = {"Exists"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_INDIVIDUAL_FEERATE)] = {"GetIndividualFeerate"};
    stats[static_cast<size_t>(TxGraphTraceOp::GET_TX_COUNT)]           = {"GetTransactionCount"};
    stats[static_cast<size_t>(TxGraphTraceOp::START_STAGING)]         = {"StartStaging"};
    stats[static_cast<size_t>(TxGraphTraceOp::ABORT_STAGING)]         = {"AbortStaging"};
    stats[static_cast<size_t>(TxGraphTraceOp::COMMIT_STAGING)]        = {"CommitStaging"};

    // Mutation counters (not timed, but counted).
    uint64_t add_tx_count{0}, remove_tx_count{0}, add_dep_count{0}, set_fee_count{0}, unlink_ref_count{0};
    uint64_t total_ops{0};
    uint64_t commit_count{0};

    // ------------------------------------------------------------------
    // Replay loop
    // ------------------------------------------------------------------
    while (true) {
        uint8_t opbyte{};
        if (!ReadBytes(f, &opbyte, 1)) break; // EOF

        ++total_ops;

        switch (static_cast<TxGraphTraceOp>(opbyte)) {

        // ----------------------------------------------------------
        // Mutations (execute, no timing)
        // ----------------------------------------------------------
        case TxGraphTraceOp::ADD_TX: {
            ++add_tx_count;
            uint32_t graph_idx{};
            int64_t fee{};
            int32_t size{};
            if (!ReadLE(f, graph_idx) || !ReadLE_i64(f, fee) || !ReadLE_i32(f, size)) goto eof_error;
            {
                // Replace any old Ref for this graph_idx (destroys it → UnlinkRef).
                refs[graph_idx] = std::make_unique<TxGraph::Ref>();
                FeePerWeight feerate{fee, size};
                graph->AddTransaction(*refs[graph_idx], feerate);
            }
            break;
        }

        case TxGraphTraceOp::REMOVE_TX: {
            ++remove_tx_count;
            uint32_t graph_idx{};
            if (!ReadLE(f, graph_idx)) goto eof_error;
            {
                auto it = refs.find(graph_idx);
                if (it == refs.end() || !it->second) break;
                graph->RemoveTransaction(*it->second);
                // Ref stays alive in refs — it will be destroyed by UNLINK_REF
                // (matching original lifetime where Ref survives until mapTx.erase).
            }
            break;
        }

        case TxGraphTraceOp::ADD_DEP: {
            ++add_dep_count;
            uint32_t parent{}, child{};
            if (!ReadLE(f, parent) || !ReadLE(f, child)) goto eof_error;
            {
                auto pit = refs.find(parent);
                auto cit = refs.find(child);
                if (pit == refs.end() || !pit->second || cit == refs.end() || !cit->second) break;
                graph->AddDependency(*pit->second, *cit->second);
            }
            break;
        }

        case TxGraphTraceOp::SET_FEE: {
            ++set_fee_count;
            uint32_t graph_idx{};
            int64_t fee{};
            if (!ReadLE(f, graph_idx) || !ReadLE_i64(f, fee)) goto eof_error;
            {
                auto it = refs.find(graph_idx);
                if (it == refs.end() || !it->second) break;
                graph->SetTransactionFee(*it->second, fee);
            }
            break;
        }

        case TxGraphTraceOp::UNLINK_REF: {
            ++unlink_ref_count;
            uint32_t graph_idx{};
            if (!ReadLE(f, graph_idx)) goto eof_error;
            refs.erase(graph_idx); // Destroys Ref → ~Ref → graph->UnlinkRef
            break;
        }

        // ----------------------------------------------------------
        // Trigger operations (execute + time)
        // ----------------------------------------------------------
        case TxGraphTraceOp::GET_BLOCK_BUILDER: {
            auto t0 = Clock::now();
            auto builder = graph->GetBlockBuilder();
            while (auto chunk = builder->GetCurrentChunk()) {
                builder->Include();
            }
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::DO_WORK: {
            uint64_t max_cost{};
            if (!ReadLE(f, max_cost)) goto eof_error;
            auto t0 = Clock::now();
            graph->DoWork(max_cost);
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::COMPARE_MAIN_ORDER: {
            uint32_t idx_a{}, idx_b{};
            if (!ReadLE(f, idx_a) || !ReadLE(f, idx_b)) goto eof_error;
            {
                auto ait = refs.find(idx_a);
                auto bit = refs.find(idx_b);
                if (ait == refs.end() || !ait->second || bit == refs.end() || !bit->second) break;
                auto t0 = Clock::now();
                (void)graph->CompareMainOrder(*ait->second, *bit->second);
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::GET_ANCESTORS: {
            uint32_t idx{};
            uint8_t level_byte{};
            if (!ReadLE(f, idx) || !ReadBytes(f, &level_byte, 1)) goto eof_error;
            {
                auto it = refs.find(idx);
                if (it == refs.end() || !it->second) break;
                auto t0 = Clock::now();
                (void)graph->GetAncestors(*it->second, static_cast<TxGraph::Level>(level_byte));
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::GET_DESCENDANTS: {
            uint32_t idx{};
            uint8_t level_byte{};
            if (!ReadLE(f, idx) || !ReadBytes(f, &level_byte, 1)) goto eof_error;
            {
                auto it = refs.find(idx);
                if (it == refs.end() || !it->second) break;
                auto t0 = Clock::now();
                (void)graph->GetDescendants(*it->second, static_cast<TxGraph::Level>(level_byte));
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::GET_ANCESTORS_UNION: {
            uint32_t count{};
            if (!ReadLE(f, count)) goto eof_error;
            {
                std::vector<uint32_t> idxs(count);
                for (uint32_t i = 0; i < count; ++i) {
                    if (!ReadLE(f, idxs[i])) goto eof_error;
                }
                uint8_t level_byte{};
                if (!ReadBytes(f, &level_byte, 1)) goto eof_error;
                std::vector<const TxGraph::Ref*> ptrs;
                ptrs.reserve(count);
                for (uint32_t ridx : idxs) {
                    auto it = refs.find(ridx);
                    if (it != refs.end() && it->second) ptrs.push_back(it->second.get());
                }
                if (!ptrs.empty()) {
                    auto t0 = Clock::now();
                    (void)graph->GetAncestorsUnion(ptrs, static_cast<TxGraph::Level>(level_byte));
                    stats[opbyte].total_us += ElapsedUs(t0);
                    ++stats[opbyte].calls;
                }
            }
            break;
        }

        case TxGraphTraceOp::GET_DESCENDANTS_UNION: {
            uint32_t count{};
            if (!ReadLE(f, count)) goto eof_error;
            {
                std::vector<uint32_t> idxs(count);
                for (uint32_t i = 0; i < count; ++i) {
                    if (!ReadLE(f, idxs[i])) goto eof_error;
                }
                uint8_t level_byte{};
                if (!ReadBytes(f, &level_byte, 1)) goto eof_error;
                std::vector<const TxGraph::Ref*> ptrs;
                ptrs.reserve(count);
                for (uint32_t ridx : idxs) {
                    auto it = refs.find(ridx);
                    if (it != refs.end() && it->second) ptrs.push_back(it->second.get());
                }
                if (!ptrs.empty()) {
                    auto t0 = Clock::now();
                    (void)graph->GetDescendantsUnion(ptrs, static_cast<TxGraph::Level>(level_byte));
                    stats[opbyte].total_us += ElapsedUs(t0);
                    ++stats[opbyte].calls;
                }
            }
            break;
        }

        case TxGraphTraceOp::GET_CLUSTER: {
            uint32_t idx{};
            uint8_t level_byte{};
            if (!ReadLE(f, idx) || !ReadBytes(f, &level_byte, 1)) goto eof_error;
            {
                auto it = refs.find(idx);
                if (it == refs.end() || !it->second) break;
                auto t0 = Clock::now();
                (void)graph->GetCluster(*it->second, static_cast<TxGraph::Level>(level_byte));
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::GET_CHUNK_FEERATE: {
            uint32_t idx{};
            if (!ReadLE(f, idx)) goto eof_error;
            {
                auto it = refs.find(idx);
                if (it == refs.end() || !it->second) break;
                auto t0 = Clock::now();
                (void)graph->GetMainChunkFeerate(*it->second);
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::COUNT_DISTINCT: {
            uint32_t count{};
            if (!ReadLE(f, count)) goto eof_error;
            {
                std::vector<uint32_t> idxs(count);
                for (uint32_t i = 0; i < count; ++i) {
                    if (!ReadLE(f, idxs[i])) goto eof_error;
                }
                uint8_t level_byte{};
                if (!ReadBytes(f, &level_byte, 1)) goto eof_error;
                std::vector<const TxGraph::Ref*> ptrs;
                ptrs.reserve(count);
                for (uint32_t ridx : idxs) {
                    auto it = refs.find(ridx);
                    if (it != refs.end() && it->second) ptrs.push_back(it->second.get());
                }
                if (!ptrs.empty()) {
                    auto t0 = Clock::now();
                    (void)graph->CountDistinctClusters(ptrs, static_cast<TxGraph::Level>(level_byte));
                    stats[opbyte].total_us += ElapsedUs(t0);
                    ++stats[opbyte].calls;
                }
            }
            break;
        }

        case TxGraphTraceOp::GET_MEMORY_USAGE: {
            auto t0 = Clock::now();
            (void)graph->GetMainMemoryUsage();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::GET_WORST_CHUNK: {
            auto t0 = Clock::now();
            (void)graph->GetWorstMainChunk();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::GET_DIAGRAMS: {
            auto t0 = Clock::now();
            (void)graph->GetMainStagingDiagrams();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::TRIM: {
            auto t0 = Clock::now();
            (void)graph->Trim();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::IS_OVERSIZED: {
            uint8_t level_byte{};
            if (!ReadBytes(f, &level_byte, 1)) goto eof_error;
            auto t0 = Clock::now();
            (void)graph->IsOversized(static_cast<TxGraph::Level>(level_byte));
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::EXISTS: {
            uint32_t idx{};
            uint8_t level_byte{};
            if (!ReadLE(f, idx) || !ReadBytes(f, &level_byte, 1)) goto eof_error;
            {
                auto it = refs.find(idx);
                if (it == refs.end() || !it->second) break;
                auto t0 = Clock::now();
                (void)graph->Exists(*it->second, static_cast<TxGraph::Level>(level_byte));
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::GET_INDIVIDUAL_FEERATE: {
            uint32_t idx{};
            if (!ReadLE(f, idx)) goto eof_error;
            {
                auto it = refs.find(idx);
                if (it == refs.end() || !it->second) break;
                auto t0 = Clock::now();
                (void)graph->GetIndividualFeerate(*it->second);
                stats[opbyte].total_us += ElapsedUs(t0);
                ++stats[opbyte].calls;
            }
            break;
        }

        case TxGraphTraceOp::GET_TX_COUNT: {
            uint8_t level_byte{};
            if (!ReadBytes(f, &level_byte, 1)) goto eof_error;
            auto t0 = Clock::now();
            (void)graph->GetTransactionCount(static_cast<TxGraph::Level>(level_byte));
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        // ----------------------------------------------------------
        // Staging (execute + time)
        // ----------------------------------------------------------
        case TxGraphTraceOp::START_STAGING: {
            auto t0 = Clock::now();
            graph->StartStaging();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::ABORT_STAGING: {
            auto t0 = Clock::now();
            graph->AbortStaging();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            break;
        }

        case TxGraphTraceOp::COMMIT_STAGING: {
            auto t0 = Clock::now();
            graph->CommitStaging();
            stats[opbyte].total_us += ElapsedUs(t0);
            ++stats[opbyte].calls;
            if (mem_csv && (stats[opbyte].calls - 1) % 100 == 0) {
                const size_t usage = graph->GetMainMemoryUsage();
                fprintf(mem_csv, "%llu,%zu\n", (unsigned long long)(stats[opbyte].calls - 1), usage);
                ++commit_count;
            }
            break;
        }

        default:
            fprintf(stderr, "Warning: unknown opcode 0x%02x, stopping\n", opbyte);
            goto done;
        }
    }
    goto done;

eof_error:
    fprintf(stderr, "Warning: unexpected EOF while reading payload\n");

done:
    fclose(f);
    if (mem_csv) {
        fclose(mem_csv);
        printf("Wrote %llu memory samples to CSV (every 100th COMMIT_STAGING)\n", (unsigned long long)commit_count);
    }

    // ------------------------------------------------------------------
    // Report (including TxGraph-internal memory via TotalMemoryUsage)
    // ------------------------------------------------------------------
    const size_t final_usage = graph->GetMainMemoryUsage();
    printf("\nTxGraph GetMainMemoryUsage (final): %zu bytes\n", final_usage);

    printf("\n=== TxGraph Replay Summary ===\n");
    printf("Total ops replayed: %llu\n", (unsigned long long)total_ops);

    printf("\nMutations (not timed):\n");
    printf("  %-28s %llu\n", "ADD_TX:", (unsigned long long)add_tx_count);
    printf("  %-28s %llu\n", "REMOVE_TX:", (unsigned long long)remove_tx_count);
    printf("  %-28s %llu\n", "ADD_DEP:", (unsigned long long)add_dep_count);
    printf("  %-28s %llu\n", "SET_FEE:", (unsigned long long)set_fee_count);
    printf("  %-28s %llu\n", "UNLINK_REF:", (unsigned long long)unlink_ref_count);

    printf("\nTimed entry points:\n");
    printf("  %-28s %12s %14s %14s\n", "Entry point", "Calls", "Total (us)", "Avg (us)");
    printf("  %-28s %12s %14s %14s\n", "---", "---", "---", "---");

    uint64_t grand_total_us{0};
    uint64_t grand_total_calls{0};

    for (size_t i = 0; i < NUM_OPS; ++i) {
        if (!stats[i].name || stats[i].calls == 0) continue;
        double avg = static_cast<double>(stats[i].total_us) / static_cast<double>(stats[i].calls);
        printf("  %-28s %12llu %14llu %14.2f\n",
               stats[i].name,
               (unsigned long long)stats[i].calls,
               (unsigned long long)stats[i].total_us,
               avg);
        grand_total_us += stats[i].total_us;
        grand_total_calls += stats[i].calls;
    }

    printf("  %-28s %12s %14s\n", "", "---", "---");
    printf("  %-28s %12llu %14llu\n", "TOTAL",
           (unsigned long long)grand_total_calls,
           (unsigned long long)grand_total_us);

    return 0;
}
