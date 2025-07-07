// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <blockfilter.h>
#include <consensus/merkle.h>
#define private protected
#define final
#include <index/blockfilterindex.h>
#undef final
#undef private
#include <interfaces/chain.h>
#include <node/miner.h>
#include <pow.h>
#include <test/util/blockfilter.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <sync.h>

using node::BlockAssembler;
using node::CBlockTemplate;

BOOST_AUTO_TEST_SUITE(blockfilter_sync_reorg_tests)

struct BuildChainTestingSetup : public TestChain100Setup {
    CBlock CreateBlock(const CBlockIndex* prev, const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey);
    bool BuildChain(const CBlockIndex* pindex, const CScript& coinbase_script_pub_key, size_t length, std::vector<std::shared_ptr<CBlock>>& chain);
};

CBlock BuildChainTestingSetup::CreateBlock(const CBlockIndex* prev,
    const std::vector<CMutableTransaction>& txns,
    const CScript& scriptPubKey)
{
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock();
    CBlock& block = pblocktemplate->block;
    block.hashPrevBlock = prev->GetBlockHash();
    block.nTime = prev->nTime + 1;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    for (const CMutableTransaction& tx : txns) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    {
        CMutableTransaction tx_coinbase{*block.vtx.at(0)};
        tx_coinbase.nLockTime = static_cast<uint32_t>(prev->nHeight);
        tx_coinbase.vin.at(0).scriptSig = CScript{} << prev->nHeight + 1;
        block.vtx.at(0) = MakeTransactionRef(std::move(tx_coinbase));
        block.hashMerkleRoot = BlockMerkleRoot(block);
    }

    while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;

    return block;
}

bool BuildChainTestingSetup::BuildChain(const CBlockIndex* pindex,
    const CScript& coinbase_script_pub_key,
    size_t length,
    std::vector<std::shared_ptr<CBlock>>& chain)
{
    std::vector<CMutableTransaction> no_txns;

    chain.resize(length);
    for (auto& block : chain) {
        block = std::make_shared<CBlock>(CreateBlock(pindex, no_txns, coinbase_script_pub_key));
        CBlockHeader header = block->GetBlockHeader();

        BlockValidationState state;
        if (!Assert(m_node.chainman)->ProcessNewBlockHeaders({{header}}, true, state, &pindex)) {
            return false;
        }
    }

    return true;
}

static const CBlockIndex* NextSyncBlock(const CBlockIndex* pindex_prev, CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    if (!pindex_prev) {
        return chain.Genesis();
    }

    const CBlockIndex* pindex = chain.Next(pindex_prev);
    if (pindex) {
        return pindex;
    }

    // Since block is not in the chain, return the next block in the chain AFTER the last common ancestor.
    // Caller will be responsible for rewinding back to the common ancestor.
    return chain.Next(chain.FindFork(pindex_prev));
}

constexpr auto SYNC_LOG_INTERVAL{30s};
constexpr auto SYNC_LOCATOR_WRITE_INTERVAL{3600s};

class TestBlockFilterIndex : public BlockFilterIndex {
public:
    TestBlockFilterIndex(std::unique_ptr<interfaces::Chain> chain, BlockFilterType filter_type, size_t n_cache_size, bool f_memory = false, bool f_wipe = false)
    : BlockFilterIndex(std::move(chain), filter_type, n_cache_size, f_memory, f_wipe) {}

    void Sync(int height, Mutex& mtx, std::condition_variable& master_cv, std::condition_variable& sync_cv, std::atomic<bool>& reorg_done, std::atomic<bool>& wait_for_reorg);
};

void TestBlockFilterIndex::Sync(int height, Mutex& mtx, std::condition_variable& master_cv, std::condition_variable& sync_cv, std::atomic<bool>& reorg_done, std::atomic<bool>& wait_for_reorg)
{
    const CBlockIndex* pindex = m_best_block_index.load();
    if (!m_synced) {
        std::chrono::steady_clock::time_point last_log_time{0s};
        std::chrono::steady_clock::time_point last_locator_write_time{0s};
        while (true) {
            if (pindex && pindex->nHeight == height) {
                WAIT_LOCK(mtx, lock);
                wait_for_reorg = true;
                master_cv.notify_one();
                sync_cv.wait(lock, [&reorg_done] { return reorg_done.load(); });
            }

            if (m_interrupt) {
                LogPrintf("%s: m_interrupt set; exiting ThreadSync\n", GetName());

                SetBestBlockIndex(pindex);
                // No need to handle errors in Commit. If it fails, the error will be already be
                // logged. The best way to recover is to continue, as index cannot be corrupted by
                // a missed commit to disk for an advanced index state.
                Commit();
                return;
            }

            const CBlockIndex* pindex_next = WITH_LOCK(cs_main, return NextSyncBlock(pindex, m_chainstate->m_chain));
            // If pindex_next is null, it means pindex is the chain tip, so
            // commit data indexed so far.
            if (!pindex_next) {
                SetBestBlockIndex(pindex);
                // No need to handle errors in Commit. See rationale above.
                Commit();

                // If pindex is still the chain tip after committing, exit the
                // sync loop. It is important for cs_main to be locked while
                // setting m_synced = true, otherwise a new block could be
                // attached while m_synced is still false, and it would not be
                // indexed.
                LOCK(::cs_main);
                pindex_next = NextSyncBlock(pindex, m_chainstate->m_chain);
                if (!pindex_next) {
                    m_synced = true;
                    break;
                }
            }

            if (pindex_next->pprev != pindex && !Rewind(pindex, pindex_next->pprev)) {
                FatalErrorf("%s: Failed to rewind index %s to a previous chain tip", __func__, GetName());
                return;
            }
            pindex = pindex_next;


            if (!ProcessBlock(pindex)) return; // error logged internally

            auto current_time{std::chrono::steady_clock::now()};
            if (last_log_time + SYNC_LOG_INTERVAL < current_time) {
                LogPrintf("Syncing %s with block chain from height %d\n",
                        GetName(), pindex->nHeight);
                last_log_time = current_time;
            }

            if (last_locator_write_time + SYNC_LOCATOR_WRITE_INTERVAL < current_time) {
                SetBestBlockIndex(pindex);
                last_locator_write_time = current_time;
                // No need to handle errors in Commit. See rationale above.
                Commit();
            }
        }
    }

    if (pindex) {
        LogPrintf("%s is enabled at height %d\n", GetName(), pindex->nHeight);
    } else {
        LogPrintf("%s is enabled\n", GetName());
    }
}

BOOST_FIXTURE_TEST_CASE(blockfilter_index_sync_reorg, BuildChainTestingSetup)
{
    TestBlockFilterIndex filter_index(interfaces::MakeChain(m_node), BlockFilterType::BASIC, 1 << 20, true);
    BOOST_REQUIRE(filter_index.Init());

    int pause_height = COINBASE_MATURITY - 3;
    std::vector<CBlockIndex*> un_indexed;
    auto& chain = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain());
    for (int i = pause_height + 1; i <= chain.Height(); i++) {
        un_indexed.push_back(chain[i]);
    }

    Mutex mtx;
    std::condition_variable master_cv, sync_cv;
    std::atomic<bool> reorg_done{false}, wait_for_reorg{false};
    std::thread sync_thread([&] { filter_index.Sync(pause_height, mtx, master_cv, sync_cv, reorg_done, wait_for_reorg); });

    {
        WAIT_LOCK(mtx, lock);
        master_cv.wait(lock, [&] { return wait_for_reorg.load(); });
    }

    // reorg
    const CBlockIndex* forki;
    {
        LOCK(cs_main);
        forki = m_node.chainman->ActiveChain()[pause_height-1];
    }
    CKey coinbase_key_A = GenerateRandomKey();
    CScript coinbase_script_pub_key_A = GetScriptForDestination(PKHash(coinbase_key_A.GetPubKey()));
    std::vector<std::shared_ptr<CBlock>> chainA;
    BOOST_REQUIRE(BuildChain(forki, coinbase_script_pub_key_A, 5, chainA));

    for (size_t i = 0; i < 5; i++) {
        const auto& block = chainA[i];
        BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(block, true, true, nullptr));
    }

    {
        WAIT_LOCK(mtx, lock);
        reorg_done = true;
        sync_cv.notify_one();
    }

    sync_thread.join();

    {
        LOCK(cs_main);

        BlockFilter filter;
        for (auto& block_index : un_indexed)
            BOOST_CHECK(!filter_index.LookupFilter(block_index, filter));
        for (size_t i = 0; i < 5; i++) {
            const auto& block = chainA[i];
            auto block_index = m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash());
            BOOST_CHECK(filter_index.LookupFilter(block_index, filter));
        }
    }

    filter_index.Interrupt();
    filter_index.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
