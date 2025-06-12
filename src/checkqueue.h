// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <logging.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/threadnames.h>

#include <algorithm>
#include <iterator>
#include <optional>
#include <vector>

template <typename T, typename R = std::remove_cvref_t<decltype(std::declval<T>()().value())>>
class CCheckQueue;

template <typename T, typename R = std::remove_cvref_t<decltype(std::declval<T>()().value())>>
class CWorker {
private:
    CCheckQueue<T, R> *cqueue;
    //! Mutex to protect the inner state
    Mutex m_mutex;

    int id;
    //! Worker threads block on this when out of work
    std::condition_variable m_worker_cv;

    //! The queue of elements to be processed.
    //! As the order of booleans doesn't matter, it is used as a LIFO (stack)
    std::vector<T> queue GUARDED_BY(m_mutex);
    bool m_pool_destroy{false} GUARDED_BY(m_mutex);
    bool m_master_on{false} GUARDED_BY(m_mutex);
    unsigned int done{0};

    /**
     * the result turned out, finish verification
     * use atomic rather than protect in m_mutex to avoid ABBA deadlock
     */
    std::atomic<bool> m_finish{false};

    std::thread m_worker_thread;

    //! The maximum number of elements to be processed in one batch
    const unsigned int nBatchSize;


    /** Internal function that does bulk of the verification work. */
    void Worker() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::vector<T> vChecks;
        vChecks.reserve(nBatchSize*10);
        unsigned int nNow = 0;
        std::optional<R> local_result;
        bool do_work;

        do {
            {
                WAIT_LOCK(m_mutex, lock);
                if (nNow) {
                    done += nNow;
                    if (local_result.has_value()) {
                        LOCK(cqueue->m_result_lock);
                        if (!cqueue->m_result.has_value()) {
                            cqueue->SetFinish();
                            std::swap(local_result, cqueue->m_result);
                        }
                    }
                }


                if (queue.empty() && m_master_on) {
                    cqueue->IncrementDone(done);
                    done = 0;
                }
                // first do the clean-up of the previous loop run (allowing us to do it in the same critsect)
                // logically, the do loop starts here
                while (queue.empty() && !m_pool_destroy) {
                    m_worker_cv.wait(lock); // wait
                }

                if (m_pool_destroy) {
                    // return value does not matter, because m_pool_destroy is only set in the destructor.
                    return;
                }

                // Check whether we need to do work at all
                do_work = !m_finish;
                nNow = queue.size();
                if (do_work) {
                    // Decide how many work units to process now.
                    // * Do not try to do everything at once, but aim for increasingly smaller batches so
                    //   all workers finish approximately simultaneously.
                    // * Try to account for idle jobs which will instantly start helping.
                    // * Don't do batches smaller than 1 (duh), or larger than nBatchSize.
                    vChecks.assign(std::make_move_iterator(queue.begin()), std::make_move_iterator(queue.end()));
                }
                queue.clear();
            }
            // execute work
            if (do_work) {
                for (T& check : vChecks) {
                    local_result = check();
                    if (local_result.has_value()) break;
                }
                vChecks.clear();
            }
        } while (true);
    }

public:
//    CWorker(CWorker&&) = default;
//    CWorker& operator=(CWorker&&) = default;
    CWorker(int worker_index, unsigned int batch_size, CCheckQueue<T, R> *cq): cqueue(cq), nBatchSize(batch_size)
    {
        id = worker_index;
        m_worker_thread = std::thread([this, worker_index]() {
            util::ThreadRename(strprintf("scriptch.%i", worker_index));
            Worker();
        });
    }

    void Add(std::vector<T>&& vChecks) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        queue.insert(queue.end(), std::make_move_iterator(vChecks.begin()), std::make_move_iterator(vChecks.end()));
    }

    void Notify() {
        m_worker_cv.notify_one();
    }

    void Join() {
        m_worker_thread.join();
    }

    void MarkFinish() {
        m_finish = true;
    }

    void CleanFinish() {
        m_finish = false;
    }

    // m_mutex required
    void MarkPoolDestroy() {
        WITH_LOCK(m_mutex, m_pool_destroy = true);
    }

    // m_mutex required
    void MarkMasterOn() {
        {
            LOCK(m_mutex);
            m_master_on = true;
        }
        Notify();
    }

    void MarkMasterOff() {
        LOCK(m_mutex);
        m_master_on = false;
    }
};

/**
 * Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning an std::optional<R>.
  *
  * The overall result of the computation is std::nullopt if all invocations
  * return std::nullopt, or one of the other results otherwise.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  *
  */
template <typename T, typename R>
class CCheckQueue
{
private:
    Mutex m_mutex;
    unsigned int nTodo{0};
    //! Master thread blocks on this when out of work
    std::condition_variable m_master_cv;

    /**
     * Point to the worker index in m_workers, no need to lock it since there is
     * only one producer
     */
    unsigned int next_worker{0};

    std::vector<std::unique_ptr<CWorker<T, R>>> m_workers;

public:
    Mutex m_result_lock;
    //! The temporary evaluation result.
    std::optional<R> m_result;

    //! Mutex to ensure only one concurrent CCheckQueueControl
    Mutex m_control_mutex;

    //! Create a new check queue
    explicit CCheckQueue(unsigned int batch_size, int worker_threads_num) {
        LogInfo("Script verification uses %d additional threads", worker_threads_num);
        m_workers.reserve(worker_threads_num);
        for (int n = 0; n < worker_threads_num; ++n) {
            m_workers.emplace_back(std::make_unique<CWorker<T, R>>(n, batch_size, this));
        }
    }

    // Since this class manages its own resources, which is a thread
    // pool `m_worker_threads`, copy and move operations are not appropriate.
    CCheckQueue(const CCheckQueue&) = delete;
    CCheckQueue& operator=(const CCheckQueue&) = delete;
    CCheckQueue(CCheckQueue&&) = delete;
    CCheckQueue& operator=(CCheckQueue&&) = delete;

    //! Join the execution until completion. If at least one evaluation wasn't successful, return
    //! its error.
    std::optional<R> Complete() {
        for (auto& w : m_workers)
            w->MarkMasterOn();

        while (true) {
            WAIT_LOCK(m_mutex, lock);
            if (!nTodo) {
                for (auto& w : m_workers) {
                    w->CleanFinish();
                    w->MarkMasterOff();
                }

                LOCK(m_result_lock);
                std::optional<R> to_return = std::move(m_result);
                // reset the status for new work later
                m_result = std::nullopt;
                // return the current status
                return to_return;
            }

            m_master_cv.wait(lock);
        }
    }

    //! Add a batch of checks to the queue
    // no support for concurrent Add for now, since no lock for m_workers
    void Add(std::vector<T>&& vChecks)
    {
        if (vChecks.empty()) {
            return;
        }

        WITH_LOCK(m_mutex, nTodo += vChecks.size());
        auto& worker = m_workers[next_worker];
        next_worker = (next_worker + 1) % m_workers.size();
        worker->Add(std::move(vChecks));
        worker->Notify();
    }

    ~CCheckQueue()
    {
        for (auto& w : m_workers) {
            w->MarkPoolDestroy();
            w->Notify();
        }

        for (auto& w : m_workers) {
            w->Join();
        }
    }

    bool HasThreads() const { return !m_workers.empty(); }
    void SetFinish() {
        for (auto &w : m_workers) {
            w->MarkFinish();
        }
    }

    void Notify() {
        m_master_cv.notify_one();
    }

    void IncrementDone(unsigned int done) {
        LOCK(m_mutex);
        nTodo -= done;
        if (!nTodo) Notify();
    }
};

/**
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename T, typename R = std::remove_cvref_t<decltype(std::declval<T>()().value())>>
class SCOPED_LOCKABLE CCheckQueueControl
{
private:
    CCheckQueue<T, R>& m_queue;
    UniqueLock<Mutex> m_lock;
    bool fDone;

public:
    CCheckQueueControl() = delete;
    CCheckQueueControl(const CCheckQueueControl&) = delete;
    CCheckQueueControl& operator=(const CCheckQueueControl&) = delete;
    explicit CCheckQueueControl(CCheckQueue<T>& queueIn) EXCLUSIVE_LOCK_FUNCTION(queueIn.m_control_mutex) : m_queue(queueIn), m_lock(LOCK_ARGS(queueIn.m_control_mutex)), fDone(false) {}

    std::optional<R> Complete()
    {
        auto ret = m_queue.Complete();
        fDone = true;
        return ret;
    }

    void Add(std::vector<T>&& vChecks)
    {
        m_queue.Add(std::move(vChecks));
    }

    ~CCheckQueueControl() UNLOCK_FUNCTION()
    {
        if (!fDone)
            Complete();
    }
};

#endif // BITCOIN_CHECKQUEUE_H
