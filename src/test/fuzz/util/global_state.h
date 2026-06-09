// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_GLOBAL_STATE_H
#define BITCOIN_TEST_FUZZ_UTIL_GLOBAL_STATE_H

//! Detect global state that leaks between fuzz iterations.
//!
//! A fuzz target should behave the same no matter which inputs ran before it.
//! Mutable globals that survive one iteration and bleed into the next are a
//! source of fuzz instability and non-determinism (see issue #29018).
//!
//! This helper snapshots the writable, loaded ELF segments (essentially the
//! .data/.bss of the main program) and diffs them across iterations. Any byte
//! that differs from the previous baseline is reported, because it means some
//! global outlived a single input.
//!
//! Scope and blind spots: only writable PT_LOAD segments are covered. The heap,
//! stack, thread-local storage and shared memory are not part of any such
//! segment and are therefore invisible -- in particular a pointer stored in a
//! global is seen, but the heap object it points to is not.
namespace global_state {
//! Capture the baseline on the first call and re-baseline on each subsequent
//! one. Call at the start of every iteration, before the target runs.
void BeforeInput();
//! Diff the current memory against the baseline and print any drift to stderr.
//! Call after the target has run.
void Check();
} // namespace global_state

#endif // BITCOIN_TEST_FUZZ_UTIL_GLOBAL_STATE_H
