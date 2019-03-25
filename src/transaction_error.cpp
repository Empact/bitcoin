// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <transaction_error.h>

#include <cassert>

std::string TransactionErrorString(const TransactionError err)
{
    switch (err) {
        case TransactionError::OK:
            return "No error";
        case TransactionError::MISSING_INPUTS:
            return "Missing inputs";
        case TransactionError::ALREADY_IN_CHAIN:
            return "Transaction already in block chain";
        case TransactionError::P2P_DISABLED:
            return "Peer-to-peer functionality missing or disabled";
        case TransactionError::MEMPOOL_REJECTED:
            return "Transaction rejected by AcceptToMemoryPool";
        case TransactionError::MEMPOOL_ERROR:
            return "AcceptToMemoryPool failed";
        case TransactionError::INVALID_PSBT:
            return "PSBT is not sane";
        case TransactionError::PSBT_MISMATCH:
            return "PSBTs not compatible (different transactions)";
        case TransactionError::SIGHASH_MISMATCH:
            return "Specified sighash value does not match existing value";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}
