// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_WALLETDB_H
#define BITCOIN_TEST_UTIL_WALLETDB_H
#include <memory>
#include <string>

#include <wallet/db.h>

/** Return object for accessing temporary in-memory database. */
std::unique_ptr<wallet::WalletDatabase> CreateMockWalletDatabase();

#endif // BITCOIN_TEST_UTIL_WALLETDB_H
