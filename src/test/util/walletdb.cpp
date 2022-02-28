// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/walletdb.h>

#ifdef USE_SQLITE
#  include <wallet/sqlite.h>
#elif USE_BDB
#  include <wallet/bdb.h>
#endif

std::unique_ptr<wallet::WalletDatabase> CreateMockWalletDatabase()
{
#ifdef USE_SQLITE
    return std::make_unique<wallet::SQLiteDatabase>("", "", true);
#elif USE_BDB
    return std::make_unique<wallet::BerkeleyDatabase>(std::make_shared<wallet::BerkeleyEnvironment>(), "");
#endif
}
