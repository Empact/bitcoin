// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_WALLET_DATABASE_H
#define BITCOIN_INTERFACES_WALLET_DATABASE_H

#include <string>
#include <vector>

class CWallet;
class CWalletTx;
class uint256;

/** Error statuses for the wallet database */
enum class DBErrors
{
    LOAD_OK,
    CORRUPT,
    NONCRITICAL_ERROR,
    TOO_NEW,
    LOAD_FAIL,
    NEED_REWRITE
};

namespace interfaces {

  //! Interface for accessing a wallet database.
  class WalletDatabaseBatch
  {
  public:
      virtual ~WalletDatabaseBatch() {}

      template <typename K, typename T>
      bool Write(const K& key, const T& value, bool fOverwrite = true);

      template <typename K>
      bool Erase(const K& key);

      template <typename K, typename T>
      bool Read(const K& key, T& value);

      DBErrors FindWalletTx(std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
      DBErrors LoadWallet(CWallet* pwallet);

      // virtual bool TxnBegin() = 0;
      // virtual bool TxnCommit() = 0;
      // virtual bool TxnAbort() = 0;
  };

  //! Interface for accessing a wallet database.
  class WalletDatabase
  {
  public:
      virtual ~WalletDatabase() {}

      virtual void PeriodicallyCompact() = 0;
      virtual void IncrementUpdateCounter() = 0;
      virtual bool Rewrite(const char* skip = nullptr) = 0;
      virtual void Flush(bool shutdown) = 0;
      virtual bool Backup(const std::string& strDest) = 0;

      virtual WalletDatabaseBatch Batch(const char* pszMode, bool fFlushOnCloseIn) = 0;
  };

} // namespace interfaces

#endif // BITCOIN_INTERFACES_WALLET_DATABASE_H
