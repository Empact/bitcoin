// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BDB_H
#define BITCOIN_WALLET_BDB_H

#include <clientversion.h>
#include <fs.h>
#include <serialize.h>
#include <streams.h>
#include <util/system.h>
#include <wallet/db.h>

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-override"
#endif
#include <db_cxx.h>
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

struct bilingual_str;

static const unsigned int DEFAULT_WALLET_DBLOGSIZE = 100;
static const bool DEFAULT_WALLET_PRIVDB = true;

struct WalletDatabaseFileId {
    u_int8_t value[DB_FILE_ID_LEN];
    bool operator==(const WalletDatabaseFileId& rhs) const;
};

class BerkeleyDatabase;

class BerkeleyEnvironment
{
private:
    bool fDbEnvInit;
    bool fMockDb;
    // Don't change into fs::path, as that can result in
    // shutdown problems/crashes caused by a static initialized internal pointer.
    std::string strPath;

public:
    std::unique_ptr<DbEnv> dbenv;
    std::map<std::string, std::reference_wrapper<BerkeleyDatabase>> m_databases;
    std::condition_variable_any m_db_in_use;

    BerkeleyEnvironment(const fs::path& env_directory);
    BerkeleyEnvironment();
    ~BerkeleyEnvironment();
    void Reset();

    bool IsMock() const { return fMockDb; }
    bool IsInitialized() const { return fDbEnvInit; }
    bool IsDatabaseLoaded(const std::string& db_filename) const { return m_databases.find(db_filename) != m_databases.end(); }
    fs::path Directory() const { return strPath; }

    bool Verify(const std::string& strFile);
    /**
     * Salvage data from a file that Verify says is bad.
     * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
     * Appends binary key/value pairs to vResult, returns true if successful.
     * NOTE: reads the entire database into memory, so cannot be used
     * for huge databases.
     */
    typedef std::pair<std::vector<unsigned char>, std::vector<unsigned char> > KeyValPair;
    bool Salvage(const std::string& strFile, bool fAggressive, std::vector<KeyValPair>& vResult);

    bool Open(bool retry);
    void Close();
    void Flush();
    void CheckpointLSN(const std::string& strFile);

    void CloseDb(const std::string& strFile);
    void ReloadDbEnv();

    DbTxn* TxnBegin(int flags = DB_TXN_WRITE_NOSYNC)
    {
        DbTxn* ptxn = nullptr;
        int ret = dbenv->txn_begin(nullptr, &ptxn, flags);
        if (!ptxn || ret != 0)
            return nullptr;
        return ptxn;
    }
};

/** Get BerkeleyEnvironment and database filename given a wallet path. */
std::shared_ptr<BerkeleyEnvironment> GetWalletEnv(const fs::path& wallet_path, std::string& database_filename);

bool IsBDBWalletLoaded(const fs::path& wallet_path);

/** An instance of this class represents one database.
 * For BerkeleyDB this is just a (env, strFile) tuple.
 **/
class BerkeleyDatabase : public WalletDatabase
{
private:
    /** RAII class that automatically cleanses its data on destruction */
    class SafeDbt final
    {
        Dbt m_dbt;

    public:
        // construct Dbt with internally-managed data
        SafeDbt();
        // construct Dbt with provided data
        SafeDbt(void* data, size_t size);
        ~SafeDbt();

        // delegate to Dbt
        const void* get_data() const;
        u_int32_t get_size() const;

        // conversion operator to access the underlying Dbt
        operator Dbt*();
    };

    bool m_read_only = false;

    Dbc* m_cursor = nullptr;
    DbTxn* m_active_txn = nullptr;

    /**
     * Pointer to shared database environment.
     *
     * Normally there is only one BerkeleyDatabase object per
     * BerkeleyEnvivonment, but in the special, backwards compatible case where
     * multiple wallet BDB data files are loaded from the same directory, this
     * will point to a shared instance that gets freed when the last data file
     * is closed.
     */
    std::shared_ptr<BerkeleyEnvironment> env;

    std::string strFile;
    std::string m_file_path;

    /** Return whether this database handle is a dummy for testing.
     * Only to be used at a low level, application should ideally not care
     * about this.
     */
    bool IsDummy() const { return env == nullptr; }

    bool DBRead(CDataStream& key, CDataStream& value) const override;
    bool DBWrite(CDataStream& key, CDataStream& value, bool overwrite=true) const override;
    bool DBErase(CDataStream& key) const override;
    bool DBExists(CDataStream& key) const override;

public:
    /** Create dummy DB handle */
    BerkeleyDatabase() : WalletDatabase(), env(nullptr)
    {
    }

    /** Create DB handle to real database */
    BerkeleyDatabase(std::shared_ptr<BerkeleyEnvironment> env, std::string filename) :
        WalletDatabase(), env(std::move(env)), strFile(std::move(filename))
    {
        auto inserted = this->env->m_databases.emplace(strFile, std::ref(*this));
        assert(inserted.second);
    }

    ~BerkeleyDatabase();

    /** Database pointer. This is initialized lazily and reset during flushes, so it can be null. */
    std::unique_ptr<Db> m_db;


    /** Open the database if it is not already opened */
    void Open(const char* mode) override;

    /** Close the database */
    void Close() override;

    /** Indicate the a new database user has began using the database. Increments m_refcount */
    void Acquire() override;
    /** Indicate that database user has stopped using the database. Decrement m_refcount */
    void Release() override;

    /** Rewrite the entire database on disk, with the exception of key pszSkip if non-zero
     */
    bool Rewrite(const char* pszSkip=nullptr) override;

    /** Back up the entire database to a file.
     */
    bool Backup(const std::string& strDest) const override;

    /** Make sure all changes are flushed to disk.
     */
    void Flush() override;
    /* flush the wallet passively (TRY_LOCK)
       ideal to be called periodically */
    bool PeriodicFlush() override;

    void ReloadDbEnv() override;

    /* verifies the environment and database file */
    bool Verify(std::vector<bilingual_str>& warnings, bilingual_str& errorStr) override;

    bool CreateCursor() override
    {
        if (!m_db)
            return false;
        m_cursor = nullptr;
        int ret = m_db->cursor(nullptr, &m_cursor, 0);
        if (ret != 0)
            return false;
        return true;
    }

    bool ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete) override
    {
        complete = false;
        if (m_cursor == nullptr) return false;
        // Read at cursor
        SafeDbt datKey;
        SafeDbt datValue;
        int ret = m_cursor->get(datKey, datValue, DB_NEXT);
        if (ret == DB_NOTFOUND) {
            complete = true;
        }
        if (ret != 0)
            return false;
        else if (datKey.get_data() == nullptr || datValue.get_data() == nullptr)
            return false;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());
        return true;
    }

    void CloseCursor() override
    {
        m_cursor->close();
        m_cursor = nullptr;
    }

    bool TxnBegin() override
    {
        if (!m_db || m_active_txn)
            return false;
        DbTxn* ptxn = env->TxnBegin();
        if (!ptxn)
            return false;
        m_active_txn = ptxn;
        return true;
    }

    bool TxnCommit() override
    {
        if (!m_db || !m_active_txn)
            return false;
        int ret = m_active_txn->commit(0);
        m_active_txn = nullptr;
        return (ret == 0);
    }

    bool TxnAbort() override
    {
        if (!m_db || !m_active_txn)
            return false;
        int ret = m_active_txn->abort();
        m_active_txn = nullptr;
        return (ret == 0);
    }
};

std::string BerkeleyDatabaseVersion();

#endif // BITCOIN_WALLET_BDB_H
