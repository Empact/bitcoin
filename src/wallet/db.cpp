// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/db.h>

#include <util/strencodings.h>
#include <util/translation.h>

#include <stdint.h>

#ifndef WIN32
#include <sys/stat.h>
#endif

#include <boost/thread.hpp>

namespace {

//! Make sure database has a unique fileid within the environment. If it
//! doesn't, throw an error. BDB caches do not work properly when more than one
//! open database has the same fileid (values written to one database may show
//! up in reads to other databases).
//!
//! BerkeleyDB generates unique fileids by default
//! (https://docs.oracle.com/cd/E17275_01/html/programmer_reference/program_copy.html),
//! so bitcoin should never create different databases with the same fileid, but
//! this error can be triggered if users manually copy database files.
std::unordered_map<std::string, WalletDatabaseFileId> g_fileids;

RecursiveMutex cs_db;
std::map<std::string, std::weak_ptr<BerkeleyEnvironment>> g_dbenvs GUARDED_BY(cs_db); //!< Map from directory name to db environment.
} // namespace

bool WalletDatabaseFileId::operator==(const WalletDatabaseFileId& rhs) const
{
    return memcmp(value, &rhs.value, sizeof(value)) == 0;
}

static void SplitWalletPath(const fs::path& wallet_path, fs::path& env_directory, std::string& database_filename)
{
    if (fs::is_regular_file(wallet_path)) {
        // Special case for backwards compatibility: if wallet path points to an
        // existing file, treat it as the path to a BDB data file in a parent
        // directory that also contains BDB log files.
        env_directory = wallet_path.parent_path();
        database_filename = wallet_path.filename().string();
    } else {
        // Normal case: Interpret wallet path as a directory path containing
        // data and log files.
        env_directory = wallet_path;
        database_filename = "wallet.dat";
    }
}

bool IsWalletLoaded(const fs::path& wallet_path)
{
    fs::path env_directory;
    std::string database_filename;
    SplitWalletPath(wallet_path, env_directory, database_filename);
    LOCK(cs_db);
    auto env = g_dbenvs.find(env_directory.string());
    if (env == g_dbenvs.end()) return false;
    auto database = env->second.lock();
    return database && database->IsDatabaseLoaded(database_filename);
}

fs::path WalletDataFilePath(const fs::path& wallet_path)
{
    fs::path env_directory;
    std::string database_filename;
    SplitWalletPath(wallet_path, env_directory, database_filename);
    return env_directory / database_filename;
}

/**
 * @param[in] wallet_path Path to wallet directory. Or (for backwards compatibility only) a path to a berkeley btree data file inside a wallet directory.
 * @param[out] database_filename Filename of berkeley btree data file inside the wallet directory.
 * @return A shared pointer to the BerkeleyEnvironment object for the wallet directory, never empty because ~BerkeleyEnvironment
 * erases the weak pointer from the g_dbenvs map.
 * @post A new BerkeleyEnvironment weak pointer is inserted into g_dbenvs if the directory path key was not already in the map.
 */
std::shared_ptr<BerkeleyEnvironment> GetWalletEnv(const fs::path& wallet_path, std::string& database_filename)
{
    fs::path env_directory;
    SplitWalletPath(wallet_path, env_directory, database_filename);
    LOCK(cs_db);
    auto inserted = g_dbenvs.emplace(env_directory.string(), std::weak_ptr<BerkeleyEnvironment>());
    if (inserted.second) {
        auto env = std::make_shared<BerkeleyEnvironment>(env_directory.string());
        inserted.first->second = env;
        return env;
    }
    return inserted.first->second.lock();
}

void BerkeleyEnvironment::Close()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;

    for (auto& db : m_databases) {
        BerkeleyDatabase& database = db.second.get();
        assert(database.m_refcount == 0);
        if (database.m_db) {
            database.m_db->close(0);
            database.m_db.reset();
        }
    }

    char** listp;
    dbenv->log_archive(&listp, DB_ARCH_REMOVE);

    FILE* error_file = nullptr;
    dbenv->get_errfile(&error_file);

    int ret = dbenv->close(0);
    if (ret != 0)
        LogPrintf("BerkeleyEnvironment::Close: Error %d closing database environment: %s\n", ret, DbEnv::strerror(ret));
    if (!fMockDb) {
        DbEnv((u_int32_t)0).remove(strPath.c_str(), 0);
        fs::remove_all(fs::path(strPath) / "database");
    }

    if (error_file) fclose(error_file);

    UnlockDirectory(strPath, ".walletlock");
}

void BerkeleyEnvironment::Reset()
{
    dbenv.reset(new DbEnv(DB_CXX_NO_EXCEPTIONS));
    fDbEnvInit = false;
    fMockDb = false;
}

BerkeleyEnvironment::BerkeleyEnvironment(const fs::path& dir_path) : strPath(dir_path.string())
{
    Reset();
}

BerkeleyEnvironment::~BerkeleyEnvironment()
{
    LOCK(cs_db);
    g_dbenvs.erase(strPath);
    Close();
}

bool BerkeleyEnvironment::Open(bool retry)
{
    if (fDbEnvInit) {
        return true;
    }

    fs::path pathIn = strPath;
    TryCreateDirectories(pathIn);
    if (!LockDirectory(pathIn, ".walletlock")) {
        LogPrintf("Cannot obtain a lock on wallet directory %s. Another instance of bitcoin may be using it.\n", strPath);
        return false;
    }

    fs::path pathLogDir = pathIn / "database";
    TryCreateDirectories(pathLogDir);
    fs::path pathErrorFile = pathIn / "db.log";
    LogPrintf("BerkeleyEnvironment::Open: LogDir=%s ErrorFile=%s\n", pathLogDir.string(), pathErrorFile.string());

    unsigned int nEnvFlags = 0;
    if (gArgs.GetBoolArg("-privdb", DEFAULT_WALLET_PRIVDB))
        nEnvFlags |= DB_PRIVATE;

    dbenv->set_lg_dir(pathLogDir.string().c_str());
    dbenv->set_cachesize(0, 0x100000, 1); // 1 MiB should be enough for just the wallet
    dbenv->set_lg_bsize(0x10000);
    dbenv->set_lg_max(1048576);
    dbenv->set_lk_max_locks(40000);
    dbenv->set_lk_max_objects(40000);
    dbenv->set_errfile(fsbridge::fopen(pathErrorFile, "a")); /// debug
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->set_flags(DB_TXN_WRITE_NOSYNC, 1);
    dbenv->log_set_config(DB_LOG_AUTO_REMOVE, 1);
    int ret = dbenv->open(strPath.c_str(),
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_RECOVER |
                             nEnvFlags,
                         S_IRUSR | S_IWUSR);
    if (ret != 0) {
        LogPrintf("BerkeleyEnvironment::Open: Error %d opening database environment: %s\n", ret, DbEnv::strerror(ret));
        int ret2 = dbenv->close(0);
        if (ret2 != 0) {
            LogPrintf("BerkeleyEnvironment::Open: Error %d closing failed database environment: %s\n", ret2, DbEnv::strerror(ret2));
        }
        Reset();
        if (retry) {
            // try moving the database env out of the way
            fs::path pathDatabaseBak = pathIn / strprintf("database.%d.bak", GetTime());
            try {
                fs::rename(pathLogDir, pathDatabaseBak);
                LogPrintf("Moved old %s to %s. Retrying.\n", pathLogDir.string(), pathDatabaseBak.string());
            } catch (const fs::filesystem_error&) {
                // failure is ok (well, not really, but it's not worse than what we started with)
            }
            // try opening it again one more time
            if (!Open(false /* retry */)) {
                // if it still fails, it probably means we can't even create the database env
                return false;
            }
        } else {
            return false;
        }
    }

    fDbEnvInit = true;
    fMockDb = false;
    return true;
}

//! Construct an in-memory mock Berkeley environment for testing
BerkeleyEnvironment::BerkeleyEnvironment()
{
    Reset();

    LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::MakeMock\n");

    dbenv->set_cachesize(1, 0, 1);
    dbenv->set_lg_bsize(10485760 * 4);
    dbenv->set_lg_max(10485760);
    dbenv->set_lk_max_locks(10000);
    dbenv->set_lk_max_objects(10000);
    dbenv->set_flags(DB_AUTO_COMMIT, 1);
    dbenv->log_set_config(DB_LOG_IN_MEMORY, 1);
    int ret = dbenv->open(nullptr,
                         DB_CREATE |
                             DB_INIT_LOCK |
                             DB_INIT_LOG |
                             DB_INIT_MPOOL |
                             DB_INIT_TXN |
                             DB_THREAD |
                             DB_PRIVATE,
                         S_IRUSR | S_IWUSR);
    if (ret > 0) {
        throw std::runtime_error(strprintf("BerkeleyEnvironment::MakeMock: Error %d opening database environment.", ret));
    }

    fDbEnvInit = true;
    fMockDb = true;
}

bool BerkeleyEnvironment::Verify(const std::string& strFile)
{
    Db db(dbenv.get(), 0);
    int result = db.verify(strFile.c_str(), nullptr, nullptr, 0);
    return result == 0;
}

BerkeleyDatabase::SafeDbt::SafeDbt()
{
    m_dbt.set_flags(DB_DBT_MALLOC);
}

BerkeleyDatabase::SafeDbt::SafeDbt(void* data, size_t size)
    : m_dbt(data, size)
{
}

BerkeleyDatabase::SafeDbt::~SafeDbt()
{
    if (m_dbt.get_data() != nullptr) {
        // Clear memory, e.g. in case it was a private key
        memory_cleanse(m_dbt.get_data(), m_dbt.get_size());
        // under DB_DBT_MALLOC, data is malloced by the Dbt, but must be
        // freed by the caller.
        // https://docs.oracle.com/cd/E17275_01/html/api_reference/C/dbt.html
        if (m_dbt.get_flags() & DB_DBT_MALLOC) {
            free(m_dbt.get_data());
        }
    }
}

const void* BerkeleyDatabase::SafeDbt::get_data() const
{
    return m_dbt.get_data();
}

u_int32_t BerkeleyDatabase::SafeDbt::get_size() const
{
    return m_dbt.get_size();
}

BerkeleyDatabase::SafeDbt::operator Dbt*()
{
    return &m_dbt;
}

bool BerkeleyDatabase::Verify(std::vector<bilingual_str>& warnings, bilingual_str& errorStr)
{
    fs::path walletDir = env->Directory();

    LogPrintf("Using BerkeleyDB version %s\n", BerkeleyDatabaseVersion());
    LogPrintf("Using wallet %s\n", walletDir.string());

    if (!env->Open(true /* retry */)) {
        errorStr = strprintf(_("Error initializing wallet database environment %s!"), walletDir);
        return false;
    }

    if (fs::exists(walletDir / strFile))
    {
        assert(m_refcount == 0);

        std::string backup_filename;
        if (!env->Verify(strFile)) {
            errorStr = strprintf(_("%s corrupt. Try using the wallet tool bitcoin-wallet to salvage"), strFile);
            return false;
        }
    }
    // also return true if files does not exists
    return true;
}

void BerkeleyEnvironment::CheckpointLSN(const std::string& strFile)
{
    dbenv->txn_checkpoint(0, 0, 0);
    if (fMockDb)
        return;
    dbenv->lsn_reset(strFile.c_str(), 0);
}

BerkeleyDatabase::~BerkeleyDatabase()
{
    Close();
    if (env) {
        LOCK(cs_db);
        size_t erased = env->m_databases.erase(strFile);
        assert(erased == 1);
        g_dbenvs.erase(env->Directory().string());
        env = nullptr;
    }
}

void BerkeleyDatabase::Open(const char* pszMode)
{
    m_read_only = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    if (IsDummy()){
        return;
    }

    bool fCreate = strchr(pszMode, 'c') != nullptr;
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(cs_db);
        if (!env->Open(false /* retry */))
            throw std::runtime_error("BerkeleyDatabase: Failed to open database environment.");

        if (m_db == nullptr) {
            int ret;
            std::unique_ptr<Db> pdb_temp = MakeUnique<Db>(env->dbenv.get(), 0);

            bool fMockDb = env->IsMock();
            if (fMockDb) {
                DbMpoolFile* mpf = pdb_temp->get_mpf();
                ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0) {
                    throw std::runtime_error(strprintf("BerkeleyDatabase: Failed to configure for no temp file backing for database %s", strFile));
                }
            }

            ret = pdb_temp->open(nullptr,                             // Txn pointer
                            fMockDb ? nullptr : strFile.c_str(),  // Filename
                            fMockDb ? strFile.c_str() : "main",   // Logical db name
                            DB_BTREE,                                 // Database type
                            nFlags,                                   // Flags
                            0);

            if (ret != 0) {
                throw std::runtime_error(strprintf("BerkeleyDatabase: Error %d, can't open database %s", ret, strFile));
            }
            m_file_path = (env->Directory() / strFile).string();

            // Check that the BDB file id has not already been loaded in any BDB environment
            // to avoid BDB data consistency bugs that happen when different data
            // files in the same environment have the same fileid. All BDB environments are
            // checked to prevent bitcoin from opening the same data file through another
            // environment when the file is referenced through equivalent but
            // not obviously identical symlinked or hard linked or bind mounted
            // paths. In the future a more relaxed check for equal inode and
            // device ids could be done instead, which would allow opening
            // different backup copies of a wallet at the same time. Maybe even
            // more ideally, an exclusive lock for accessing the database could
            // be implemented, so no equality checks are needed at all. (Newer
            // versions of BDB have an set_lk_exclusive method for this
            // purpose, but the older version we use does not.)
            WalletDatabaseFileId fileid;
            int fileid_ret = pdb_temp->get_mpf()->get_fileid(fileid.value);
            if (fileid_ret != 0) {
                throw std::runtime_error(strprintf("BerkeleyDatabase: Can't open database %s (get_fileid failed with %d)", strFile, fileid_ret));
            }
            for (const auto& item : g_fileids) {
                if (fileid == item.second && item.first != m_file_path) {
                    throw std::runtime_error(strprintf("BerkeleyDatabase: Can't open database %s (duplicates fileid %s from %s)", strFile,
                        HexStr(std::begin(item.second.value), std::end(item.second.value)), item.first));
                }
            }
            g_fileids[m_file_path] = fileid;

            m_db.reset(pdb_temp.release());

            if (fCreate && !Exists(std::string("version"))) {
                bool fTmp = m_read_only;
                m_read_only = false;
                Write(std::string("version"), CLIENT_VERSION);
                m_read_only = fTmp;
            }
        }
    }
}

void WalletDatabase::IncrementUpdateCounter()
{
    ++nUpdateCounter;
}

void BerkeleyEnvironment::CloseDb(const std::string& strFile)
{
    {
        LOCK(cs_db);
        auto it = m_databases.find(strFile);
        assert(it != m_databases.end());
        BerkeleyDatabase& database = it->second.get();
        if (database.m_db) {
            // Close the database handle
            database.m_db->close(0);
            database.m_db.reset();
        }
    }
}

void BerkeleyEnvironment::ReloadDbEnv()
{
    // Make sure that no Db's are in use
    AssertLockNotHeld(cs_db);
    std::unique_lock<RecursiveMutex> lock(cs_db);
    m_db_in_use.wait(lock, [this](){
        for (auto& db : m_databases) {
            if (db.second.get().m_refcount > 0) return false;
        }
        return true;
    });

    std::vector<std::string> filenames;
    for (auto it : m_databases) {
        filenames.push_back(it.first);
    }
    // Close the individual Db's
    for (const std::string& filename : filenames) {
        CloseDb(filename);
    }
    // Reset the environment
    Flush(); // This will flush and close the environment
    Close();
    Reset();
    Open(true);
}

bool BerkeleyDatabase::Rewrite(const char* pszSkip)
{
    if (IsDummy()) {
        return true;
    }
    while (true) {
        {
            LOCK(cs_db);
            if (m_refcount == 0) {
                // Flush log data to the dat file
                env->CloseDb(strFile);
                env->CheckpointLSN(strFile);

                bool fSuccess = true;
                LogPrintf("BerkeleyBatch::Rewrite: Rewriting %s...\n", strFile);
                std::string strFileRes = strFile + ".rewrite";
                { // surround usage of db with extra {}
                    Open("r");
                    Acquire();
                    std::unique_ptr<Db> pdbCopy = MakeUnique<Db>(env->dbenv.get(), 0);

                    int ret = pdbCopy->open(nullptr,               // Txn pointer
                                            strFileRes.c_str(), // Filename
                                            "main",             // Logical db name
                                            DB_BTREE,           // Database type
                                            DB_CREATE,          // Flags
                                            0);
                    if (ret > 0) {
                        LogPrintf("BerkeleyBatch::Rewrite: Can't create database file %s\n", strFileRes);
                        fSuccess = false;
                    }

                    if (CreateCursor())
                        while (fSuccess) {
                            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                            bool complete;
                            bool ret1 = ReadAtCursor(ssKey, ssValue, complete);
                            if (complete) {
                                CloseCursor();
                                break;
                            } else if (!ret1) {
                                CloseCursor();
                                fSuccess = false;
                                break;
                            }
                            if (pszSkip &&
                                strncmp(ssKey.data(), pszSkip, std::min(ssKey.size(), strlen(pszSkip))) == 0)
                                continue;
                            if (strncmp(ssKey.data(), "\x07version", 8) == 0) {
                                // Update version:
                                ssValue.clear();
                                ssValue << CLIENT_VERSION;
                            }
                            Dbt datKey(ssKey.data(), ssKey.size());
                            Dbt datValue(ssValue.data(), ssValue.size());
                            int ret2 = pdbCopy->put(nullptr, &datKey, &datValue, DB_NOOVERWRITE);
                            if (ret2 > 0)
                                fSuccess = false;
                        }
                    if (fSuccess) {
                        Release();
                        Close();
                        if (pdbCopy->close(0))
                            fSuccess = false;
                    } else {
                        pdbCopy->close(0);
                    }
                }
                if (fSuccess) {
                    Db dbA(env->dbenv.get(), 0);
                    if (dbA.remove(strFile.c_str(), nullptr, 0))
                        fSuccess = false;
                    Db dbB(env->dbenv.get(), 0);
                    if (dbB.rename(strFileRes.c_str(), nullptr, strFile.c_str(), 0))
                        fSuccess = false;
                }
                if (!fSuccess)
                    LogPrintf("BerkeleyBatch::Rewrite: Failed to rewrite database file %s\n", strFileRes);
                return fSuccess;
            }
        }
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }
}


void BerkeleyEnvironment::Flush()
{
    int64_t nStart = GetTimeMillis();
    // Flush log data to the actual data file on all files that are not in use
    LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::Flush: [%s] Flush%s\n", strPath, fDbEnvInit ? "" : " database not started");
    if (!fDbEnvInit)
        return;
    {
        LOCK(cs_db);
        for (auto& db_it : m_databases) {
            std::string strFile = db_it.first;
            int nRefCount = db_it.second.get().m_refcount;
            LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::Flush: Flushing %s (refcount = %d)...\n", strFile, nRefCount);
            if (nRefCount == 0) {
                // Move log data to the dat file
                CloseDb(strFile);
                LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::Flush: %s checkpoint\n", strFile);
                dbenv->txn_checkpoint(0, 0, 0);
                LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::Flush: %s detach\n", strFile);
                if (!fMockDb)
                    dbenv->lsn_reset(strFile.c_str(), 0);
                LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::Flush: %s closed\n", strFile);
            }
        }
        LogPrint(BCLog::WALLETDB, "BerkeleyEnvironment::Flush: Flush%s took %15dms\n", fDbEnvInit ? "" : " database not started", GetTimeMillis() - nStart);
    }
}

bool BerkeleyDatabase::PeriodicFlush()
{
    if (IsDummy()) {
        return true;
    }
    bool ret = false;
    TRY_LOCK(cs_db, lockDb);
    if (lockDb)
    {
        // Don't do this if any databases are in use
        int nRefCount = 0;
        for (auto& db_it : env->m_databases) {
            nRefCount += db_it.second.get().m_refcount;
        }

        if (nRefCount == 0)
        {
            boost::this_thread::interruption_point();
            LogPrint(BCLog::WALLETDB, "Flushing %s\n", strFile);
            int64_t nStart = GetTimeMillis();

            // Flush wallet file so it's self contained
            env->CloseDb(strFile);
            env->CheckpointLSN(strFile);

            m_refcount = 0;
            LogPrint(BCLog::WALLETDB, "Flushed %s %dms\n", strFile, GetTimeMillis() - nStart);
            ret = true;
        }
    }

    return ret;
}

bool BerkeleyDatabase::Backup(const std::string& strDest) const
{
    if (IsDummy()) {
        return false;
    }
    while (true)
    {
        {
            LOCK(cs_db);
            if (m_refcount == 0)
            {
                // Flush log data to the dat file
                env->CloseDb(strFile);
                env->CheckpointLSN(strFile);

                // Copy wallet file
                fs::path pathSrc = env->Directory() / strFile;
                fs::path pathDest(strDest);
                if (fs::is_directory(pathDest))
                    pathDest /= strFile;

                try {
                    if (fs::equivalent(pathSrc, pathDest)) {
                        LogPrintf("cannot backup to wallet source file %s\n", pathDest.string());
                        return false;
                    }

                    fs::copy_file(pathSrc, pathDest, fs::copy_option::overwrite_if_exists);
                    LogPrintf("copied %s to %s\n", strFile, pathDest.string());
                    return true;
                } catch (const fs::filesystem_error& e) {
                    LogPrintf("error copying %s to %s - %s\n", strFile, pathDest.string(), fsbridge::get_filesystem_error_message(e));
                    return false;
                }
            }
        }
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }
}

void BerkeleyDatabase::Close()
{
    if (m_active_txn) {
        m_active_txn->abort();
    }

    if (!IsDummy()) {
        env->Flush();
        // TODO: To avoid g_dbenvs.erase erasing the environment prematurely after the
        // first database shutdown when multiple databases are open in the same
        // environment, should replace raw database `env` pointers with shared or weak
        // pointers, or else separate the database and environment shutdowns so
        // environments can be shut down after databases.
        g_fileids.erase(m_file_path);
    }
}

void BerkeleyDatabase::Flush()
{
    if (m_active_txn) {
        return;
    }

    if (!IsDummy()) {
        // Flush database activity from memory pool to disk log
        unsigned int nMinutes = 0;
        if (m_read_only)
            nMinutes = 1;

        env->dbenv->txn_checkpoint(nMinutes ? gArgs.GetArg("-dblogsize", DEFAULT_WALLET_DBLOGSIZE) * 1024 : 0, nMinutes, 0);
    }
}

void BerkeleyDatabase::ReloadDbEnv()
{
    if (!IsDummy()) {
        env->ReloadDbEnv();
    }
}

std::string BerkeleyDatabaseVersion()
{
    return DbEnv::version(nullptr, nullptr, nullptr);
}

void BerkeleyDatabase::Release()
{
    if (m_active_txn) {
       m_active_txn->abort();
    }

    m_refcount--;
    if (!IsDummy()) {
        env->m_db_in_use.notify_all();
    }
}

void BerkeleyDatabase::Acquire()
{
    m_refcount++;
}

bool BerkeleyDatabase::DBRead(CDataStream& key, CDataStream& value) const
{
    if (!m_db)
        return false;

    // Key
    SafeDbt datKey(key.data(), key.size());

    // Read
    SafeDbt datValue;
    int ret = m_db->get(m_active_txn, datKey, datValue, 0);
    if (ret == 0 && datValue.get_data() != nullptr) {
        value.write((char*)datValue.get_data(), datValue.get_size());
        return true;
    }
    return false;
}

bool BerkeleyDatabase::DBWrite(CDataStream& key, CDataStream& value, bool overwrite) const
{
    if (!m_db)
        return true;
    if (m_read_only)
        assert(!"Write called on database in read-only mode");

    // Key
    SafeDbt datKey(key.data(), key.size());

    // Value
    SafeDbt datValue(value.data(), value.size());

    // Write
    int ret = m_db->put(m_active_txn, datKey, datValue, (overwrite ? 0 : DB_NOOVERWRITE));
    return (ret == 0);
}

bool BerkeleyDatabase::DBErase(CDataStream& key) const
{
    if (!m_db)
        return false;
    if (m_read_only)
        assert(!"Erase called on database in read-only mode");

    // Key
    SafeDbt datKey(key.data(), key.size());

    // Erase
    int ret = m_db->del(m_active_txn, datKey, 0);
    return (ret == 0 || ret == DB_NOTFOUND);
}

bool BerkeleyDatabase::DBExists(CDataStream& key) const
{
    if (!m_db)
        return false;

    // Key
    SafeDbt datKey(key.data(), key.size());

    // Exists
    int ret = m_db->exists(m_active_txn, datKey, 0);
    return ret == 0;
}

/** Return object for accessing database at specified path. */
std::unique_ptr<WalletDatabase> CreateWalletDatabase(const fs::path& path)
{
    std::string filename;
    return MakeUnique<BerkeleyDatabase>(GetWalletEnv(path, filename), std::move(filename));
}

/** Return object for accessing dummy database with no read/write capabilities. */
std::unique_ptr<WalletDatabase> CreateDummyWalletDatabase()
{
    return MakeUnique<BerkeleyDatabase>();
}

/** Return object for accessing temporary in-memory database. */
std::unique_ptr<WalletDatabase> CreateMockWalletDatabase()
{
    return MakeUnique<BerkeleyDatabase>(std::make_shared<BerkeleyEnvironment>(), "");
}
