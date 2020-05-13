// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fs.h>
#include <util/system.h>
#include <util/translation.h>
#include <wallet/bdb.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

namespace WalletTool {

// The standard wallet deleter function blocks on the validation interface
// queue, which doesn't exist for the bitcoin-wallet. Define our own
// deleter here.
static void WalletToolReleaseWallet(CWallet* wallet)
{
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Flush(true);
    delete wallet;
}

static std::shared_ptr<CWallet> CreateWallet(const std::string& name, const fs::path& path)
{
    if (fs::exists(path)) {
        tfm::format(std::cerr, "Error: File exists already\n");
        return nullptr;
    }
    // dummy chain interface
    std::shared_ptr<CWallet> wallet_instance(new CWallet(nullptr /* chain */, WalletLocation(name), CreateWalletDatabase(path)), WalletToolReleaseWallet);
    LOCK(wallet_instance->cs_wallet);
    bool first_run = true;
    DBErrors load_wallet_ret = wallet_instance->LoadWallet(first_run);
    if (load_wallet_ret != DBErrors::LOAD_OK) {
        tfm::format(std::cerr, "Error creating %s", name);
        return nullptr;
    }

    wallet_instance->SetMinVersion(FEATURE_HD_SPLIT);

    // generate a new HD seed
    auto spk_man = wallet_instance->GetOrCreateLegacyScriptPubKeyMan();
    CPubKey seed = spk_man->GenerateNewSeed();
    spk_man->SetHDSeed(seed);

    tfm::format(std::cout, "Topping up keypool...\n");
    wallet_instance->TopUpKeyPool();
    return wallet_instance;
}

static std::shared_ptr<CWallet> LoadWallet(const std::string& name, const fs::path& path)
{
    if (!fs::exists(path)) {
        tfm::format(std::cerr, "Error: Wallet files does not exist\n");
        return nullptr;
    }

    // dummy chain interface
    std::shared_ptr<CWallet> wallet_instance(new CWallet(nullptr /* chain */, WalletLocation(name), CreateWalletDatabase(path)), WalletToolReleaseWallet);
    DBErrors load_wallet_ret;
    try {
        bool first_run;
        load_wallet_ret = wallet_instance->LoadWallet(first_run);
    } catch (const std::runtime_error&) {
        tfm::format(std::cerr, "Error loading %s. Is wallet being used by another process?\n", name);
        return nullptr;
    }

    if (load_wallet_ret != DBErrors::LOAD_OK) {
        wallet_instance = nullptr;
        if (load_wallet_ret == DBErrors::CORRUPT) {
            tfm::format(std::cerr, "Error loading %s: Wallet corrupted", name);
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NONCRITICAL_ERROR) {
            tfm::format(std::cerr, "Error reading %s! All keys read correctly, but transaction data"
                            " or address book entries might be missing or incorrect.",
                name);
        } else if (load_wallet_ret == DBErrors::TOO_NEW) {
            tfm::format(std::cerr, "Error loading %s: Wallet requires newer version of %s",
                name, PACKAGE_NAME);
            return nullptr;
        } else if (load_wallet_ret == DBErrors::NEED_REWRITE) {
            tfm::format(std::cerr, "Wallet needed to be rewritten: restart %s to complete", PACKAGE_NAME);
            return nullptr;
        } else {
            tfm::format(std::cerr, "Error loading %s", name);
            return nullptr;
        }
    }

    return wallet_instance;
}

static void WalletShowInfo(CWallet* wallet_instance)
{
    LOCK(wallet_instance->cs_wallet);

    tfm::format(std::cout, "Wallet info\n===========\n");
    tfm::format(std::cout, "Encrypted: %s\n", wallet_instance->IsCrypted() ? "yes" : "no");
    tfm::format(std::cout, "HD (hd seed available): %s\n", wallet_instance->IsHDEnabled() ? "yes" : "no");
    tfm::format(std::cout, "Keypool Size: %u\n", wallet_instance->GetKeyPoolSize());
    tfm::format(std::cout, "Transactions: %zu\n", wallet_instance->mapWallet.size());
    tfm::format(std::cout, "Address Book: %zu\n", wallet_instance->m_address_book.size());
}

/* End of headers, beginning of key/value data */
static const char *HEADER_END = "HEADER=END";
/* End of key/value data */
static const char *DATA_END = "DATA=END";

static bool SalvageDb(Db& db, const std::string& strFile, std::vector<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>>& vResult)
{
    std::stringstream strDump;

    int result = db.verify(strFile.c_str(), nullptr, &strDump, DB_SALVAGE | DB_AGGRESSIVE);
    if (result == DB_VERIFY_BAD) {
        LogPrintf("Salvage: Database salvage found errors, all data may not be recoverable.\n");
    }
    if (result != 0 && result != DB_VERIFY_BAD) {
        LogPrintf("Salvage: Database salvage failed with result %d.\n", result);
        return false;
    }

    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    //  hexadecimal key
    //  hexadecimal value
    //  ... repeated
    // DATA=END

    std::string strLine;
    while (!strDump.eof() && strLine != HEADER_END)
        getline(strDump, strLine); // Skip past header

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != DATA_END) {
        getline(strDump, keyHex);
        if (keyHex != DATA_END) {
            if (strDump.eof())
                break;
            getline(strDump, valueHex);
            if (valueHex == DATA_END) {
                LogPrintf("Salvage: WARNING: Number of keys in data does not match number of values.\n");
                break;
            }
            vResult.push_back(make_pair(ParseHex(keyHex), ParseHex(valueHex)));
        }
    }

    if (keyHex != DATA_END) {
        LogPrintf("Salvage: WARNING: Unexpected end of file while reading salvage output.\n");
        return false;
    }

    return (result == 0);
}

static bool SalvageWallet(fs::path file_path)
{
    CWallet dummy_wallet(nullptr, WalletLocation(), CreateDummyWalletDatabase());
    std::string filename;
    std::shared_ptr<BerkeleyEnvironment> env = GetWalletEnv(file_path, filename);

    // Recovery procedure:
    // move wallet file to walletfilename.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to fresh wallet file
    // Set -rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("%s.%d.bak", filename, now);

    int result = env->dbenv->dbrename(nullptr, filename.c_str(), nullptr,
                                       newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        LogPrintf("Renamed %s to %s\n", filename, newFilename);
    else
    {
        LogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::unique_ptr<Db> pdbCopy = MakeUnique<Db>(env->dbenv.get(), 0);
    std::vector<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>> salvagedData;
    bool fSuccess = SalvageDb(*pdbCopy, newFilename, salvagedData);
    if (salvagedData.empty())
    {
        LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename);
        return false;
    }
    LogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    int ret = pdbCopy->open(nullptr,               // Txn pointer
                            filename.c_str(),   // Filename
                            "main",             // Logical db name
                            DB_BTREE,           // Database type
                            DB_CREATE,          // Flags
                            0);
    if (ret > 0) {
        LogPrintf("Cannot create database file %s\n", filename);
        pdbCopy->close(0);
        return false;
    }

    DbTxn* ptxn = env->TxnBegin();
    for (std::pair<std::vector<unsigned char>, std::vector<unsigned char>>& row : salvagedData)
    {
        CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
        CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
        std::string strType, strErr;
        /* only let keys (cryptographical keys) as KV/key-type pass through */
        bool fReadOK = WalletBatch::ReadKeyValue(&dummy_wallet, ssKey, ssValue, strType, strErr);
        if (!WalletBatch::IsKeyType(strType) && strType != DBKeys::HDCHAIN) {
            continue;
        }
        if (!fReadOK)
        {
            LogPrintf("WARNING: SalvageWallet skipping %s: %s\n", strType, strErr);
            continue;
        }
        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool ExecuteWalletToolFunc(const std::string& command, const std::string& name)
{
    fs::path path = fs::absolute(name, GetWalletDir());

    if (command == "create") {
        std::shared_ptr<CWallet> wallet_instance = CreateWallet(name, path);
        if (wallet_instance) {
            WalletShowInfo(wallet_instance.get());
            wallet_instance->Flush(true);
        }
    } else if (command == "info" || command == "salvage") {
        if (!fs::exists(path)) {
            tfm::format(std::cerr, "Error: no wallet file at %s\n", name);
            return false;
        }
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        std::unique_ptr<WalletDatabase> database = CreateWalletDatabase(path);
        if (!database->Verify(warnings, error)) {
            tfm::format(std::cerr, "%s\nError loading %s. Is wallet being used by other process?\n", error.original, name);
            return false;
        }
        database.reset();
        database = nullptr;

        if (command == "info") {
            std::shared_ptr<CWallet> wallet_instance = LoadWallet(name, path);
            if (!wallet_instance) return false;
            WalletShowInfo(wallet_instance.get());
            wallet_instance->Flush(true);
        } else if (command == "salvage") {
            SalvageWallet(path);
        }
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command);
        return false;
    }

    return true;
}
} // namespace WalletTool
