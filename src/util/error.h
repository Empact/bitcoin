// Copyright (c) 2010-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_ERROR_H
#define BITCOIN_UTIL_ERROR_H

#include <string>

std::string AmountHighWarn(const std::string& optname);

std::string AmountErrMsg(const char* const optname, const std::string& strValue);

#endif // BITCOIN_UTIL_ERROR_H
