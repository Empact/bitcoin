// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTILEXCEPTION_H
#define BITCOIN_UTILEXCEPTION_H

#include <exception>

void PrintExceptionContinue(const std::exception *pex, const char* pszThread);

#endif // BITCOIN_UTILEXCEPTION_H
