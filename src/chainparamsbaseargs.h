// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMSBASEARGS_H
#define BITCOIN_CHAINPARAMSBASEARGS_H

class ArgsManager;

/**
 *Set the arguments for chainparams
 * @see chainparamsbase.h
 */
void SetupChainParamsBaseOptions(ArgsManager& argsman);

#endif // BITCOIN_CHAINPARAMSBASEARGS_H
