// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_NETWORK_NAME_H
#define BITCOIN_NET_NETWORK_NAME_H

#include <netaddress.h>

#include <string>

enum Network ParseNetworkName(std::string net);
std::string GetNetworkName(enum Network net);

#endif // BITCOIN_NET_NETWORK_NAME_H
