// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_SOCKET_H
#define BITCOIN_NET_SOCKET_H

#include <compat.h> // for SOCKET
#include <netaddress.h> // for CService

#include <cstdint>
#include <string>

SOCKET CreateSocket(const CService &addrConnect);
bool ConnectSocketDirectly(const CService &addrConnect, const SOCKET& hSocketRet, int nTimeout, bool manual_connection);
bool ConnectThroughProxy(const CService &proxy, const std::string& strDest, int port, const SOCKET& hSocketRet, int nTimeout, bool randomize_credentials, bool *outProxyConnectionFailed);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Set the TCP_NODELAY flag on a socket */
bool SetSocketNoDelay(const SOCKET& hSocket);

inline bool IsSelectableSocket(const SOCKET& s) {
#if defined(USE_POLL) || defined(WIN32)
    return true;
#else
    return (s < FD_SETSIZE);
#endif
}

/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);
void InterruptSocks5(bool interrupt);

/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);

#endif // BITCOIN_NET_SOCKET_H
