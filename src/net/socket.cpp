// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/socket.h>

#include <tinyformat.h>
#include <util/system.h>

#include <cstddef>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#ifndef WIN32
#include <fcntl.h>
#else
#include <codecvt>
#endif

#ifdef USE_POLL
#include <poll.h>
#endif

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

namespace {

/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(const SOCKET& hSocket, bool fNonBlocking)
{
    if (fNonBlocking) {
#ifdef WIN32
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags | O_NONBLOCK) == SOCKET_ERROR) {
#endif
            return false;
        }
    } else {
#ifdef WIN32
        u_long nZero = 0;
        if (ioctlsocket(hSocket, FIONBIO, &nZero) == SOCKET_ERROR) {
#else
        int fFlags = fcntl(hSocket, F_GETFL, 0);
        if (fcntl(hSocket, F_SETFL, fFlags & ~O_NONBLOCK) == SOCKET_ERROR) {
#endif
            return false;
        }
    }

    return true;
}

template<typename... Args>
static void LogConnectFailure(bool manual_connection, const char* fmt, const Args&... args) {
    std::string error_message = tfm::format(fmt, args...);
    if (manual_connection) {
        LogPrintf("%s\n", error_message);
    } else {
        LogPrint(BCLog::NET, "%s\n", error_message);
    }
}

} // namespace

#ifdef WIN32
std::string NetworkErrorString(int err)
{
    wchar_t buf[256];
    buf[0] = 0;
    if(FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            buf, ARRAYSIZE(buf), nullptr))
    {
        return strprintf("%s (%d)", std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t>().to_bytes(buf), err);
    }
    else
    {
        return strprintf("Unknown error (%d)", err);
    }
}
#else
std::string NetworkErrorString(int err)
{
    char buf[256];
    buf[0] = 0;
    /* Too bad there are two incompatible implementations of the
     * thread-safe strerror. */
    const char *s;
#ifdef STRERROR_R_CHAR_P /* GNU variant can return a pointer outside the passed buffer */
    s = strerror_r(err, buf, sizeof(buf));
#else /* POSIX variant always returns message in buffer */
    s = buf;
    if (strerror_r(err, buf, sizeof(buf)))
        buf[0] = 0;
#endif
    return strprintf("%s (%d)", s, err);
}
#endif

SOCKET CreateSocket(const CService &addrConnect)
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("Cannot create socket for %s: unsupported network\n", addrConnect.ToString());
        return INVALID_SOCKET;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (!IsSelectableSocket(hSocket)) {
        CloseSocket(hSocket);
        LogPrintf("Cannot create connection: non-selectable socket created (fd >= FD_SETSIZE ?)\n");
        return INVALID_SOCKET;
    }

#ifdef SO_NOSIGPIPE
    int set = 1;
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

    //Disable Nagle's algorithm
    SetSocketNoDelay(hSocket);

    // Set to non-blocking
    if (!SetSocketNonBlocking(hSocket, true)) {
        CloseSocket(hSocket);
        LogPrintf("ConnectSocketDirectly: Setting socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));
    }
    return hSocket;
}


bool ConnectSocketDirectly(const CService &addrConnect, const SOCKET& hSocket, int nTimeout, bool manual_connection)
{
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (hSocket == INVALID_SOCKET) {
        LogPrintf("Cannot connect to %s: invalid socket\n", addrConnect.ToString());
        return false;
    }
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("Cannot connect to %s: unsupported network\n", addrConnect.ToString());
        return false;
    }
    if (connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        // WSAEINVAL is here because some legacy version of winsock uses it
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL)
        {
#ifdef USE_POLL
            struct pollfd pollfd = {};
            pollfd.fd = hSocket;
            pollfd.events = POLLIN | POLLOUT;
            int nRet = poll(&pollfd, 1, nTimeout);
#else
            struct timeval timeout = MillisToTimeval(nTimeout);
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = select(hSocket + 1, nullptr, &fdset, nullptr, &timeout);
#endif
            if (nRet == 0)
            {
                LogPrint(BCLog::NET, "connection to %s timeout\n", addrConnect.ToString());
                return false;
            }
            if (nRet == SOCKET_ERROR)
            {
                LogPrintf("select() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                return false;
            }
            socklen_t nRetSize = sizeof(nRet);
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (sockopt_arg_type)&nRet, &nRetSize) == SOCKET_ERROR)
            {
                LogPrintf("getsockopt() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                return false;
            }
            if (nRet != 0)
            {
                LogConnectFailure(manual_connection, "connect() to %s failed after select(): %s", addrConnect.ToString(), NetworkErrorString(nRet));
                return false;
            }
        }
#ifdef WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            LogConnectFailure(manual_connection, "connect() to %s failed: %s", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
            return false;
        }
    }
    return true;
}

bool CloseSocket(SOCKET& hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return false;
#ifdef WIN32
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    if (ret) {
        LogPrintf("Socket close failed: %d. Error: %s\n", hSocket, NetworkErrorString(WSAGetLastError()));
    }
    hSocket = INVALID_SOCKET;
    return ret != SOCKET_ERROR;
}

bool SetSocketNoDelay(const SOCKET& hSocket)
{
    int set = 1;
    int rc = setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
    return rc == 0;
}

namespace {

/** Status codes that can be returned by InterruptibleRecv */
enum class IntrRecvError {
    OK,
    Timeout,
    Disconnected,
    NetworkError,
    Interrupted
};


/** SOCKS version */
enum SOCKSVersion: uint8_t {
    SOCKS4 = 0x04,
    SOCKS5 = 0x05
};

/** Values defined for METHOD in RFC1928 */
enum SOCKS5Method: uint8_t {
    NOAUTH = 0x00,        //!< No authentication required
    GSSAPI = 0x01,        //!< GSSAPI
    USER_PASS = 0x02,     //!< Username/password
    NO_ACCEPTABLE = 0xff, //!< No acceptable methods
};

/** Values defined for CMD in RFC1928 */
enum SOCKS5Command: uint8_t {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

/** Values defined for REP in RFC1928 */
enum SOCKS5Reply: uint8_t {
    SUCCEEDED = 0x00,        //!< Succeeded
    GENFAILURE = 0x01,       //!< General failure
    NOTALLOWED = 0x02,       //!< Connection not allowed by ruleset
    NETUNREACHABLE = 0x03,   //!< Network unreachable
    HOSTUNREACHABLE = 0x04,  //!< Network unreachable
    CONNREFUSED = 0x05,      //!< Connection refused
    TTLEXPIRED = 0x06,       //!< TTL expired
    CMDUNSUPPORTED = 0x07,   //!< Command not supported
    ATYPEUNSUPPORTED = 0x08, //!< Address type not supported
};

/** Values defined for ATYPE in RFC1928 */
enum SOCKS5Atyp: uint8_t {
    IPV4 = 0x01,
    DOMAINNAME = 0x03,
    IPV6 = 0x04,
};

/** Credentials for proxy authentication */
struct ProxyCredentials
{
    std::string username;
    std::string password;
};

std::atomic<bool> interruptSocks5Recv(false);

/** Convert SOCKS5 reply to an error message */
std::string Socks5ErrorString(uint8_t err)
{
    switch(err) {
        case SOCKS5Reply::GENFAILURE:
            return "general failure";
        case SOCKS5Reply::NOTALLOWED:
            return "connection not allowed";
        case SOCKS5Reply::NETUNREACHABLE:
            return "network unreachable";
        case SOCKS5Reply::HOSTUNREACHABLE:
            return "host unreachable";
        case SOCKS5Reply::CONNREFUSED:
            return "connection refused";
        case SOCKS5Reply::TTLEXPIRED:
            return "TTL expired";
        case SOCKS5Reply::CMDUNSUPPORTED:
            return "protocol error";
        case SOCKS5Reply::ATYPEUNSUPPORTED:
            return "address type not supported";
        default:
            return "unknown";
    }
}

/**
 * Read bytes from socket. This will either read the full number of bytes requested
 * or return False on error or timeout.
 * This function can be interrupted by calling InterruptSocks5()
 *
 * @param data Buffer to receive into
 * @param len  Length of data to receive
 * @param timeout  Timeout in milliseconds for receive operation
 *
 * @note This function requires that hSocket is in non-blocking mode.
 */
IntrRecvError InterruptibleRecv(uint8_t* data, size_t len, int timeout, const SOCKET& hSocket)
{
    int64_t curTime = GetTimeMillis();
    int64_t endTime = curTime + timeout;
    // Maximum time to wait in one select call. It will take up until this time (in millis)
    // to break off in case of an interruption.
    const int64_t maxWait = 1000;
    while (len > 0 && curTime < endTime) {
        ssize_t ret = recv(hSocket, (char*)data, len, 0); // Optimistically try the recv first
        if (ret > 0) {
            len -= ret;
            data += ret;
        } else if (ret == 0) { // Unexpected disconnection
            return IntrRecvError::Disconnected;
        } else { // Other error or blocking
            int nErr = WSAGetLastError();
            if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL) {
                if (!IsSelectableSocket(hSocket)) {
                    return IntrRecvError::NetworkError;
                }
                int timeout_ms = std::min(endTime - curTime, maxWait);
#ifdef USE_POLL
                struct pollfd pollfd = {};
                pollfd.fd = hSocket;
                pollfd.events = POLLIN | POLLOUT;
                int nRet = poll(&pollfd, 1, timeout_ms);
#else
                struct timeval tval = MillisToTimeval(timeout_ms);
                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(hSocket, &fdset);
                int nRet = select(hSocket + 1, &fdset, nullptr, nullptr, &tval);
#endif
                if (nRet == SOCKET_ERROR) {
                    return IntrRecvError::NetworkError;
                }
            } else {
                return IntrRecvError::NetworkError;
            }
        }
        if (interruptSocks5Recv)
            return IntrRecvError::Interrupted;
        curTime = GetTimeMillis();
    }
    return len == 0 ? IntrRecvError::OK : IntrRecvError::Timeout;
}

// Need ample time for negotiation for very slow proxies such as Tor (milliseconds)
const int SOCKS5_RECV_TIMEOUT = 20 * 1000;

/** Connect using SOCKS5 (as described in RFC1928) */
bool Socks5(const std::string& strDest, int port, const ProxyCredentials *auth, const SOCKET& hSocket)
{
    IntrRecvError recvr;
    LogPrint(BCLog::NET, "SOCKS5 connecting %s\n", strDest);
    if (strDest.size() > 255) {
        return error("Hostname too long");
    }
    // Accepted authentication methods
    std::vector<uint8_t> vSocks5Init;
    vSocks5Init.push_back(SOCKSVersion::SOCKS5);
    if (auth) {
        vSocks5Init.push_back(0x02); // Number of methods
        vSocks5Init.push_back(SOCKS5Method::NOAUTH);
        vSocks5Init.push_back(SOCKS5Method::USER_PASS);
    } else {
        vSocks5Init.push_back(0x01); // Number of methods
        vSocks5Init.push_back(SOCKS5Method::NOAUTH);
    }
    ssize_t ret = send(hSocket, (const char*)vSocks5Init.data(), vSocks5Init.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5Init.size()) {
        return error("Error sending to proxy");
    }
    uint8_t pchRet1[2];
    if ((recvr = InterruptibleRecv(pchRet1, 2, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
        LogPrintf("Socks5() connect to %s:%d failed: InterruptibleRecv() timeout or other failure\n", strDest, port);
        return false;
    }
    if (pchRet1[0] != SOCKSVersion::SOCKS5) {
        return error("Proxy failed to initialize");
    }
    if (pchRet1[1] == SOCKS5Method::USER_PASS && auth) {
        // Perform username/password authentication (as described in RFC1929)
        std::vector<uint8_t> vAuth;
        vAuth.push_back(0x01); // Current (and only) version of user/pass subnegotiation
        if (auth->username.size() > 255 || auth->password.size() > 255)
            return error("Proxy username or password too long");
        vAuth.push_back(auth->username.size());
        vAuth.insert(vAuth.end(), auth->username.begin(), auth->username.end());
        vAuth.push_back(auth->password.size());
        vAuth.insert(vAuth.end(), auth->password.begin(), auth->password.end());
        ret = send(hSocket, (const char*)vAuth.data(), vAuth.size(), MSG_NOSIGNAL);
        if (ret != (ssize_t)vAuth.size()) {
            return error("Error sending authentication to proxy");
        }
        LogPrint(BCLog::PROXY, "SOCKS5 sending proxy authentication %s:%s\n", auth->username, auth->password);
        uint8_t pchRetA[2];
        if ((recvr = InterruptibleRecv(pchRetA, 2, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
            return error("Error reading proxy authentication response");
        }
        if (pchRetA[0] != 0x01 || pchRetA[1] != 0x00) {
            return error("Proxy authentication unsuccessful");
        }
    } else if (pchRet1[1] == SOCKS5Method::NOAUTH) {
        // Perform no authentication
    } else {
        return error("Proxy requested wrong authentication method %02x", pchRet1[1]);
    }
    std::vector<uint8_t> vSocks5;
    vSocks5.push_back(SOCKSVersion::SOCKS5); // VER protocol version
    vSocks5.push_back(SOCKS5Command::CONNECT); // CMD CONNECT
    vSocks5.push_back(0x00); // RSV Reserved must be 0
    vSocks5.push_back(SOCKS5Atyp::DOMAINNAME); // ATYP DOMAINNAME
    vSocks5.push_back(strDest.size()); // Length<=255 is checked at beginning of function
    vSocks5.insert(vSocks5.end(), strDest.begin(), strDest.end());
    vSocks5.push_back((port >> 8) & 0xFF);
    vSocks5.push_back((port >> 0) & 0xFF);
    ret = send(hSocket, (const char*)vSocks5.data(), vSocks5.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)vSocks5.size()) {
        return error("Error sending to proxy");
    }
    uint8_t pchRet2[4];
    if ((recvr = InterruptibleRecv(pchRet2, 4, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
        if (recvr == IntrRecvError::Timeout) {
            /* If a timeout happens here, this effectively means we timed out while connecting
             * to the remote node. This is very common for Tor, so do not print an
             * error message. */
            return false;
        } else {
            return error("Error while reading proxy response");
        }
    }
    if (pchRet2[0] != SOCKSVersion::SOCKS5) {
        return error("Proxy failed to accept request");
    }
    if (pchRet2[1] != SOCKS5Reply::SUCCEEDED) {
        // Failures to connect to a peer that are not proxy errors
        LogPrintf("Socks5() connect to %s:%d failed: %s\n", strDest, port, Socks5ErrorString(pchRet2[1]));
        return false;
    }
    if (pchRet2[2] != 0x00) { // Reserved field must be 0
        return error("Error: malformed proxy response");
    }
    uint8_t pchRet3[256];
    switch (pchRet2[3])
    {
        case SOCKS5Atyp::IPV4: recvr = InterruptibleRecv(pchRet3, 4, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case SOCKS5Atyp::IPV6: recvr = InterruptibleRecv(pchRet3, 16, SOCKS5_RECV_TIMEOUT, hSocket); break;
        case SOCKS5Atyp::DOMAINNAME:
        {
            recvr = InterruptibleRecv(pchRet3, 1, SOCKS5_RECV_TIMEOUT, hSocket);
            if (recvr != IntrRecvError::OK) {
                return error("Error reading from proxy");
            }
            int nRecv = pchRet3[0];
            recvr = InterruptibleRecv(pchRet3, nRecv, SOCKS5_RECV_TIMEOUT, hSocket);
            break;
        }
        default: return error("Error: malformed proxy response");
    }
    if (recvr != IntrRecvError::OK) {
        return error("Error reading from proxy");
    }
    if ((recvr = InterruptibleRecv(pchRet3, 2, SOCKS5_RECV_TIMEOUT, hSocket)) != IntrRecvError::OK) {
        return error("Error reading from proxy");
    }
    LogPrint(BCLog::NET, "SOCKS5 connected %s\n", strDest);
    return true;
}

} // namespace

bool ConnectThroughProxy(const CService& proxy, const std::string& strDest, int port, const SOCKET& hSocket, int nTimeout, bool randomize_credentials, bool *outProxyConnectionFailed)
{
    // first connect to proxy server
    if (!ConnectSocketDirectly(proxy, hSocket, nTimeout, true)) {
        if (outProxyConnectionFailed)
            *outProxyConnectionFailed = true;
        return false;
    }
    // do socks negotiation
    if (randomize_credentials) {
        ProxyCredentials random_auth;
        static std::atomic_int counter(0);
        random_auth.username = random_auth.password = strprintf("%i", counter++);
        if (!Socks5(strDest, (unsigned short)port, &random_auth, hSocket)) {
            return false;
        }
    } else {
        if (!Socks5(strDest, (unsigned short)port, 0, hSocket)) {
            return false;
        }
    }
    return true;
}

void InterruptSocks5(bool interrupt)
{
    interruptSocks5Recv = interrupt;
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}
