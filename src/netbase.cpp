// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netbase.h>

#include <hash.h>
#include <sync.h>
#include <uint256.h>
#include <random.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <atomic>

// Settings
static CCriticalSection cs_proxyInfos;
static proxyType proxyInfo[NET_MAX] GUARDED_BY(cs_proxyInfos);
static proxyType nameProxy GUARDED_BY(cs_proxyInfos);
int nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
bool fNameLookup = DEFAULT_NAME_LOOKUP;

enum Network ParseNetwork(std::string net) {
    Downcase(net);
    if (net == "ipv4") return NET_IPV4;
    if (net == "ipv6") return NET_IPV6;
    if (net == "onion") return NET_ONION;
    if (net == "tor") {
        LogPrintf("Warning: net name 'tor' is deprecated and will be removed in the future. You should use 'onion' instead.\n");
        return NET_ONION;
    }
    return NET_UNROUTABLE;
}

std::string GetNetworkName(enum Network net) {
    switch(net)
    {
    case NET_IPV4: return "ipv4";
    case NET_IPV6: return "ipv6";
    case NET_ONION: return "onion";
    default: return "";
    }
}

bool static LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    vIP.clear();

    {
        CNetAddr addr;
        if (addr.SetSpecial(std::string(pszName))) {
            vIP.push_back(addr);
            return true;
        }
    }

    struct addrinfo aiHint;
    memset(&aiHint, 0, sizeof(struct addrinfo));

    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
    aiHint.ai_family = AF_UNSPEC;
#ifdef WIN32
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif
    struct addrinfo *aiRes = nullptr;
    int nErr = getaddrinfo(pszName, nullptr, &aiHint, &aiRes);
    if (nErr)
        return false;

    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != nullptr && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        CNetAddr resolved;
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            resolved = CNetAddr(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr);
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            struct sockaddr_in6* s6 = (struct sockaddr_in6*) aiTrav->ai_addr;
            resolved = CNetAddr(s6->sin6_addr, s6->sin6_scope_id);
        }
        /* Never allow resolving to an internal address. Consider any such result invalid */
        if (!resolved.IsInternal()) {
            vIP.push_back(resolved);
        }

        aiTrav = aiTrav->ai_next;
    }

    freeaddrinfo(aiRes);

    return (vIP.size() > 0);
}

bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    std::string strHost(pszName);
    if (strHost.empty())
        return false;
    if (strHost.front() == '[' && strHost.back() == ']') {
        strHost = strHost.substr(1, strHost.size() - 2);
    }

    return LookupIntern(strHost.c_str(), vIP, nMaxSolutions, fAllowLookup);
}

bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup)
{
    std::vector<CNetAddr> vIP;
    LookupHost(pszName, vIP, 1, fAllowLookup);
    if(vIP.empty())
        return false;
    addr = vIP.front();
    return true;
}

bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions)
{
    if (pszName[0] == 0)
        return false;
    int port = portDefault;
    std::string hostname;
    SplitHostPort(std::string(pszName), port, hostname);

    std::vector<CNetAddr> vIP;
    bool fRet = LookupIntern(hostname.c_str(), vIP, nMaxSolutions, fAllowLookup);
    if (!fRet)
        return false;
    vAddr.resize(vIP.size());
    for (unsigned int i = 0; i < vIP.size(); i++)
        vAddr[i] = CService(vIP[i], port);
    return true;
}

bool Lookup(const char *pszName, CService& addr, int portDefault, bool fAllowLookup)
{
    std::vector<CService> vService;
    bool fRet = Lookup(pszName, vService, portDefault, fAllowLookup, 1);
    if (!fRet)
        return false;
    addr = vService[0];
    return true;
}

CService LookupNumeric(const char *pszName, int portDefault)
{
    CService addr;
    // "1.2:345" will fail to resolve the ip, but will still set the port.
    // If the ip fails to resolve, re-init the result.
    if(!Lookup(pszName, addr, portDefault, false))
        addr = CService();
    return addr;
}

bool SetProxy(enum Network net, const proxyType &addrProxy) {
    assert(net >= 0 && net < NET_MAX);
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    proxyInfo[net] = addrProxy;
    return true;
}

bool GetProxy(enum Network net, proxyType &proxyInfoOut) {
    assert(net >= 0 && net < NET_MAX);
    LOCK(cs_proxyInfos);
    if (!proxyInfo[net].IsValid())
        return false;
    proxyInfoOut = proxyInfo[net];
    return true;
}

bool SetNameProxy(const proxyType &addrProxy) {
    if (!addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    nameProxy = addrProxy;
    return true;
}

bool GetNameProxy(proxyType &nameProxyOut) {
    LOCK(cs_proxyInfos);
    if(!nameProxy.IsValid())
        return false;
    nameProxyOut = nameProxy;
    return true;
}

bool HaveNameProxy() {
    LOCK(cs_proxyInfos);
    return nameProxy.IsValid();
}

bool IsProxy(const CNetAddr &addr) {
    LOCK(cs_proxyInfos);
    for (int i = 0; i < NET_MAX; i++) {
        if (addr == static_cast<CNetAddr>(proxyInfo[i].proxy))
            return true;
    }
    return false;
}

bool LookupSubNet(const char* pszName, CSubNet& ret)
{
    std::string strSubnet(pszName);
    size_t slash = strSubnet.find_last_of('/');
    std::vector<CNetAddr> vIP;

    std::string strAddress = strSubnet.substr(0, slash);
    if (LookupHost(strAddress.c_str(), vIP, 1, false))
    {
        CNetAddr network = vIP[0];
        if (slash != strSubnet.npos)
        {
            std::string strNetmask = strSubnet.substr(slash + 1);
            int32_t n;
            // IPv4 addresses start at offset 12, and first 12 bytes must match, so just offset n
            if (ParseInt32(strNetmask, &n)) { // If valid number, assume /24 syntax
                ret = CSubNet(network, n);
                return ret.IsValid();
            }
            else // If not a valid number, try full netmask syntax
            {
                // Never allow lookup for netmask
                if (LookupHost(strNetmask.c_str(), vIP, 1, false)) {
                    ret = CSubNet(network, vIP[0]);
                    return ret.IsValid();
                }
            }
        }
        else
        {
            ret = CSubNet(network);
            return ret.IsValid();
        }
    }
    return false;
}
