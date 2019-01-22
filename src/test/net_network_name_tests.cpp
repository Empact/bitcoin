// Copyright (c) 2012-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/network_name.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(net_network_name_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(net_network_name_ParseNetworkName)
{
    BOOST_CHECK_EQUAL(ParseNetworkName("ipv4"), NET_IPV4);
    BOOST_CHECK_EQUAL(ParseNetworkName("ipv6"), NET_IPV6);
    BOOST_CHECK_EQUAL(ParseNetworkName("onion"), NET_ONION);
    BOOST_CHECK_EQUAL(ParseNetworkName("tor"), NET_ONION);

    BOOST_CHECK_EQUAL(ParseNetworkName("IPv4"), NET_IPV4);
    BOOST_CHECK_EQUAL(ParseNetworkName("IPv6"), NET_IPV6);
    BOOST_CHECK_EQUAL(ParseNetworkName("ONION"), NET_ONION);
    BOOST_CHECK_EQUAL(ParseNetworkName("TOR"), NET_ONION);

    BOOST_CHECK_EQUAL(ParseNetworkName(":)"), NET_UNROUTABLE);
    BOOST_CHECK_EQUAL(ParseNetworkName("tÖr"), NET_UNROUTABLE);
    BOOST_CHECK_EQUAL(ParseNetworkName("\xfe\xff"), NET_UNROUTABLE);
    BOOST_CHECK_EQUAL(ParseNetworkName(""), NET_UNROUTABLE);
}

BOOST_AUTO_TEST_SUITE_END()
