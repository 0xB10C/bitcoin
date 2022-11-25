// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <util/trace.h>

TRACEPOINT_SEMAPHORE(test, zero_args);
TRACEPOINT_SEMAPHORE(test, one_arg);
TRACEPOINT_SEMAPHORE(test, six_args);
TRACEPOINT_SEMAPHORE(test, twelve_args);

BOOST_FIXTURE_TEST_SUITE(util_trace_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_tracepoint_zero_args)
{
  TRACEPOINT0(test, zero_args);
  BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(test_tracepoint_n_args)
{
  TRACEPOINT(test, one_arg, 1);
  TRACEPOINT(test, six_args, 1, 2, 3, 4, 5, 6);
  TRACEPOINT(test, twelve_args, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
  BOOST_CHECK(true);
}

BOOST_AUTO_TEST_SUITE_END()
