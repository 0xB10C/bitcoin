// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TRACE_H
#define BITCOIN_UTIL_TRACE_H

#ifdef ENABLE_TRACING

// Setting SDT_USE_VARIADIC let's systemtap (sys/sdt.h) know that we want to use
// the optional variadic macros to define tracepoints.
#define SDT_USE_VARIADIC 1

#include <sys/sdt.h>

// A USDT tracepoint with no arguments.
#define TRACEPOINT0(context, event) \
    STAP_PROBE(context, event)

// A USDT tracepoint with one to twelve arguments.
#define TRACEPOINT(context, event, ...) \
    STAP_PROBEV(context, event, __VA_ARGS__)

#else

#define TRACEPOINT_SEMAPHORE(context, event)
#define TRACEPOINT_ACTIVE(context, event) false
#define TRACEPOINT0(context, event)
#define TRACEPOINT(context, event, ...)

#endif


#endif // BITCOIN_UTIL_TRACE_H
