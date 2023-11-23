// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TRACE_H
#define BITCOIN_UTIL_TRACE_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#ifdef ENABLE_TRACING

// Setting SDT_USE_VARIADIC let's systemtap (sys/sdt.h) know that we want to use
// the optional variadic macros to define tracepoints.
#define SDT_USE_VARIADIC 1

#include <sys/sdt.h>

// Disabling this warning can be removed once we switch to C++20
#if defined(__clang__) && __cplusplus < 202002L
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_PUSH _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\"")
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_POP _Pragma("clang diagnostic pop")
#else
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_PUSH
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_POP
#endif

// A USDT tracepoint with zero to twelve arguments.
#define TRACEPOINT(context, ...)                                 \
    BITCOIN_DISABLE_WARN_ZERO_VARIADIC_PUSH                      \
    STAP_PROBEV(context, __VA_ARGS__);                           \
    BITCOIN_DISABLE_WARN_ZERO_VARIADIC_POP

#else

#define TRACEPOINT(context, ...)

#endif


#endif // BITCOIN_UTIL_TRACE_H
