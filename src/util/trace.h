// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TRACE_H
#define BITCOIN_UTIL_TRACE_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

/*
#define TRACEPOINT_SEMAPHORE(context, event)
#define TRACEPOINT_ACTIVE(context, event) false
#define TRACEPOINT_DEFINITION(context, event, ...)
#define TRACEPOINT(context, ...)
*/

#ifdef ENABLE_TRACING

// Disabling this warning can be removed once we switch to C++20
#if defined(__clang__) && __cplusplus < 202002L
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_PUSH _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\"")
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_POP _Pragma("clang diagnostic pop")
#else
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_PUSH
#define BITCOIN_DISABLE_WARN_ZERO_VARIADIC_POP
#endif

#if defined(__APPLE__)
    #define STRING(s) #s

    #include <unistd.h>

    #define MACOS_STABILITY(context) STRING(___dtrace_stability$##context##$v1$1_1_0_1_1_0_1_1_0_1_1_0_1_1_0)
    #define MACOS_TYPEDEFS(context) STRING(___dtrace_typedefs$##context##$v2)

    #define TRACEPOINT(context, event, ...) \
        do { \
	    __asm__ volatile(".reference " MACOS_TYPEDEFS(context)); \
	    __dtrace_probe$##context##$##event##$v1(__VA_ARGS__); \
	    __asm__ volatile(".reference " MACOS_STABILITY(context)); \
        } while (0)

    #define	TRACEPOINT_ACTIVE(context, event) \
	    ({ int _r = __dtrace_isenabled$##context##$##event##$v1(); __asm__ volatile(""); _r; })

    #define TRACEPOINT_SEMAPHORE(context, event) \
        extern "C" int __dtrace_isenabled$##context##$##event##$v1(void);

    #define TRACEPOINT_DEFINITION(context, event, ...) \
        extern "C" void __dtrace_probe$##context##$##event##$v1(__VA_ARGS__);

#elif defined(__linux__)

    // Setting SDT_USE_VARIADIC let's systemtap (sys/sdt.h) know that we want to use
    // the optional variadic macros to define tracepoints.
    #define SDT_USE_VARIADIC 1

    // Setting _SDT_HAS_SEMAPHORES let's systemtap (sys/sdt.h) know that we want to
    // use the optional semaphore feature for our tracepoints. This feature allows
    // us to check if something is attached to a tracepoint. We only want to prepare
    // some potentially expensive tracepoint arguments, if the tracepoint is being
    // used. Here, an expensive argument preparation could, for example, be
    // calculating a hash or serialization of a data structure.
    #define _SDT_HAS_SEMAPHORES 1

    #include <sys/sdt.h>

    // Used to define a counting semaphore for a tracepoint. This semaphore is
    // automatically incremented by tracing frameworks (bpftrace, bcc, libbpf, ...)
    // upon attaching to the tracepoint and decremented when detaching. This needs
    // to be a global variable. It's placed in the '.probes' ELF section.
    #define TRACEPOINT_SEMAPHORE(context, event) \
        unsigned short context##_##event##_semaphore __attribute__((section(".probes")))

    // Extract the first argument of a variable number of arguments, even without warning
    // when only 1 argument is provided
    #define TRACEPOINT_FIRST_ARG(...) TRACEPOINT_FIRST_ARG_HELPER(__VA_ARGS__, dummy)
    #define TRACEPOINT_FIRST_ARG_HELPER(arg1, ...) arg1

    // Returns true if something is attached to the tracepoint.
    #define TRACEPOINT_ACTIVE(context, event) TRACEPOINT_ACTIVE_HELPER(context, event)
    #define TRACEPOINT_ACTIVE_HELPER(context, event) context##_##event##_semaphore > 0

    // A USDT tracepoint with one to twelve arguments. It's checked that the
    // tracepoint is active before preparing its arguments.
    #define TRACEPOINT(context, ...)                                                \
        do {                                                                        \
            if (TRACEPOINT_ACTIVE(context, TRACEPOINT_FIRST_ARG(__VA_ARGS__))) {    \
                BITCOIN_DISABLE_WARN_ZERO_VARIADIC_PUSH                             \
                STAP_PROBEV(context, __VA_ARGS__);                                  \
                BITCOIN_DISABLE_WARN_ZERO_VARIADIC_POP                              \
            }                                                                       \
        } while(0)

    #define TRACEPOINT_DEFINITION(context, event, ...)


#elif defined(__FreeBSD__)
    #include <sys/sdt.h>

    #define TRACEPOINT(context, event, ...) \
        __dtrace_##context##___##event(__VA_ARGS__)

    #define	TRACEPOINT_ACTIVE(context, event) \
        __dtraceenabled_##context##___##event()

    #define TRACEPOINT_SEMAPHORE(context, event) \
        extern "C" int __dtraceenabled_##context##___##event(long);

    #define TRACEPOINT_DEFINITION(context, event, ...) \
        extern "C" void __dtrace_##context##___##event(__VA_ARGS__);

#endif

// Tracepoints
TRACEPOINT_DEFINITION(net, outbound_message, int64_t, const char *, const char *, const char *, int64_t, const unsigned char *);
TRACEPOINT_DEFINITION(net, inbound_message, int64_t, const char *, const char *, const char *, int64_t, const unsigned char *);

TRACEPOINT_DEFINITION(validation, block_connected, unsigned char *, int32_t, uint64_t, int32_t, uint64_t, uint64_t);

/*


TRACEPOINT_DEFINITION(utxocache, flush, int64_t, uint32_t, uint64_t, uint64_t, uint8_t);
TRACEPOINT_DEFINITION(utxocache, add, unsigned char *, uint32_t, uint32_t, int64_t, uint8_t);
TRACEPOINT_DEFINITION(utxocache, spent, unsigned char *, uint32_t, uint32_t, int64_t, uint8_t);
TRACEPOINT_DEFINITION(utxocache, uncache, unsigned char *, uint32_t, uint32_t, int64_t, uint8_t);

TRACEPOINT_DEFINITION(coin_selection, selected_coins, char *, char *, int64_t, int64_t, int64_t) ;
TRACEPOINT_DEFINITION(coin_selection, normal_create_tx_internal, char *, uint8_t, int64_t, int32_t);
TRACEPOINT_DEFINITION(coin_selection, attempting_aps_create_tx, char *);
TRACEPOINT_DEFINITION(coin_selection, aps_create_tx_internal, char *, uint8_t, uint8_t, int64_t, int32_t);
*/
#endif // ENABLE_TRACING

#endif // BITCOIN_UTIL_TRACE_H
