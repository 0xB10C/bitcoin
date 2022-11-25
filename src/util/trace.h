// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TRACE_H
#define BITCOIN_UTIL_TRACE_H

#ifdef ENABLE_TRACING

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
    unsigned short context##_##event##_semaphore __attribute__((section (".probes")))

// Returns true if something is attached to the tracepoint.
#define TRACEPOINT_ACTIVE(context, event) context##_##event##_semaphore > 0

// A USDT tracepoint with zero to twelve arguments. Here, it **IS** checked that
// the tracepoint is active before preparing its arguments. Use the
// TRACEPOINT_UNCHECKED macro if you want to manually check that the tracepoint
// is active.
#define TRACEPOINT(context, event, args...) \
    if (TRACEPOINT_ACTIVE(context, event)) \
        STAP_PROBEV(context, event, args)

// A USDT tracepoint with zero to twelve arguments. Here, it is **NOT** checked
// that the tracepoint is active before preparing its arguments. Use this macro
// if you want to, for example, prepare expensive tracepoint arguments over
// multiple lines. Example usage:
//
//  if (TRACEPOINT_ACTIVE(context, event)) {
//      result = slightly_expensive_calulation();
//      TRACEPOINT_UNCHECKED(context, event, result);
// }
//
#define TRACEPOINT_UNCHECKED(context, event, args...) \
    STAP_PROBEV(context, event, args)

#else

#define TRACEPOINT_SEMAPHORE(context, event)
#define TRACEPOINT_ACTIVE(context, event) false
#define TRACEPOINT(context, event, ...)
#define TRACEPOINT_UNCHECKED(context, event, ...)

#endif // ENABLE_TRACING

#endif // BITCOIN_UTIL_TRACE_H
