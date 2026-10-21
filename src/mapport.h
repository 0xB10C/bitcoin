// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MAPPORT_H
#define BITCOIN_MAPPORT_H

inline constexpr bool DEFAULT_NATPMP = true;

class LocalAddresses;

/** `local_addrs` receives the external address of any mapping created, and
 *  must outlive the mapping thread; InterruptMapPort and StopMapPort are what
 *  guarantee that. */
void StartMapPort(bool enable, LocalAddresses& local_addrs);
void InterruptMapPort();
void StopMapPort();

#endif // BITCOIN_MAPPORT_H
