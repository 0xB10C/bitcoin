// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETSIM_EXPORT_H
#define BITCOIN_NETSIM_EXPORT_H

#include <util/fs.h>

#include <string>

namespace netsim {

class Network;

/** Write the network graph to `<prefix>-nodes.csv` and `<prefix>-edges.csv`.
 *
 * Two CSV files rather than GraphML or GML. Both networkx and igraph read an
 * edge list with attributes directly, the format needs no escaping rules for
 * the values involved, and it streams: at 100k nodes and a million edges a
 * single XML document would be slow to write and slower to parse, for no gain.
 *
 * The edge file is a snapshot of what is still up when the run ends. Closed
 * connections are left out, and are not retained in memory either: a node
 * opens roughly thirty feelers per simulated hour and each lives for a
 * moment, so over any long run they outnumber the topology and a file of them
 * would be a log rather than a graph.
 *
 * Times are microseconds relative to the start of the run, so two runs are
 * comparable without knowing the arbitrary epoch.
 *
 * Returns false if either file could not be written.
 */
bool WriteGraph(const Network& net, const fs::path& prefix);

/** Write the address-coverage samples to `path`, one row per sample.
 *
 * Empty unless the run tracked addresses, in which case this is the
 * propagation curve: for each withheld listener address, how many nodes held
 * it at each sample instant. Returns false if the file could not be written.
 */
bool WriteAddrSamples(const Network& net, const fs::path& path);

/** Write every per-node block arrival to `path`, one row per (block, node).
 *
 * This is the propagation curve in raw form: sort by height then by
 * `elapsed_us` and the nth row is the instant the nth node adopted that
 * block. Empty unless the run gave each node its own chain, where there is
 * something to observe. Returns false if the file could not be written.
 */
bool WriteBlockArrivals(const Network& net, const fs::path& path);

/** Write every first-time address acquisition to `path`.
 *
 * The address-relay counterpart of `WriteBlockArrivals`: one row per (tracked
 * address, node), carrying when that node first held it. Resolution is the
 * sampling interval. Returns false if the file could not be written.
 */
bool WriteAddrArrivals(const Network& net, const fs::path& path);

/** Write the forwarding graph the tracked addresses travel in to `path`.
 *
 * One row per (tracked address, node, rank). Where `WriteAddrArrivals` records
 * the edges an announcement actually used, this records the edges that were
 * there to use, including those of nodes the announcement never reached — the
 * difference between a part of the network that could not be reached and one
 * that was merely reached late. Empty unless `Network::SampleRelayGraph` was
 * called. Returns false if the file could not be written.
 */
bool WriteRelayGraph(const Network& net, const fs::path& path);

/** Column headers, exposed so a test can assert the writer and the reader agree. */
std::string NodeColumns();
std::string EdgeColumns();
std::string AddrSampleColumns();
std::string BlockArrivalColumns();
std::string AddrArrivalColumns();
std::string RelayEdgeColumns();

} // namespace netsim

#endif // BITCOIN_NETSIM_EXPORT_H
