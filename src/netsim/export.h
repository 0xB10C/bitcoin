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

/** Column headers, exposed so a test can assert the writer and the reader agree. */
std::string NodeColumns();
std::string EdgeColumns();
std::string AddrSampleColumns();

} // namespace netsim

#endif // BITCOIN_NETSIM_EXPORT_H
