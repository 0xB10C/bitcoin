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
 * Closed connections are included, marked `live=0` and carrying the instant
 * they closed. That is deliberate. A feeler only exists for a moment, and the
 * count and timing of short-lived connections is exactly what an analysis of
 * eclipse exposure or churn wants, so dropping them would throw away the more
 * interesting half of the record.
 *
 * Times are microseconds relative to the start of the run, so two runs are
 * comparable without knowing the arbitrary epoch.
 *
 * Returns false if either file could not be written.
 */
bool WriteGraph(const Network& net, const fs::path& prefix);

/** Column headers, exposed so a test can assert the writer and the reader agree. */
std::string NodeColumns();
std::string EdgeColumns();

} // namespace netsim

#endif // BITCOIN_NETSIM_EXPORT_H
