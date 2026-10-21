// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netsim/export.h>

#include <net.h>
#include <netgroup.h>
#include <netsim/addresses.h>
#include <netsim/network.h>
#include <netsim/node.h>
#include <node/connection_types.h>
#include <util/strencodings.h>

#include <cstdint>
#include <fstream>
#include <string>

namespace netsim {

namespace {
/** Live degree of one node, split by connection kind. */
struct Degree {
    size_t full_relay{0};
    size_t block_relay{0};
    size_t feeler{0};
    size_t inbound{0};
};

Degree LiveDegree(const SimNode& node)
{
    Degree degree;
    for (const CNode* peer : node.connman->TestNodes()) {
        if (peer->IsInboundConn()) {
            ++degree.inbound;
        } else if (peer->IsBlockOnlyConn()) {
            ++degree.block_relay;
        } else if (peer->IsFeelerConn()) {
            ++degree.feeler;
        } else {
            ++degree.full_relay;
        }
    }
    return degree;
}

} // namespace

std::string NodeColumns()
{
    return "id,address,network,listening,region,netgroup,addrman_total,addrman_tried,"
           "out_full_relay,out_block_relay,out_feeler,inbound";
}

std::string EdgeColumns()
{
    return "initiator,acceptor,conn_type,opened_us,bytes_to_acceptor,bytes_to_initiator";
}

std::string BlockArrivalColumns()
{
    return "height,hash,node,elapsed_us,from";
}

bool WriteBlockArrivals(const Network& net, const fs::path& path)
{
    std::ofstream out{path.std_path()};
    if (!out.is_open()) return false;
    out << BlockArrivalColumns() << "\n";

    const SimTime start{net.StartTime()};
    for (const Network::BlockArrival& arrival : net.BlockArrivals()) {
        out << arrival.height << ','
            << arrival.hash.ToString() << ','
            << arrival.node << ','
            << (arrival.at - start).count() << ','
            << arrival.from << '\n';
    }
    out.flush();
    return out.good();
}

std::string AddrArrivalColumns()
{
    return "address_of,node,elapsed_us";
}

bool WriteAddrArrivals(const Network& net, const fs::path& path)
{
    std::ofstream out{path.std_path()};
    if (!out.is_open()) return false;
    out << AddrArrivalColumns() << "\n";

    const SimTime start{net.StartTime()};
    for (const Network::AddrArrival& arrival : net.AddrArrivals()) {
        out << arrival.address_of << ','
            << arrival.node << ','
            << (arrival.at - start).count() << '\n';
    }
    out.flush();
    return out.good();
}

std::string AddrSampleColumns()
{
    return "elapsed_us,node,address,holders,in_tried,multiplicity";
}

bool WriteAddrSamples(const Network& net, const fs::path& path)
{
    std::ofstream out{path.std_path()};
    if (!out.is_open()) return false;
    out << AddrSampleColumns() << "\n";

    const SimTime start{net.StartTime()};
    for (const Network::AddrSample& sample : net.AddrSamples()) {
        out << (sample.at - start).count() << ','
            << sample.node << ','
            << net.At(sample.node).self.ToStringAddrPort() << ','
            << sample.holders << ','
            << sample.in_tried << ','
            << sample.multiplicity << '\n';
    }
    out.flush();
    return out.good();
}

bool WriteGraph(const Network& net, const fs::path& prefix)
{
    const fs::path nodes_path{fs::PathFromString(fs::PathToString(prefix) + "-nodes.csv")};
    const fs::path edges_path{fs::PathFromString(fs::PathToString(prefix) + "-edges.csv")};
    const SimTime start{net.StartTime()};

    {
        std::ofstream out{nodes_path.std_path()};
        if (!out.is_open()) return false;
        out << NodeColumns() << "\n";

        for (uint32_t id{0}; id < net.NumNodes(); ++id) {
            const SimNode& node{net.At(id)};
            const Degree degree{LiveDegree(node)};
            // The netgroup as Core computes it, hex-encoded. Grouping by this
            // column is how an analysis asks whether outbound diversity
            // actually held.
            const std::string netgroup{HexStr(net.Context().netgroupman.GetGroup(node.self))};

            out << id << ','
                << node.self.ToStringAddrPort() << ','
                << AddressUniverse::NetName(net.Addresses().NetOf(id)) << ','
                << (node.listening ? 1 : 0) << ','
                << net.Latency().Region(id) << ','
                << netgroup << ','
                << node.addrman->Size() << ','
                << node.addrman->Size(/*net=*/std::nullopt, /*in_new=*/false) << ','
                << degree.full_relay << ','
                << degree.block_relay << ','
                << degree.feeler << ','
                << degree.inbound << '\n';
        }
        out.flush();
        if (!out.good()) return false;
    }

    {
        std::ofstream out{edges_path.std_path()};
        if (!out.is_open()) return false;
        out << EdgeColumns() << "\n";

        // A snapshot of what is still up. Closed links are left out, and their
        // slots have in any case already been recycled.
        for (const Link& link : net.Links()) {
            if (link.closed) continue;
            out << link.initiator << ','
                << link.acceptor << ','
                << ConnectionTypeAsString(link.conn_type) << ','
                << (link.opened_at - start).count() << ','
                << link.bytes_to_acceptor << ','
                << link.bytes_to_initiator << '\n';
        }
        out.flush();
        if (!out.good()) return false;
    }

    return true;
}

} // namespace netsim
