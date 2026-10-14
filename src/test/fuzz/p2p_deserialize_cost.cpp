// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <blockfilter.h>
#include <common/bloom.h>
#include <merkleblock.h>
#include <net.h>
#include <netaddress.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <serialize.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util/cost.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace {

//! Deserializes a payload exactly as the matching ProcessMessage handler does,
//! and nothing else. `process_message` stays the ground truth; this harness
//! exists to isolate parse cost from handler cost and to run orders of
//! magnitude faster.
using Parser = void (*)(DataStream&);

//! Mirrors the hand-rolled loop in the HEADERS handler, including the one
//! count check that happens before the read.
void ParseHeaders(DataStream& s)
{
    const unsigned int count{static_cast<unsigned int>(ReadCompactSize(s))};
    if (count > MAX_HEADERS_RESULTS) return; // the handler returns after Misbehaving
    std::vector<CBlockHeader> headers(count);
    for (unsigned int n = 0; n < count; ++n) {
        s >> headers[n];
        ReadCompactSize(s);
    }
}

//! Mirrors the read sequence in the VERSION handler.
void ParseVersion(DataStream& s)
{
    int32_t version{0};
    uint64_t services{0};
    int64_t time{0};
    s >> version >> Using<CustomUintFormatter<8>>(services) >> time;
    s.ignore(8);
    CNetAddr addr_me;
    s >> CNetAddr::V1(addr_me);
    s.ignore(26);
    uint64_t nonce{0};
    s >> nonce;
    std::string subver;
    s >> LIMITED_STRING(subver, MAX_SUBVERSION_LENGTH);
    int32_t starting_height{0};
    uint8_t relay{0};
    s >> starting_height >> relay;
}

void ParseNothing(DataStream&) {}

const std::map<std::string, Parser>& Parsers()
{
    static const std::map<std::string, Parser> parsers{
        // No payload is read at all by these handlers.
        {NetMsgType::VERACK, ParseNothing},
        {NetMsgType::SENDADDRV2, ParseNothing},
        {NetMsgType::SENDHEADERS, ParseNothing},
        {NetMsgType::WTXIDRELAY, ParseNothing},
        {NetMsgType::FILTERCLEAR, ParseNothing},
        {NetMsgType::GETADDR, ParseNothing},
        {NetMsgType::MEMPOOL, ParseNothing},

        {NetMsgType::VERSION, ParseVersion},
        {NetMsgType::FEATURE, [](DataStream& s) {
             std::string feature_id;
             s >> LIMITED_STRING(feature_id, MAX_FEATUREID_LENGTH);
             std::vector<unsigned char> feature_data;
             s >> LIMITED_VECTOR(feature_data, MAX_FEATUREDATA_LENGTH);
         }},
        {NetMsgType::ADDR, [](DataStream& s) {
             std::vector<CAddress> v;
             s >> CAddress::V1_NETWORK(v);
         }},
        {NetMsgType::ADDRV2, [](DataStream& s) {
             std::vector<CAddress> v;
             s >> CAddress::V2_NETWORK(v);
         }},
        {NetMsgType::INV, [](DataStream& s) { std::vector<CInv> v; s >> v; }},
        {NetMsgType::GETDATA, [](DataStream& s) { std::vector<CInv> v; s >> v; }},
        {NetMsgType::NOTFOUND, [](DataStream& s) { std::vector<CInv> v; s >> v; }},
        {NetMsgType::GETBLOCKS, [](DataStream& s) {
             CBlockLocator l;
             uint256 stop;
             s >> l >> stop;
         }},
        {NetMsgType::GETHEADERS, [](DataStream& s) {
             CBlockLocator l;
             uint256 stop;
             s >> l >> stop;
         }},
        {NetMsgType::TX, [](DataStream& s) {
             CTransactionRef tx;
             s >> TX_WITH_WITNESS(tx);
         }},
        {NetMsgType::HEADERS, ParseHeaders},
        {NetMsgType::BLOCK, [](DataStream& s) {
             const auto block{std::make_shared<CBlock>()};
             s >> TX_WITH_WITNESS(*block);
         }},
        {NetMsgType::PING, [](DataStream& s) { uint64_t n{0}; s >> n; }},
        {NetMsgType::PONG, [](DataStream& s) { uint64_t n{0}; s >> n; }},
        {NetMsgType::FILTERLOAD, [](DataStream& s) { CBloomFilter f; s >> f; }},
        {NetMsgType::FILTERADD, [](DataStream& s) { std::vector<unsigned char> v; s >> v; }},
        {NetMsgType::FEEFILTER, [](DataStream& s) { CAmount a{0}; s >> a; }},
        {NetMsgType::SENDCMPCT, [](DataStream& s) {
             bool hb{false};
             uint64_t ver{0};
             s >> hb >> ver;
         }},
        {NetMsgType::CMPCTBLOCK, [](DataStream& s) { CBlockHeaderAndShortTxIDs c; s >> c; }},
        {NetMsgType::GETBLOCKTXN, [](DataStream& s) { BlockTransactionsRequest r; s >> r; }},
        {NetMsgType::BLOCKTXN, [](DataStream& s) { BlockTransactions r; s >> r; }},
        {NetMsgType::GETCFILTERS, [](DataStream& s) {
             uint8_t t{0};
             uint32_t h{0};
             uint256 stop;
             s >> t >> h >> stop;
         }},
        {NetMsgType::GETCFHEADERS, [](DataStream& s) {
             uint8_t t{0};
             uint32_t h{0};
             uint256 stop;
             s >> t >> h >> stop;
         }},
        {NetMsgType::GETCFCHECKPT, [](DataStream& s) {
             uint8_t t{0};
             uint256 stop;
             s >> t >> stop;
         }},
        {NetMsgType::SENDTXRCNCL, [](DataStream& s) {
             uint32_t ver{0};
             uint64_t salt{0};
             s >> ver >> salt;
         }},
        // Serialized by this node but never deserialized on the receive path.
        // Measured anyway: they are one BIP157-client or BIP37 patch away from
        // being reachable, and merkleblock is the second most expensive shape
        // in the whole protocol.
        {NetMsgType::MERKLEBLOCK, [](DataStream& s) { CMerkleBlock m; s >> m; }},
        {NetMsgType::CFILTER, [](DataStream& s) { BlockFilter f; s >> f; }},
        {NetMsgType::CFHEADERS, [](DataStream& s) {
             uint8_t t{0};
             uint256 stop, prev;
             std::vector<uint256> hashes;
             s >> t >> stop >> prev >> hashes;
         }},
        {NetMsgType::CFCHECKPT, [](DataStream& s) {
             uint8_t t{0};
             uint256 stop;
             std::vector<uint256> headers;
             s >> t >> stop >> headers;
         }},
    };
    return parsers;
}

std::string_view g_limit_to_type{};

} // namespace

void initialize_p2p_deserialize_cost()
{
    static const auto testing_setup{MakeNoLogFileContext<>()};

    // A new message type must not silently go unmeasured.
    for (const auto& type : ALL_NET_MESSAGE_TYPES) {
        Assert(Parsers().count(type) == 1);
    }

    if (const auto val{std::getenv("LIMIT_TO_MESSAGE_TYPE")}) {
        g_limit_to_type = val;
        Assert(std::count(ALL_NET_MESSAGE_TYPES.begin(), ALL_NET_MESSAGE_TYPES.end(), g_limit_to_type));
    }

    fuzz_cost::Init(ALL_NET_MESSAGE_TYPES);
}

FUZZ_TARGET(p2p_deserialize_cost, .init = initialize_p2p_deserialize_cost)
{
    size_t type_index;
    std::span<const uint8_t> payload_bytes;
    if (g_limit_to_type.empty()) {
        if (buffer.empty()) return;
        type_index = buffer[0] % ALL_NET_MESSAGE_TYPES.size();
        payload_bytes = buffer.subspan(1);
    } else {
        // One campaign per message type: the whole input is payload, so every
        // mutation stays on the type being measured.
        type_index = fuzz_cost::LabelIndex(g_limit_to_type);
        payload_bytes = buffer;
    }

    const std::string& type{ALL_NET_MESSAGE_TYPES[type_index]};

    // bytes_in counts what the attacker had to send, header included.
    // Pure deserialization touches no global state, so the trial may re-run it
    // to get a trustworthy timing on a candidate maximum.
    fuzz_cost::Trial trial{type_index, payload_bytes.size() + CMessageHeader::HEADER_SIZE,
                           buffer, /*repeatable=*/true};
    while (trial.Next()) {
        DataStream payload{payload_bytes};
        try {
            Parsers().at(type)(payload);
        } catch (const std::ios_base::failure&) {
        }
    }
}
