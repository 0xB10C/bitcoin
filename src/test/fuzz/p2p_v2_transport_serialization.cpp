// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/endian.h>
#include <crypto/bip324_suite.h>
#include <crypto/rfc8439.h>
#include <key.h>
#include <net.h>
#include <netmessagemaker.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>

FUZZ_TARGET(p2p_v2_transport_serialization)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};

    // Picking constant keys seems to give us higher fuzz test coverage
    // The BIP324 Cipher suite is separately fuzzed, so we don't have to
    // pick fuzzed keys here.
    BIP324Key key_l, key_p, rekey_salt;
    memset(key_l.data(), 1, BIP324_KEY_LEN);
    memset(key_p.data(), 2, BIP324_KEY_LEN);
    memset(rekey_salt.data(), 3, BIP324_KEY_LEN);

    // Construct deserializer, with a dummy NodeId
    V2TransportDeserializer deserializer{(NodeId)0, key_l, key_p, rekey_salt};
    V2TransportSerializer serializer{key_l, key_p, rekey_salt};
    FSChaCha20 fsc20{key_l, rekey_salt, REKEY_INTERVAL};

    bool length_assist = fdp.ConsumeBool();
    auto payload_bytes = fdp.ConsumeRemainingBytes<uint8_t>();

    if (length_assist && payload_bytes.size() >= V2_MIN_MESSAGE_LENGTH) {
        uint32_t packet_len = payload_bytes.size() - BIP324_LENGTH_FIELD_LEN - RFC8439_TAGLEN;
        packet_len = htole32(packet_len);
        fsc20.Crypt({reinterpret_cast<std::byte*>(&packet_len), BIP324_LENGTH_FIELD_LEN},
                    {reinterpret_cast<std::byte*>(payload_bytes.data()), BIP324_LENGTH_FIELD_LEN});
    }

    Span<const uint8_t> msg_bytes{payload_bytes};
    while (msg_bytes.size() > 0) {
        const int handled = deserializer.Read(msg_bytes);
        if (handled < 0) {
            break;
        }
        if (deserializer.Complete()) {
            const std::chrono::microseconds m_time{std::numeric_limits<int64_t>::max()};
            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer.GetMessage(m_time, reject_message, disconnect)};
            if (!reject_message) {
                assert(result.m_type.size() <= CMessageHeader::COMMAND_SIZE);
                assert(result.m_raw_message_size <= buffer.size());
                assert(result.m_raw_message_size == V2_MIN_MESSAGE_LENGTH + result.m_message_size);
                assert(result.m_time == m_time);

                std::vector<unsigned char> header;
                auto msg = CNetMsgMaker{result.m_recv.GetVersion()}.Make(result.m_type, MakeUCharSpan(result.m_recv));
                assert(serializer.prepareForTransport(msg, header));
            }
        }
    }
}
