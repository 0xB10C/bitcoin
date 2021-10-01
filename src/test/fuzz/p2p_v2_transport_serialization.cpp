// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/bip324_suite.h>
#include <key.h>
#include <net.h>
#include <netmessagemaker.h>
#include <test/fuzz/fuzz.h>

#include <cassert>

FUZZ_TARGET(p2p_v2_transport_serialization)
{
    // use keys with all zeros
    BIP324Key key_l, key_p, rekey_salt;
    memset(key_l.data(), 1, BIP324_KEY_LEN);
    memset(key_p.data(), 2, BIP324_KEY_LEN);
    memset(rekey_salt.data(), 3, BIP324_KEY_LEN);

    // Construct deserializer, with a dummy NodeId
    V2TransportDeserializer deserializer{(NodeId)0, key_l, key_p, rekey_salt};
    V2TransportSerializer serializer{key_l, key_p, rekey_salt};

    while (buffer.size() > 0) {
        const int handled = deserializer.Read(buffer);
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
