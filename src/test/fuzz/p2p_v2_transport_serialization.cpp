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

#include <array>
#include <cassert>
#include <cstddef>

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
    ChaCha20 c20{reinterpret_cast<unsigned char*>(key_p.data()), key_p.size()};

    std::array<std::byte, 12> nonce;
    memset(nonce.data(), 0, 12);
    c20.SetRFC8439Nonce(nonce);

    bool length_assist = fdp.ConsumeBool();

    // There is no sense in providing a mac assist if the length is incorrect.
    bool mac_assist = length_assist && fdp.ConsumeBool();
    auto payload_bytes = fdp.ConsumeRemainingBytes<uint8_t>();
    bool request_ignore_message{false};

    if (payload_bytes.size() >= V2_MIN_MESSAGE_LENGTH) {
        if (length_assist) {
            uint32_t packet_len = payload_bytes.size() - BIP324_LENGTH_FIELD_LEN - RFC8439_TAGLEN;
            packet_len = htole32(packet_len);
            fsc20.Crypt({reinterpret_cast<std::byte*>(&packet_len), BIP324_LENGTH_FIELD_LEN},
                        {reinterpret_cast<std::byte*>(payload_bytes.data()), BIP324_LENGTH_FIELD_LEN});
        }

        if (mac_assist) {
            std::array<std::byte, RFC8439_TAGLEN> tag;
            ComputeRFC8439Tag(GetPoly1305Key(c20), {},
                              {reinterpret_cast<std::byte*>(payload_bytes.data()) + BIP324_LENGTH_FIELD_LEN,
                              payload_bytes.size() - BIP324_LENGTH_FIELD_LEN - RFC8439_TAGLEN}, tag);
            memcpy(payload_bytes.data() + payload_bytes.size() - RFC8439_TAGLEN, tag.data(), RFC8439_TAGLEN);

            std::vector<std::byte> decrypted(payload_bytes.size() - BIP324_LENGTH_FIELD_LEN - RFC8439_TAGLEN);
            RFC8439Decrypt({}, key_p, nonce,
                           {reinterpret_cast<std::byte*>(payload_bytes.data() + BIP324_LENGTH_FIELD_LEN),
                            payload_bytes.size() - BIP324_LENGTH_FIELD_LEN},
                            decrypted);
            if (BIP324HeaderFlags((uint8_t)decrypted.at(0) & BIP324_IGNORE) != BIP324_NONE) {
                request_ignore_message = true;
            }
        }
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

            if (mac_assist) {
                assert(!disconnect);
            }

            if (request_ignore_message) {
                assert(reject_message);
            }

            if (!reject_message) {
                assert(result.m_type.size() <= CMessageHeader::COMMAND_SIZE);
                assert(result.m_raw_message_size <= buffer.size());

                auto message_type_size = result.m_raw_message_size - V2_MIN_MESSAGE_LENGTH - result.m_message_size;
                assert(message_type_size <= 13);
                assert(message_type_size >= 1);
                assert(result.m_time == m_time);

                std::vector<unsigned char> header;
                auto msg = CNetMsgMaker{result.m_recv.GetVersion()}.Make(result.m_type, MakeUCharSpan(result.m_recv));
                // if decryption succeeds, encryption must succeed
                assert(serializer.prepareForTransport(msg, header));
            }
        }
    }
}
