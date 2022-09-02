// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/bip324_suite.h>

#include <crypto/common.h>
#include <crypto/poly1305.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <span.h>
#include <support/cleanse.h>

#include <assert.h>
#include <cstring>
#include <string.h>

#ifndef HAVE_TIMINGSAFE_BCMP

int timingsafe_bcmp(const unsigned char* b1, const unsigned char* b2, size_t n)
{
    const unsigned char *p1 = b1, *p2 = b2;
    int ret = 0;

    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return (ret != 0);
}

#endif // TIMINGSAFE_BCMP

BIP324CipherSuite::~BIP324CipherSuite()
{
    memory_cleanse(payload_key.data(), payload_key.size());
    memory_cleanse(rekey_salt.data(), rekey_salt.size());
}

void BIP324CipherSuite::CommitToKeys(const Span<const std::byte> data, bool commit_to_L, bool commit_to_P)
{
    if (commit_to_L) {
        fsc20.CommitToKey(data);
    }

    if (commit_to_P) {
        HashWriter hasher;
        assert(CSHA256::OUTPUT_SIZE == BIP324_KEY_LEN);
        hasher << MakeUCharSpan(rekey_salt) << MakeUCharSpan(data) << MakeUCharSpan(payload_key);
        auto new_key = hasher.GetSHA256();
        memcpy(payload_key.data(), new_key.data(), BIP324_KEY_LEN);
    }

    rekey_ctr++;
    msg_ctr = 0;
    set_nonce();
}

bool BIP324CipherSuite::Crypt(const Span<const std::byte> aad,
                              const Span<const std::byte> input,
                              Span<std::byte> output,
                              BIP324HeaderFlags& flags, bool encrypt)
{
    // check buffer boundaries
    if (
        // if we encrypt, make sure the destination has the space for the length field, header, ciphertext and MAC
        (encrypt && (output.size() < BIP324_LENGTH_FIELD_LEN + BIP324_HEADER_LEN + input.size() + RFC8439_TAGLEN)) ||
        // if we decrypt, make sure the source contains at least the header + mac and the destination has the space for the source - MAC - header
        (!encrypt && (input.size() < BIP324_HEADER_LEN + RFC8439_TAGLEN || output.size() < input.size() - BIP324_HEADER_LEN - RFC8439_TAGLEN))) {
        return false;
    }

    if (encrypt) {
        // input is just the payload
        // output will be encrypted length + encrypted (header and payload) + mac tag
        uint32_t ciphertext_len = BIP324_HEADER_LEN + input.size();
        WriteLE32(reinterpret_cast<unsigned char*>(&ciphertext_len), ciphertext_len);

        std::vector<std::byte> input_vec;
        input_vec.resize(BIP324_HEADER_LEN + input.size());

        memcpy(input_vec.data(), &flags, BIP324_HEADER_LEN);
        if (!input.empty()) {
            memcpy(input_vec.data() + BIP324_HEADER_LEN, input.data(), input.size());
        }

        auto write_pos = output.data();
        fsc20.Crypt({reinterpret_cast<std::byte*>(&ciphertext_len), BIP324_LENGTH_FIELD_LEN},
                    {write_pos, BIP324_LENGTH_FIELD_LEN});
        write_pos += BIP324_LENGTH_FIELD_LEN;
        RFC8439Encrypt(aad, payload_key, nonce, input_vec, {write_pos, BIP324_HEADER_LEN + input.size() + RFC8439_TAGLEN});

    } else {
        // we must use BIP324CipherSuite::DecryptLength before calling BIP324CipherSuite::Crypt
        // input is encrypted (header + payload) and the mac tag
        // decrypted header will be put in flags and output will be payload.
        std::vector<std::byte> decrypted_plaintext(input.size() - RFC8439_TAGLEN);
        auto authenticated = RFC8439Decrypt(aad, payload_key, nonce, input, decrypted_plaintext);
        if (!authenticated) {
            return false;
        }

        memcpy(&flags, decrypted_plaintext.data(), BIP324_HEADER_LEN);
        if (!output.empty()) {
            memcpy(output.data(), decrypted_plaintext.data() + BIP324_HEADER_LEN, input.size() - BIP324_HEADER_LEN - RFC8439_TAGLEN);
        }
    }

    msg_ctr++;
    if (msg_ctr == REKEY_INTERVAL) {
        // Rekey key_P. key_L is automatically re-keyed since we're using a forward-secure version
        // of ChaCha20, FSChacha20
        CommitToKeys({(std::byte*)nullptr, 0}, false, true);
    }
    set_nonce();
    return true;
}

uint32_t BIP324CipherSuite::DecryptLength(const std::array<std::byte, BIP324_LENGTH_FIELD_LEN>& ciphertext)
{
    std::array<uint8_t, BIP324_LENGTH_FIELD_LEN> length_buffer;
    fsc20.Crypt(ciphertext, MakeWritableByteSpan(length_buffer));

    return (uint32_t{length_buffer[0]}) |
           (uint32_t{length_buffer[1]} << 8) |
           (uint32_t{length_buffer[2]} << 16);
}
