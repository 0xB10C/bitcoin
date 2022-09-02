/***********************************************************************
 * Copyright (c) 2022 Pieter Wuile                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ELLSWIFT_TESTS_H
#define SECP256K1_MODULE_ELLSWIFT_TESTS_H

#include "../../../include/secp256k1_ellswift.h"

/** This is a hasher for ellswift_xdh which just returns the shared X coordinate.
 *
 * This is generally a bad idea as it means changes to the encoding of the
 * exchanged public keys do not affect the shared secret. However, it's used here
 * in tests to be able to verify the X coordinate through other means.
 */
static int ellswift_xdh_hash_x32(unsigned char *output, const unsigned char *x32, const unsigned char *ours64, const unsigned char *theirs64, void *data) {
    (void)ours64;
    (void)theirs64;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

void run_ellswift_tests(void) {
    int i = 0;
    /* Verify that secp256k1_ellswift_encode + decode roundtrips. */
    for (i = 0; i < 1000 * count; i++) {
        unsigned char rnd32[32];
        unsigned char ell64[64];
        secp256k1_ge g, g2;
        secp256k1_pubkey pubkey, pubkey2;
        /* Generate random public key and random randomizer. */
        random_group_element_test(&g);
        secp256k1_pubkey_save(&pubkey, &g);
        secp256k1_testrand256(rnd32);
        /* Convert the public key to ElligatorSwift and back. */
        secp256k1_ellswift_encode(ctx, ell64, &pubkey, rnd32);
        secp256k1_ellswift_decode(ctx, &pubkey2, ell64);
        secp256k1_pubkey_load(ctx, &g2, &pubkey2);
        /* Compare with original. */
        ge_equals_ge(&g, &g2);
    }
    /* Verify the behavior of secp256k1_ellswift_create */
    for (i = 0; i < 400 * count; i++) {
        unsigned char rnd32[32], sec32[32];
        secp256k1_scalar sec;
        secp256k1_gej res;
        secp256k1_ge dec;
        secp256k1_pubkey pub;
        unsigned char ell64[64];
        int ret;
        /* Generate random secret key and random randomizer. */
        secp256k1_testrand256_test(rnd32);
        random_scalar_order_test(&sec);
        secp256k1_scalar_get_b32(sec32, &sec);
        /* Construct ElligatorSwift-encoded public keys for that key. */
        ret = secp256k1_ellswift_create(ctx, ell64, sec32, rnd32);
        CHECK(ret);
        /* Decode it, and compare with traditionally-computed public key. */
        secp256k1_ellswift_decode(ctx, &pub, ell64);
        secp256k1_pubkey_load(ctx, &dec, &pub);
        secp256k1_ecmult(&res, NULL, &secp256k1_scalar_zero, &sec);
        ge_equals_gej(&dec, &res);
    }
    /* Verify that secp256k1_ellswift_xdh computes the right shared X coordinate. */
    for (i = 0; i < 800 * count; i++) {
        unsigned char ell64[64], sec32[32], share32[32];
        secp256k1_scalar sec;
        secp256k1_ge dec, res;
        secp256k1_fe share_x;
        secp256k1_gej decj, resj;
        secp256k1_pubkey pub;
        int ret;
        /* Generate random secret key. */
        random_scalar_order_test(&sec);
        secp256k1_scalar_get_b32(sec32, &sec);
        /* Generate random ElligatorSwift encoding for the remote key and decode it. */
        secp256k1_testrand256_test(ell64);
        secp256k1_testrand256_test(ell64 + 32);
        secp256k1_ellswift_decode(ctx, &pub, ell64);
        secp256k1_pubkey_load(ctx, &dec, &pub);
        secp256k1_gej_set_ge(&decj, &dec);
        /* Compute the X coordinate of seckey*pubkey using ellswift_xdh. Note that we
         * pass ell64 as claimed (but incorrect) encoding for sec32 here; this works
         * because the "hasher" function we use here ignores the ours64 argument. */
        ret = secp256k1_ellswift_xdh(ctx, share32, ell64, ell64, sec32, &ellswift_xdh_hash_x32, NULL);
        CHECK(ret);
        secp256k1_fe_set_b32(&share_x, share32);
        /* Compute seckey*pubkey directly. */
        secp256k1_ecmult(&resj, &decj, &sec, NULL);
        secp256k1_ge_set_gej(&res, &resj);
        /* Compare. */
        CHECK(check_fe_equal(&res.x, &share_x));
    }
    /* Verify the joint behavior of secp256k1_ellswift_xdh */
    for (i = 0; i < 200 * count; i++) {
        unsigned char rnd32a[32], rnd32b[32], sec32a[32], sec32b[32];
        secp256k1_scalar seca, secb;
        unsigned char ell64a[64], ell64b[64];
        unsigned char share32a[32], share32b[32];
        int ret;
        /* Generate random secret keys and random randomizers. */
        secp256k1_testrand256_test(rnd32a);
        secp256k1_testrand256_test(rnd32b);
        random_scalar_order_test(&seca);
        random_scalar_order_test(&secb);
        secp256k1_scalar_get_b32(sec32a, &seca);
        secp256k1_scalar_get_b32(sec32b, &secb);
        /* Construct ElligatorSwift-encoded public keys for those keys. */
        ret = secp256k1_ellswift_create(ctx, ell64a, sec32a, rnd32a);
        CHECK(ret);
        ret = secp256k1_ellswift_create(ctx, ell64b, sec32b, rnd32b);
        CHECK(ret);
        /* Compute the shared secret both ways and compare with each other. */
        ret = secp256k1_ellswift_xdh(ctx, share32a, ell64a, ell64b, sec32b, NULL, NULL);
        CHECK(ret);
        ret = secp256k1_ellswift_xdh(ctx, share32b, ell64b, ell64a, sec32a, NULL, NULL);
        CHECK(ret);
        CHECK(secp256k1_memcmp_var(share32a, share32b, 32) == 0);
        /* Verify that the shared secret doesn't match if a secret key or remote pubkey changes. */
        secp256k1_testrand_flip(ell64a, 64);
        ret = secp256k1_ellswift_xdh(ctx, share32a, ell64a, ell64b, sec32b, NULL, NULL);
        CHECK(ret);
        CHECK(secp256k1_memcmp_var(share32a, share32b, 32) != 0);
        secp256k1_testrand_flip(sec32a, 32);
        ret = secp256k1_ellswift_xdh(ctx, share32a, ell64a, ell64b, sec32b, NULL, NULL);
        CHECK(!ret || secp256k1_memcmp_var(share32a, share32b, 32) != 0);
    }
}

#endif
