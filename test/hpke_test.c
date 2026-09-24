/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/hpke.h>
#include "testutil.h"

/* a size to use for stack buffers */
#define OSSL_HPKE_TSTSIZE 512

static OSSL_LIB_CTX *testctx = NULL;
static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *deflprov = NULL;
static char *testpropq = "provider=default";
static int verbose = 0;

typedef struct {
    int mode;
    OSSL_HPKE_SUITE suite;
    const unsigned char *ikmE;
    size_t ikmElen;
    const unsigned char *expected_pkEm;
    size_t expected_pkEmlen;
    const unsigned char *ikmR;
    size_t ikmRlen;
    const unsigned char *expected_pkRm;
    size_t expected_pkRmlen;
    const unsigned char *expected_skRm;
    size_t expected_skRmlen;
    const unsigned char *expected_secret;
    size_t expected_secretlen;
    const unsigned char *ksinfo;
    size_t ksinfolen;
    const unsigned char *ikmAuth;
    size_t ikmAuthlen;
    const unsigned char *psk;
    size_t psklen;
    const char *pskid; /* want terminating NUL here */
} TEST_BASEDATA;

typedef struct {
    int seq;
    const unsigned char *pt;
    size_t ptlen;
    const unsigned char *aad;
    size_t aadlen;
    const unsigned char *expected_ct;
    size_t expected_ctlen;
} TEST_AEADDATA;

typedef struct {
    const unsigned char *context;
    size_t contextlen;
    const unsigned char *expected_secret;
    size_t expected_secretlen;
} TEST_EXPORTDATA;

/**
 * @brief Test that an EVP_PKEY encoded public key matches the supplied buffer
 * @param pkey is the EVP_PKEY we want to check
 * @param pub is the expected public key buffer
 * @param publen is the length of the above
 * @return 1 for good, 0 for bad
 */
static int cmpkey(const EVP_PKEY *pkey,
    const unsigned char *pub, size_t publen)
{
    unsigned char pubbuf[256];
    size_t pubbuflen = 0;
    int erv = 0;

    if (!TEST_true(publen <= sizeof(pubbuf)))
        return 0;
    erv = EVP_PKEY_get_octet_string_param(pkey,
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        pubbuf, sizeof(pubbuf), &pubbuflen);
    if (!TEST_true(erv))
        return 0;
    if (pub != NULL && !TEST_mem_eq(pubbuf, pubbuflen, pub, publen))
        return 0;
    return 1;
}

static int do_testhpke(const TEST_BASEDATA *base,
    const TEST_AEADDATA *aead, size_t aeadsz,
    const TEST_EXPORTDATA *export, size_t exportsz)
{
    OSSL_LIB_CTX *libctx = testctx;
    const char *propq = testpropq;
    OSSL_HPKE_CTX *sealctx = NULL, *openctx = NULL;
    unsigned char ct[256];
    unsigned char enc[256];
    unsigned char ptout[256];
    size_t ptoutlen = sizeof(ptout);
    size_t enclen = sizeof(enc);
    size_t ctlen = sizeof(ct);
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    EVP_PKEY *privE = NULL;
    unsigned char authpub[OSSL_HPKE_TSTSIZE];
    size_t authpublen = sizeof(authpub);
    EVP_PKEY *authpriv = NULL;
    unsigned char rpub[OSSL_HPKE_TSTSIZE];
    size_t rpublen = sizeof(pub);
    EVP_PKEY *privR = NULL;
    int ret = 0;
    size_t i;
    uint64_t lastseq = 0;

    if (!TEST_true(OSSL_HPKE_keygen(base->suite, pub, &publen, &privE,
            base->ikmE, base->ikmElen, libctx, propq)))
        goto end;
    if (!TEST_true(cmpkey(privE, base->expected_pkEm, base->expected_pkEmlen)))
        goto end;
    if (!TEST_ptr(sealctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                      OSSL_HPKE_ROLE_SENDER,
                      libctx, propq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_ikme(sealctx, base->ikmE, base->ikmElen)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_AUTH
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(base->ikmAuth != NULL && base->ikmAuthlen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_keygen(base->suite,
                authpub, &authpublen, &authpriv,
                base->ikmAuth, base->ikmAuthlen,
                libctx, propq)))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(sealctx, authpriv)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_keygen(base->suite, rpub, &rpublen, &privR,
            base->ikmR, base->ikmRlen, libctx, propq)))
        goto end;
    if (!TEST_true(cmpkey(privR, base->expected_pkRm, base->expected_pkRmlen)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(sealctx, base->pskid,
                base->psk, base->psklen)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_encap(sealctx, enc, &enclen,
            rpub, rpublen,
            base->ksinfo, base->ksinfolen)))
        goto end;
    if (!TEST_true(cmpkey(privE, enc, enclen)))
        goto end;
    for (i = 0; i < aeadsz; ++i) {
        ctlen = sizeof(ct);
        memset(ct, 0, ctlen);
        if (!TEST_true(OSSL_HPKE_seal(sealctx, ct, &ctlen,
                aead[i].aad, aead[i].aadlen,
                aead[i].pt, aead[i].ptlen)))
            goto end;
        if (!TEST_mem_eq(ct, ctlen, aead[i].expected_ct,
                aead[i].expected_ctlen))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_get_seq(sealctx, &lastseq)))
            goto end;
        if (lastseq != (uint64_t)(i + 1))
            goto end;
    }
    if (!TEST_ptr(openctx = OSSL_HPKE_CTX_new(base->mode, base->suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      libctx, propq)))
        goto end;
    if (base->mode == OSSL_HPKE_MODE_PSK
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(base->pskid != NULL && base->psk != NULL
                && base->psklen > 0))
            goto end;
        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(openctx, base->pskid,
                base->psk, base->psklen)))
            goto end;
    }
    if (base->mode == OSSL_HPKE_MODE_AUTH
        || base->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(openctx,
                authpub, authpublen)))
            goto end;
    }
    if (!TEST_true(OSSL_HPKE_decap(openctx, enc, enclen, privR,
            base->ksinfo, base->ksinfolen)))
        goto end;
    for (i = 0; i < aeadsz; ++i) {
        ptoutlen = sizeof(ptout);
        memset(ptout, 0, ptoutlen);
        if (!TEST_true(OSSL_HPKE_open(openctx, ptout, &ptoutlen,
                aead[i].aad, aead[i].aadlen,
                aead[i].expected_ct,
                aead[i].expected_ctlen)))
            goto end;
        if (!TEST_mem_eq(aead[i].pt, aead[i].ptlen, ptout, ptoutlen))
            goto end;
        /* check the sequence is being incremented as expected */
        if (!TEST_true(OSSL_HPKE_CTX_get_seq(openctx, &lastseq)))
            goto end;
        if (lastseq != (uint64_t)(i + 1))
            goto end;
    }
    /* check exporters */
    for (i = 0; i < exportsz; ++i) {
        size_t len = export[i].expected_secretlen;
        unsigned char eval[OSSL_HPKE_TSTSIZE];

        if (len > sizeof(eval))
            goto end;
        /* export with too long label should fail */
        if (!TEST_false(OSSL_HPKE_export(sealctx, eval, len,
                export[i].context, -1)))
            goto end;
        /* good export call */
        if (!TEST_true(OSSL_HPKE_export(sealctx, eval, len,
                export[i].context,
                export[i].contextlen)))
            goto end;
        if (!TEST_mem_eq(eval, len, export[i].expected_secret,
                export[i].expected_secretlen))
            goto end;
        if (!TEST_true(OSSL_HPKE_export(openctx, eval, len,
                export[i].context, export[i].contextlen))
            || !TEST_mem_eq(eval, len, export[i].expected_secret,
                export[i].expected_secretlen))
            goto end;

        /* check seal fails if export only mode */
        if (base->suite.aead_id == OSSL_HPKE_AEAD_ID_EXPORTONLY) {

            if (!TEST_false(OSSL_HPKE_seal(sealctx, ct, &ctlen,
                    NULL, 0, ptout, ptoutlen)))
                goto end;
        }
    }
    ret = 1;
end:
    OSSL_HPKE_CTX_free(sealctx);
    OSSL_HPKE_CTX_free(openctx);
    EVP_PKEY_free(privE);
    EVP_PKEY_free(privR);
    EVP_PKEY_free(authpriv);
    return ret;
}

static const unsigned char pt[] = {
    0x42, 0x65, 0x61, 0x75, 0x74, 0x79, 0x20, 0x69,
    0x73, 0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x2c,
    0x20, 0x74, 0x72, 0x75, 0x74, 0x68, 0x20, 0x62,
    0x65, 0x61, 0x75, 0x74, 0x79
};
static const unsigned char ksinfo[] = {
    0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61,
    0x20, 0x47, 0x72, 0x65, 0x63, 0x69, 0x61, 0x6e,
    0x20, 0x55, 0x72, 0x6e
};
#ifndef OPENSSL_NO_ECX
/*
 * static const char *pskid = "Ennyn Durin aran Moria";
 */
static const unsigned char pskid[] = {
    0x45, 0x6e, 0x6e, 0x79, 0x6e, 0x20, 0x44, 0x75,
    0x72, 0x69, 0x6e, 0x20, 0x61, 0x72, 0x61, 0x6e,
    0x20, 0x4d, 0x6f, 0x72, 0x69, 0x61, 0x00
};
static const unsigned char psk[] = {
    0x02, 0x47, 0xfd, 0x33, 0xb9, 0x13, 0x76, 0x0f,
    0xa1, 0xfa, 0x51, 0xe1, 0x89, 0x2d, 0x9f, 0x30,
    0x7f, 0xbe, 0x65, 0xeb, 0x17, 0x1e, 0x81, 0x32,
    0xc2, 0xaf, 0x18, 0x55, 0x5a, 0x73, 0x8b, 0x82
};

/* these need to be "outside" the function below to keep check-ansi CI happy */
static const unsigned char first_ikme[] = {
    0x78, 0x62, 0x8c, 0x35, 0x4e, 0x46, 0xf3, 0xe1,
    0x69, 0xbd, 0x23, 0x1b, 0xe7, 0xb2, 0xff, 0x1c,
    0x77, 0xaa, 0x30, 0x24, 0x60, 0xa2, 0x6d, 0xbf,
    0xa1, 0x55, 0x15, 0x68, 0x4c, 0x00, 0x13, 0x0b
};
static const unsigned char first_ikmr[] = {
    0xd4, 0xa0, 0x9d, 0x09, 0xf5, 0x75, 0xfe, 0xf4,
    0x25, 0x90, 0x5d, 0x2a, 0xb3, 0x96, 0xc1, 0x44,
    0x91, 0x41, 0x46, 0x3f, 0x69, 0x8f, 0x8e, 0xfd,
    0xb7, 0xac, 0xcf, 0xaf, 0xf8, 0x99, 0x50, 0x98
};
static const unsigned char first_ikmepub[] = {
    0x0a, 0xd0, 0x95, 0x0d, 0x9f, 0xb9, 0x58, 0x8e, 0x59, 0x69,
    0x0b, 0x74, 0xf1, 0x23, 0x7e, 0xcd, 0xf1, 0xd7, 0x75, 0xcd,
    0x60, 0xbe, 0x2e, 0xca, 0x57, 0xaf, 0x5a, 0x4b, 0x04, 0x71,
    0xc9, 0x1b
};
static const unsigned char first_ikmrpub[] = {
    0x9f, 0xed, 0x7e, 0x8c, 0x17, 0x38, 0x75, 0x60,
    0xe9, 0x2c, 0xc6, 0x46, 0x2a, 0x68, 0x04, 0x96,
    0x57, 0x24, 0x6a, 0x09, 0xbf, 0xa8, 0xad, 0xe7,
    0xae, 0xfe, 0x58, 0x96, 0x72, 0x01, 0x63, 0x66
};
static const unsigned char first_ikmrpriv[] = {
    0xc5, 0xeb, 0x01, 0xeb, 0x45, 0x7f, 0xe6, 0xc6,
    0xf5, 0x75, 0x77, 0xc5, 0x41, 0x3b, 0x93, 0x15,
    0x50, 0xa1, 0x62, 0xc7, 0x1a, 0x03, 0xac, 0x8d,
    0x19, 0x6b, 0xab, 0xbd, 0x4e, 0x5c, 0xe0, 0xfd
};
static const unsigned char first_expected_shared_secret[] = {
    0x72, 0x76, 0x99, 0xf0, 0x09, 0xff, 0xe3, 0xc0,
    0x76, 0x31, 0x50, 0x19, 0xc6, 0x96, 0x48, 0x36,
    0x6b, 0x69, 0x17, 0x14, 0x39, 0xbd, 0x7d, 0xd0,
    0x80, 0x77, 0x43, 0xbd, 0xe7, 0x69, 0x86, 0xcd
};
static const unsigned char first_aad0[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30
};
static const unsigned char first_ct0[] = {
    0xe5, 0x2c, 0x6f, 0xed, 0x7f, 0x75, 0x8d, 0x0c,
    0xf7, 0x14, 0x56, 0x89, 0xf2, 0x1b, 0xc1, 0xbe,
    0x6e, 0xc9, 0xea, 0x09, 0x7f, 0xef, 0x4e, 0x95,
    0x94, 0x40, 0x01, 0x2f, 0x4f, 0xeb, 0x73, 0xfb,
    0x61, 0x1b, 0x94, 0x61, 0x99, 0xe6, 0x81, 0xf4,
    0xcf, 0xc3, 0x4d, 0xb8, 0xea
};
static const unsigned char first_aad1[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x31
};
static const unsigned char first_ct1[] = {
    0x49, 0xf3, 0xb1, 0x9b, 0x28, 0xa9, 0xea, 0x9f,
    0x43, 0xe8, 0xc7, 0x12, 0x04, 0xc0, 0x0d, 0x4a,
    0x49, 0x0e, 0xe7, 0xf6, 0x13, 0x87, 0xb6, 0x71,
    0x9d, 0xb7, 0x65, 0xe9, 0x48, 0x12, 0x3b, 0x45,
    0xb6, 0x16, 0x33, 0xef, 0x05, 0x9b, 0xa2, 0x2c,
    0xd6, 0x24, 0x37, 0xc8, 0xba
};
static const unsigned char first_aad2[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x32
};
static const unsigned char first_ct2[] = {
    0x25, 0x7c, 0xa6, 0xa0, 0x84, 0x73, 0xdc, 0x85,
    0x1f, 0xde, 0x45, 0xaf, 0xd5, 0x98, 0xcc, 0x83,
    0xe3, 0x26, 0xdd, 0xd0, 0xab, 0xe1, 0xef, 0x23,
    0xba, 0xa3, 0xba, 0xa4, 0xdd, 0x8c, 0xde, 0x99,
    0xfc, 0xe2, 0xc1, 0xe8, 0xce, 0x68, 0x7b, 0x0b,
    0x47, 0xea, 0xd1, 0xad, 0xc9
};
static const unsigned char first_export1[] = {
    0xdf, 0xf1, 0x7a, 0xf3, 0x54, 0xc8, 0xb4, 0x16,
    0x73, 0x56, 0x7d, 0xb6, 0x25, 0x9f, 0xd6, 0x02,
    0x99, 0x67, 0xb4, 0xe1, 0xaa, 0xd1, 0x30, 0x23,
    0xc2, 0xae, 0x5d, 0xf8, 0xf4, 0xf4, 0x3b, 0xf6
};
static const unsigned char first_context2[] = { 0x00 };
static const unsigned char first_export2[] = {
    0x6a, 0x84, 0x72, 0x61, 0xd8, 0x20, 0x7f, 0xe5,
    0x96, 0xbe, 0xfb, 0x52, 0x92, 0x84, 0x63, 0x88,
    0x1a, 0xb4, 0x93, 0xda, 0x34, 0x5b, 0x10, 0xe1,
    0xdc, 0xc6, 0x45, 0xe3, 0xb9, 0x4e, 0x2d, 0x95
};
static const unsigned char first_context3[] = {
    0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
    0x65, 0x78, 0x74
};
static const unsigned char first_export3[] = {
    0x8a, 0xff, 0x52, 0xb4, 0x5a, 0x1b, 0xe3, 0xa7,
    0x34, 0xbc, 0x7a, 0x41, 0xe2, 0x0b, 0x4e, 0x05,
    0x5a, 0xd4, 0xc4, 0xd2, 0x21, 0x04, 0xb0, 0xc2,
    0x02, 0x85, 0xa7, 0xc4, 0x30, 0x24, 0x01, 0xcd
};

static int x25519kdfsha256_hkdfsha256_aes128gcm_psk_test(void)
{
    const TEST_BASEDATA pskdata = {
        /* "X25519", NULL, "SHA256", "SHA256", "AES-128-GCM", */
        OSSL_HPKE_MODE_PSK,
        { OSSL_HPKE_KEM_ID_X25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128 },
        first_ikme, sizeof(first_ikme),
        first_ikmepub, sizeof(first_ikmepub),
        first_ikmr, sizeof(first_ikmr),
        first_ikmrpub, sizeof(first_ikmrpub),
        first_ikmrpriv, sizeof(first_ikmrpriv),
        first_expected_shared_secret, sizeof(first_expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0, /* No Auth */
        psk, sizeof(psk), (char *)pskid
    };
    const TEST_AEADDATA aeaddata[] = {
        { 0,
            pt, sizeof(pt),
            first_aad0, sizeof(first_aad0),
            first_ct0, sizeof(first_ct0) },
        { 1,
            pt, sizeof(pt),
            first_aad1, sizeof(first_aad1),
            first_ct1, sizeof(first_ct1) },
        { 2,
            pt, sizeof(pt),
            first_aad2, sizeof(first_aad2),
            first_ct2, sizeof(first_ct2) }
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, first_export1, sizeof(first_export1) },
        { first_context2, sizeof(first_context2),
            first_export2, sizeof(first_export2) },
        { first_context3, sizeof(first_context3),
            first_export3, sizeof(first_export3) },
    };
    return do_testhpke(&pskdata, aeaddata, OSSL_NELEM(aeaddata),
        exportdata, OSSL_NELEM(exportdata));
}

static const unsigned char second_ikme[] = {
    0x72, 0x68, 0x60, 0x0d, 0x40, 0x3f, 0xce, 0x43,
    0x15, 0x61, 0xae, 0xf5, 0x83, 0xee, 0x16, 0x13,
    0x52, 0x7c, 0xff, 0x65, 0x5c, 0x13, 0x43, 0xf2,
    0x98, 0x12, 0xe6, 0x67, 0x06, 0xdf, 0x32, 0x34
};
static const unsigned char second_ikmepub[] = {
    0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86,
    0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d, 0x1d, 0x12, 0x53, 0xb6,
    0xd4, 0xea, 0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf,
    0x44, 0x31
};
static const unsigned char second_ikmr[] = {
    0x6d, 0xb9, 0xdf, 0x30, 0xaa, 0x07, 0xdd, 0x42,
    0xee, 0x5e, 0x81, 0x81, 0xaf, 0xdb, 0x97, 0x7e,
    0x53, 0x8f, 0x5e, 0x1f, 0xec, 0x8a, 0x06, 0x22,
    0x3f, 0x33, 0xf7, 0x01, 0x3e, 0x52, 0x50, 0x37
};
static const unsigned char second_ikmrpub[] = {
    0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69,
    0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95, 0xda,
    0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79,
    0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d
};
static const unsigned char second_ikmrpriv[] = {
    0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad,
    0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa, 0xc5,
    0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9,
    0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8
};
static const unsigned char second_expected_shared_secret[] = {
    0xfe, 0x0e, 0x18, 0xc9, 0xf0, 0x24, 0xce, 0x43,
    0x79, 0x9a, 0xe3, 0x93, 0xc7, 0xe8, 0xfe, 0x8f,
    0xce, 0x9d, 0x21, 0x88, 0x75, 0xe8, 0x22, 0x7b,
    0x01, 0x87, 0xc0, 0x4e, 0x7d, 0x2e, 0xa1, 0xfc
};
static const unsigned char second_aead0[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30
};
static const unsigned char second_ct0[] = {
    0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2,
    0x38, 0x10, 0xb4, 0xbe, 0x2a, 0xb4, 0xf8, 0x43,
    0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5,
    0x3a, 0x52, 0xae, 0x82, 0x18, 0xa3, 0x55, 0xa9,
    0x6d, 0x87, 0x70, 0xac, 0x83, 0xd0, 0x7b, 0xea,
    0x87, 0xe1, 0x3c, 0x51, 0x2a
};
static const unsigned char second_aead1[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x31
};
static const unsigned char second_ct1[] = {
    0xaf, 0x2d, 0x7e, 0x9a, 0xc9, 0xae, 0x7e, 0x27,
    0x0f, 0x46, 0xba, 0x1f, 0x97, 0x5b, 0xe5, 0x3c,
    0x09, 0xf8, 0xd8, 0x75, 0xbd, 0xc8, 0x53, 0x54,
    0x58, 0xc2, 0x49, 0x4e, 0x8a, 0x6e, 0xab, 0x25,
    0x1c, 0x03, 0xd0, 0xc2, 0x2a, 0x56, 0xb8, 0xca,
    0x42, 0xc2, 0x06, 0x3b, 0x84
};
static const unsigned char second_export1[] = {
    0x38, 0x53, 0xfe, 0x2b, 0x40, 0x35, 0x19, 0x5a,
    0x57, 0x3f, 0xfc, 0x53, 0x85, 0x6e, 0x77, 0x05,
    0x8e, 0x15, 0xd9, 0xea, 0x06, 0x4d, 0xe3, 0xe5,
    0x9f, 0x49, 0x61, 0xd0, 0x09, 0x52, 0x50, 0xee
};
static const unsigned char second_context2[] = { 0x00 };
static const unsigned char second_export2[] = {
    0x2e, 0x8f, 0x0b, 0x54, 0x67, 0x3c, 0x70, 0x29,
    0x64, 0x9d, 0x4e, 0xb9, 0xd5, 0xe3, 0x3b, 0xf1,
    0x87, 0x2c, 0xf7, 0x6d, 0x62, 0x3f, 0xf1, 0x64,
    0xac, 0x18, 0x5d, 0xa9, 0xe8, 0x8c, 0x21, 0xa5
};
static const unsigned char second_context3[] = {
    0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
    0x65, 0x78, 0x74
};
static const unsigned char second_export3[] = {
    0xe9, 0xe4, 0x30, 0x65, 0x10, 0x2c, 0x38, 0x36,
    0x40, 0x1b, 0xed, 0x8c, 0x3c, 0x3c, 0x75, 0xae,
    0x46, 0xbe, 0x16, 0x39, 0x86, 0x93, 0x91, 0xd6,
    0x2c, 0x61, 0xf1, 0xec, 0x7a, 0xf5, 0x49, 0x31
};

static int x25519kdfsha256_hkdfsha256_aes128gcm_base_test(void)
{
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_BASE,
        { OSSL_HPKE_KEM_ID_X25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128 },
        second_ikme, sizeof(second_ikme),
        second_ikmepub, sizeof(second_ikmepub),
        second_ikmr, sizeof(second_ikmr),
        second_ikmrpub, sizeof(second_ikmrpub),
        second_ikmrpriv, sizeof(second_ikmrpriv),
        second_expected_shared_secret, sizeof(second_expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0, /* no auth ikm */
        NULL, 0, NULL /* no psk */
    };
    const TEST_AEADDATA aeaddata[] = {
        { 0,
            pt, sizeof(pt),
            second_aead0, sizeof(second_aead0),
            second_ct0, sizeof(second_ct0) },
        { 1,
            pt, sizeof(pt),
            second_aead1, sizeof(second_aead1),
            second_ct1, sizeof(second_ct1) }
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, second_export1, sizeof(second_export1) },
        { second_context2, sizeof(second_context2),
            second_export2, sizeof(second_export2) },
        { second_context3, sizeof(second_context3),
            second_export3, sizeof(second_export3) },
    };
    return do_testhpke(&basedata, aeaddata, OSSL_NELEM(aeaddata),
        exportdata, OSSL_NELEM(exportdata));
}
#endif

static const unsigned char third_ikme[] = {
    0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
    0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
    0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
    0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
};
static const unsigned char third_ikmepub[] = {
    0x04, 0xa9, 0x27, 0x19, 0xc6, 0x19, 0x5d, 0x50, 0x85, 0x10,
    0x4f, 0x46, 0x9a, 0x8b, 0x98, 0x14, 0xd5, 0x83, 0x8f, 0xf7,
    0x2b, 0x60, 0x50, 0x1e, 0x2c, 0x44, 0x66, 0xe5, 0xe6, 0x7b,
    0x32, 0x5a, 0xc9, 0x85, 0x36, 0xd7, 0xb6, 0x1a, 0x1a, 0xf4,
    0xb7, 0x8e, 0x5b, 0x7f, 0x95, 0x1c, 0x09, 0x00, 0xbe, 0x86,
    0x3c, 0x40, 0x3c, 0xe6, 0x5c, 0x9b, 0xfc, 0xb9, 0x38, 0x26,
    0x57, 0x22, 0x2d, 0x18, 0xc4
};
static const unsigned char third_ikmr[] = {
    0x66, 0x8b, 0x37, 0x17, 0x1f, 0x10, 0x72, 0xf3,
    0xcf, 0x12, 0xea, 0x8a, 0x23, 0x6a, 0x45, 0xdf,
    0x23, 0xfc, 0x13, 0xb8, 0x2a, 0xf3, 0x60, 0x9a,
    0xd1, 0xe3, 0x54, 0xf6, 0xef, 0x81, 0x75, 0x50
};
static const unsigned char third_ikmrpub[] = {
    0x04, 0xfe, 0x8c, 0x19, 0xce, 0x09, 0x05, 0x19,
    0x1e, 0xbc, 0x29, 0x8a, 0x92, 0x45, 0x79, 0x25,
    0x31, 0xf2, 0x6f, 0x0c, 0xec, 0xe2, 0x46, 0x06,
    0x39, 0xe8, 0xbc, 0x39, 0xcb, 0x7f, 0x70, 0x6a,
    0x82, 0x6a, 0x77, 0x9b, 0x4c, 0xf9, 0x69, 0xb8,
    0xa0, 0xe5, 0x39, 0xc7, 0xf6, 0x2f, 0xb3, 0xd3,
    0x0a, 0xd6, 0xaa, 0x8f, 0x80, 0xe3, 0x0f, 0x1d,
    0x12, 0x8a, 0xaf, 0xd6, 0x8a, 0x2c, 0xe7, 0x2e,
    0xa0
};
static const unsigned char third_ikmrpriv[] = {
    0xf3, 0xce, 0x7f, 0xda, 0xe5, 0x7e, 0x1a, 0x31,
    0x0d, 0x87, 0xf1, 0xeb, 0xbd, 0xe6, 0xf3, 0x28,
    0xbe, 0x0a, 0x99, 0xcd, 0xbc, 0xad, 0xf4, 0xd6,
    0x58, 0x9c, 0xf2, 0x9d, 0xe4, 0xb8, 0xff, 0xd2
};
static const unsigned char third_expected_shared_secret[] = {
    0xc0, 0xd2, 0x6a, 0xea, 0xb5, 0x36, 0x60, 0x9a,
    0x57, 0x2b, 0x07, 0x69, 0x5d, 0x93, 0x3b, 0x58,
    0x9d, 0xcf, 0x36, 0x3f, 0xf9, 0xd9, 0x3c, 0x93,
    0xad, 0xea, 0x53, 0x7a, 0xea, 0xbb, 0x8c, 0xb8
};
static const unsigned char third_aead0[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x30
};
static const unsigned char third_ct0[] = {
    0x5a, 0xd5, 0x90, 0xbb, 0x8b, 0xaa, 0x57, 0x7f,
    0x86, 0x19, 0xdb, 0x35, 0xa3, 0x63, 0x11, 0x22,
    0x6a, 0x89, 0x6e, 0x73, 0x42, 0xa6, 0xd8, 0x36,
    0xd8, 0xb7, 0xbc, 0xd2, 0xf2, 0x0b, 0x6c, 0x7f,
    0x90, 0x76, 0xac, 0x23, 0x2e, 0x3a, 0xb2, 0x52,
    0x3f, 0x39, 0x51, 0x34, 0x34
};
static const unsigned char third_aead1[] = {
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x2d, 0x31
};
static const unsigned char third_ct1[] = {
    0xfa, 0x6f, 0x03, 0x7b, 0x47, 0xfc, 0x21, 0x82,
    0x6b, 0x61, 0x01, 0x72, 0xca, 0x96, 0x37, 0xe8,
    0x2d, 0x6e, 0x58, 0x01, 0xeb, 0x31, 0xcb, 0xd3,
    0x74, 0x82, 0x71, 0xaf, 0xfd, 0x4e, 0xcb, 0x06,
    0x64, 0x6e, 0x03, 0x29, 0xcb, 0xdf, 0x3c, 0x3c,
    0xd6, 0x55, 0xb2, 0x8e, 0x82
};
static const unsigned char third_export1[] = {
    0x5e, 0x9b, 0xc3, 0xd2, 0x36, 0xe1, 0x91, 0x1d,
    0x95, 0xe6, 0x5b, 0x57, 0x6a, 0x8a, 0x86, 0xd4,
    0x78, 0xfb, 0x82, 0x7e, 0x8b, 0xdf, 0xe7, 0x7b,
    0x74, 0x1b, 0x28, 0x98, 0x90, 0x49, 0x0d, 0x4d
};
static const unsigned char third_context2[] = { 0x00 };
static const unsigned char third_export2[] = {
    0x6c, 0xff, 0x87, 0x65, 0x89, 0x31, 0xbd, 0xa8,
    0x3d, 0xc8, 0x57, 0xe6, 0x35, 0x3e, 0xfe, 0x49,
    0x87, 0xa2, 0x01, 0xb8, 0x49, 0x65, 0x8d, 0x9b,
    0x04, 0x7a, 0xab, 0x4c, 0xf2, 0x16, 0xe7, 0x96
};
static const unsigned char third_context3[] = {
    0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
    0x65, 0x78, 0x74
};
static const unsigned char third_export3[] = {
    0xd8, 0xf1, 0xea, 0x79, 0x42, 0xad, 0xbb, 0xa7,
    0x41, 0x2c, 0x6d, 0x43, 0x1c, 0x62, 0xd0, 0x13,
    0x71, 0xea, 0x47, 0x6b, 0x82, 0x3e, 0xb6, 0x97,
    0xe1, 0xf6, 0xe6, 0xca, 0xe1, 0xda, 0xb8, 0x5a
};

static int P256kdfsha256_hkdfsha256_aes128gcm_base_test(void)
{
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_BASE,
        { OSSL_HPKE_KEM_ID_P256,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_AES_GCM_128 },
        third_ikme, sizeof(third_ikme),
        third_ikmepub, sizeof(third_ikmepub),
        third_ikmr, sizeof(third_ikmr),
        third_ikmrpub, sizeof(third_ikmrpub),
        third_ikmrpriv, sizeof(third_ikmrpriv),
        third_expected_shared_secret, sizeof(third_expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0, /* no auth */
        NULL, 0, NULL /* PSK stuff */
    };
    const TEST_AEADDATA aeaddata[] = {
        { 0,
            pt, sizeof(pt),
            third_aead0, sizeof(third_aead0),
            third_ct0, sizeof(third_ct0) },
        { 1,
            pt, sizeof(pt),
            third_aead1, sizeof(third_aead1),
            third_ct1, sizeof(third_ct1) }
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, third_export1, sizeof(third_export1) },
        { third_context2, sizeof(third_context2),
            third_export2, sizeof(third_export2) },
        { third_context3, sizeof(third_context3),
            third_export3, sizeof(third_export3) },
    };
    return do_testhpke(&basedata, aeaddata, OSSL_NELEM(aeaddata),
        exportdata, OSSL_NELEM(exportdata));
}

#ifndef OPENSSL_NO_ECX
static const unsigned char fourth_ikme[] = {
    0x55, 0xbc, 0x24, 0x5e, 0xe4, 0xef, 0xda, 0x25,
    0xd3, 0x8f, 0x2d, 0x54, 0xd5, 0xbb, 0x66, 0x65,
    0x29, 0x1b, 0x99, 0xf8, 0x10, 0x8a, 0x8c, 0x4b,
    0x68, 0x6c, 0x2b, 0x14, 0x89, 0x3e, 0xa5, 0xd9
};
static const unsigned char fourth_ikmepub[] = {
    0xe5, 0xe8, 0xf9, 0xbf, 0xff, 0x6c, 0x2f, 0x29,
    0x79, 0x1f, 0xc3, 0x51, 0xd2, 0xc2, 0x5c, 0xe1,
    0x29, 0x9a, 0xa5, 0xea, 0xca, 0x78, 0xa7, 0x57,
    0xc0, 0xb4, 0xfb, 0x4b, 0xcd, 0x83, 0x09, 0x18
};
static const unsigned char fourth_ikmr[] = {
    0x68, 0x3a, 0xe0, 0xda, 0x1d, 0x22, 0x18, 0x1e,
    0x74, 0xed, 0x2e, 0x50, 0x3e, 0xbf, 0x82, 0x84,
    0x0d, 0xeb, 0x1d, 0x5e, 0x87, 0x2c, 0xad, 0xe2,
    0x0f, 0x4b, 0x45, 0x8d, 0x99, 0x78, 0x3e, 0x31
};
static const unsigned char fourth_ikmrpub[] = {
    0x19, 0x41, 0x41, 0xca, 0x6c, 0x3c, 0x3b, 0xeb,
    0x47, 0x92, 0xcd, 0x97, 0xba, 0x0e, 0xa1, 0xfa,
    0xff, 0x09, 0xd9, 0x84, 0x35, 0x01, 0x23, 0x45,
    0x76, 0x6e, 0xe3, 0x3a, 0xae, 0x2d, 0x76, 0x64
};
static const unsigned char fourth_ikmrpriv[] = {
    0x33, 0xd1, 0x96, 0xc8, 0x30, 0xa1, 0x2f, 0x9a,
    0xc6, 0x5d, 0x6e, 0x56, 0x5a, 0x59, 0x0d, 0x80,
    0xf0, 0x4e, 0xe9, 0xb1, 0x9c, 0x83, 0xc8, 0x7f,
    0x2c, 0x17, 0x0d, 0x97, 0x2a, 0x81, 0x28, 0x48
};
static const unsigned char fourth_expected_shared_secret[] = {
    0xe8, 0x17, 0x16, 0xce, 0x8f, 0x73, 0x14, 0x1d,
    0x4f, 0x25, 0xee, 0x90, 0x98, 0xef, 0xc9, 0x68,
    0xc9, 0x1e, 0x5b, 0x8c, 0xe5, 0x2f, 0xff, 0xf5,
    0x9d, 0x64, 0x03, 0x9e, 0x82, 0x91, 0x8b, 0x66
};
static const unsigned char fourth_export1[] = {
    0x7a, 0x36, 0x22, 0x1b, 0xd5, 0x6d, 0x50, 0xfb,
    0x51, 0xee, 0x65, 0xed, 0xfd, 0x98, 0xd0, 0x6a,
    0x23, 0xc4, 0xdc, 0x87, 0x08, 0x5a, 0xa5, 0x86,
    0x6c, 0xb7, 0x08, 0x72, 0x44, 0xbd, 0x2a, 0x36
};
static const unsigned char fourth_context2[] = { 0x00 };
static const unsigned char fourth_export2[] = {
    0xd5, 0x53, 0x5b, 0x87, 0x09, 0x9c, 0x6c, 0x3c,
    0xe8, 0x0d, 0xc1, 0x12, 0xa2, 0x67, 0x1c, 0x6e,
    0xc8, 0xe8, 0x11, 0xa2, 0xf2, 0x84, 0xf9, 0x48,
    0xce, 0xc6, 0xdd, 0x17, 0x08, 0xee, 0x33, 0xf0
};
static const unsigned char fourth_context3[] = {
    0x54, 0x65, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x74,
    0x65, 0x78, 0x74
};
static const unsigned char fourth_export3[] = {
    0xff, 0xaa, 0xbc, 0x85, 0xa7, 0x76, 0x13, 0x6c,
    0xa0, 0xc3, 0x78, 0xe5, 0xd0, 0x84, 0xc9, 0x14,
    0x0a, 0xb5, 0x52, 0xb7, 0x8f, 0x03, 0x9d, 0x2e,
    0x87, 0x75, 0xf2, 0x6e, 0xff, 0xf4, 0xc7, 0x0e
};

static int export_only_test(void)
{
    /* based on RFC9180 A.7 */
    const TEST_BASEDATA basedata = {
        OSSL_HPKE_MODE_BASE,
        { OSSL_HPKE_KEM_ID_X25519,
            OSSL_HPKE_KDF_ID_HKDF_SHA256,
            OSSL_HPKE_AEAD_ID_EXPORTONLY },
        fourth_ikme, sizeof(fourth_ikme),
        fourth_ikmepub, sizeof(fourth_ikmepub),
        fourth_ikmr, sizeof(fourth_ikmr),
        fourth_ikmrpub, sizeof(fourth_ikmrpub),
        fourth_ikmrpriv, sizeof(fourth_ikmrpriv),
        fourth_expected_shared_secret, sizeof(fourth_expected_shared_secret),
        ksinfo, sizeof(ksinfo),
        NULL, 0, /* no auth */
        NULL, 0, NULL /* PSK stuff */
    };
    const TEST_EXPORTDATA exportdata[] = {
        { NULL, 0, fourth_export1, sizeof(fourth_export1) },
        { fourth_context2, sizeof(fourth_context2),
            fourth_export2, sizeof(fourth_export2) },
        { fourth_context3, sizeof(fourth_context3),
            fourth_export3, sizeof(fourth_export3) },
    };
    return do_testhpke(&basedata, NULL, 0,
        exportdata, OSSL_NELEM(exportdata));
}
#endif

/*
 * Base vectors from draft-ietf-hpke-pq-05, Appendices A.7 through A.10.
 * PSK exports were independently derived from those KEM shared secrets using
 * draft-ietf-hpke-hpke-04, Sections 4.4, 5.1, and 5.3: PSK bytes 00 through 3f,
 * psk_id "single-stage-psk", unchanged info, and an empty exporter context.
 */
static const struct {
    OSSL_HPKE_SUITE suite;
    size_t ikmlen;
    size_t publen;
    unsigned char ikmE[57];
    unsigned char ikmR[57];
    unsigned char pkRm[98];
    unsigned char enc[98];
    unsigned char ct[3][75];
    unsigned char exported[5][33];
    unsigned char exported_psk[33];
} single_stage_tests[] = {
    { { OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_SHAKE128,
          OSSL_HPKE_AEAD_ID_AES_GCM_128 },
        32, 65,
        "\x66\x95\xfd\xcf\xfd\xc5\xe0\x19\x8b\xb3\x36\x41"
        "\x0f\xd8\xa0\x44\x9c\x17\x54\xbb\xcd\xf9\x0c\x03"
        "\x39\x79\x96\xf6\x14\x77\xdf\x31",
        "\xba\xea\x9e\xf0\x31\x13\xb6\xb3\xea\xe4\x20\x55"
        "\xd1\x15\x38\x24\xe0\xd6\xce\x29\x2c\x7a\x77\x76"
        "\xc4\x61\x64\xb3\xd7\xff\x47\x2d",
        "\x04\x99\xc5\x1f\xe8\x1d\xd1\x42\x19\x3b\xe7\xeb"
        "\xfb\x9b\xbe\xad\x8d\xa7\xc5\x01\x43\x64\xf0\x7d"
        "\x70\xb6\x94\x70\x03\xb0\x37\xa7\x7d\x1d\x2a\xb7"
        "\x66\x4e\x44\x56\xba\xf9\xae\x18\x61\x77\x31\xc5"
        "\x21\x7a\xb5\xba\x72\x4d\xf2\xc6\xee\x06\xe1\x67"
        "\xd6\xf8\xad\x34\x30",
        "\x04\x0d\x6b\x7d\x55\x77\x3a\x67\x79\x61\xfc\xd2"
        "\x0a\x94\xa4\x28\xcc\xe3\x88\x7a\x0e\xad\xcc\xff"
        "\x41\x77\xaf\xae\x89\x4d\x13\x45\x7b\x9a\x6c\x6a"
        "\xce\x3a\xfb\xcb\x3a\x8a\x7b\x6d\xcf\x34\x1f\xad"
        "\x4f\x8c\x4a\x46\x59\x49\x94\x76\x5a\x49\x31\x23"
        "\xef\x00\x56\x4e\xb3",
        { "\xb6\xbb\xe2\x09\xcf\x13\xd2\xe4\x91\x65\x1b\x4e"
          "\x01\xa7\x04\x21\xcb\x63\xf5\x09\xc4\xf5\x4b\x46"
          "\x83\x38\xeb\xdc\x9c\xbe\x09\xe5\x34\x21\x45\xc1"
          "\xc3\x67\xb1\xea\xd4\x79\xb8\x04\x82\x3b\xa1\xea"
          "\x64\x0d\xf5\xf9\xf7\xbe\xbf\xea\xe4\xcf\x59\x6f"
          "\x78\x6d\xc4\xc8\x0a\xcc\x4c\xe5\x6e\x4e\xf7\x2e"
          "\x53\xa2",
            "\xfd\x31\xb9\x52\xb7\x31\xaa\xd4\xf4\x35\x97\xb0"
            "\xcc\x6b\xa2\xc3\xa3\xe5\x6f\x78\xab\xc2\x01\xb8"
            "\x6b\xed\x80\x79\x8c\x5c\xb8\x74\xd1\x4d\xba\xc6"
            "\xf3\x3c\x87\x00\xd0\xa6\x29\xe1\x26\x7c\x76\xed"
            "\x6f\x10\x1b\x13\x26\xc3\xac\xdb\x12\x5c\x7e\xb6"
            "\xea\xd4\x5a\x31\x48\xb8\x67\x66\xd2\xce\xd8\x0e"
            "\x2d\xa0",
            "\xd0\xc5\xf0\xd1\xfc\x43\xc8\x64\x46\x00\xdc\xfd"
            "\x66\x7d\x7c\xbd\x89\x9c\x6c\x68\xf1\x86\x2e\xfa"
            "\xb6\xe8\xfd\x6f\x25\x59\xb2\xe4\x86\xa4\x99\x3a"
            "\x3f\x83\xed\xc8\x3c\x17\xc7\x95\x70\x9e\xc0\x19"
            "\x2d\x58\x59\x39\x83\xba\x2c\x47\x99\x9c\xee\x42"
            "\xc7\x8e\x61\xc0\x7b\xaf\x68\x82\x4e\x9c\xd8\x3b"
            "\x51\xa7" },
        { "\x33\x36\x7f\x44\xb8\x56\x1d\x2b\xe9\xa6\x75\x35"
          "\x92\x6b\xc2\xf5\x29\x49\x26\x7b\x70\xf4\xa7\x6d"
          "\x92\x94\xc6\x90\x56\x19\x6e\xe5",
            "\x2c\x07\xc3\xd1\xd6\x8e\xf7\x11\xc3\x80\x70\x0b"
            "\xf0\x19\xba\xb6\xd8\x86\x16\xb3\x90\x60\xce\xd8"
            "\x22\xc6\x66\xad\x0d\xd6\x79\xe9",
            "\x2f\xad\xeb\xf4\xf1\x83\x68\xf7\xd5\xd2\x70\x56"
            "\x2d\xaa\x44\x9e\x31\xc6\xc8\x43\xe8\x7a\x21\x45"
            "\x16\x67\xbd\xfc\xd0\x16\x25\x5e",
            "\xa0\x56\x9f\xb1\x4b\x74\x87\xe3\x56\x30\xd6\x80"
            "\xc1\xdd\x8d\xb0\xbe\x67\x2f\x86\xd9\xe7\x7d\xbf"
            "\xf8\x62\x17\xfd\xdb\x60\x1a\x6f",
            "\x45\xd7\xf2\xb3\x2a\xfc\x6d\x8f\x5e\x12\x14\xbb"
            "\xee\xa6\xc4\x3c\x27\x5e\x0b\x82\xed\xda\x76\x21"
            "\x71\xae\xf9\xf0\x55\xa4\x2f\xdd" },
        "\xd6\x04\x42\xcd\xda\x70\x63\x60\x58\x7a\xd4\x83"
        "\xcb\x71\x27\xfa\xa1\xaa\x6c\xeb\xdd\x72\xf9\xc5"
        "\x08\x09\x09\x62\x14\x6f\x27\x4e" },
    { { OSSL_HPKE_KEM_ID_P384, OSSL_HPKE_KDF_ID_SHAKE256,
          OSSL_HPKE_AEAD_ID_AES_GCM_256 },
        48, 97,
        "\x25\x3b\xec\x46\x23\x46\x3f\x09\xf3\x6b\x49\x6c"
        "\x41\x9f\xd8\x83\x0f\xa6\x8c\xc2\x98\x1e\x72\x0b"
        "\xec\xde\x04\x2c\x86\x5a\xe9\xb6\x34\x8d\x1d\x27"
        "\x95\xbe\x4e\x23\xd6\x5c\x19\x52\x3f\xb9\x9f\x21",
        "\x65\xfc\xa3\xea\x3b\x6d\xb2\x9a\x62\xbf\xf2\x8e"
        "\xc5\x3c\x08\x71\x0f\xab\x10\xb3\x79\x8e\x59\xb6"
        "\x78\xd3\x22\x42\x96\xd5\x88\x3f\x03\x91\x23\x47"
        "\x17\x84\xce\x57\xb0\xd8\x5a\x17\xcd\x52\x11\x96",
        "\x04\xa5\xf5\x3d\xa8\x56\x43\x64\x25\x5b\xc3\x68"
        "\x50\xdf\x79\x36\x72\x78\x2a\x5c\x9e\x4a\x7f\xb5"
        "\xfb\x2e\x21\x46\xeb\x12\xe4\xd8\x47\x7a\xb1\xf3"
        "\x26\xa3\x61\xdf\xd1\xe4\x12\x12\x10\x95\x10\xe8"
        "\x13\x38\x05\x47\xc6\x8c\x09\x64\xc1\x90\x8f\x16"
        "\xf6\x7b\x90\x2a\x06\x1b\xe2\x7b\x2f\x8b\x43\xf1"
        "\xfa\xb1\xbf\x0d\xbf\x89\xf5\x16\x7c\xe8\x0a\xca"
        "\x2c\x21\x0b\x8f\xc0\xf0\x40\x69\x9d\xb9\xee\x12"
        "\x29",
        "\x04\x9f\x1d\xa9\x43\x82\x7d\x16\x52\x68\x86\x9c"
        "\x84\x29\x62\xc1\xfe\xba\x1f\xb4\x64\x02\xfd\x3f"
        "\xac\x50\xc0\x02\xcf\x44\xbb\x10\x3c\x1a\xa8\xfb"
        "\x15\xa8\x48\xf9\x90\x85\x54\x62\x4b\x0e\xac\x45"
        "\x73\xec\x25\x87\x88\x33\x54\x21\xdc\xbf\xa6\x25"
        "\xbf\xc9\x13\x6c\xfa\x0e\x33\x5f\x0d\xe0\x18\xe4"
        "\xf9\x51\x7a\xe0\xa8\x86\x3f\x1b\x36\x31\x34\x3c"
        "\x49\xc6\x7f\xd2\x40\x21\x3f\x86\xaf\x1b\x23\x5b"
        "\xa4",
        { "\x3c\x79\x22\x01\x62\x41\x55\x5d\x76\xd8\x7b\x72"
          "\x5f\x17\x05\x8f\x9c\x30\x9c\xb3\xb7\x93\xb3\xd8"
          "\xb5\x03\xcd\x99\xa6\x17\x41\x30\xaa\x6f\xc6\x79"
          "\x2f\x94\x34\x5b\xfd\x5e\x8e\xc4\xcf\xc3\x64\x1b"
          "\xf6\xa6\x72\xb5\x28\x55\x98\xe4\x9d\xab\x91\xeb"
          "\xd7\x1c\x38\xd7\x03\xd4\xe4\x1c\x0c\x6c\xd2\x3b"
          "\x8c\xf7",
            "\xa1\x74\x5c\x52\xe7\x3e\xd7\xc7\xc0\x5c\xd4\xd7"
            "\x12\x09\x4d\xc5\xc3\xec\x84\xd3\x16\xa8\x2e\xc0"
            "\xe3\x38\xb6\x4d\xd1\x17\x42\xf4\x2f\x7b\x2b\x39"
            "\x1c\xd0\xd3\x39\x7d\x45\x1e\xd4\x8c\x32\xb5\xd1"
            "\xb5\x39\x2d\xb6\x2c\x6a\x2c\x9f\x82\x9e\xd9\xf9"
            "\x37\xed\x64\x45\x2f\xc5\xe5\xc1\x08\xc0\x98\x99"
            "\x91\x0c",
            "\xa7\x03\x88\xa9\x07\x77\x9a\x2b\x59\xfd\x6f\x04"
            "\x15\x41\x92\x51\x27\x74\x55\x59\xe2\xda\x6b\x2a"
            "\xb7\xac\x9a\x49\x13\x2b\xb0\x27\xf1\x91\x8a\x3b"
            "\xa9\x3c\x7b\x01\xb0\x02\x8c\xab\x84\x02\x13\xf8"
            "\xd1\xc0\x23\xc5\x76\x65\x77\x0d\xb8\xea\x53\x5c"
            "\x8a\x58\xb6\x03\x5f\x07\xac\xb6\x58\xb3\xb8\xae"
            "\x61\x1e" },
        { "\xa2\x8e\xac\x67\xf1\xc7\xd8\xe0\xa7\xd1\x0d\xa1"
          "\xc3\xe6\x5c\x7e\x7e\x7b\x6e\x78\x8f\xdc\xd3\x3a"
          "\xa3\xee\xd6\xf6\x03\x76\x31\xa0",
            "\x39\x29\xd2\xc7\x9d\x09\x93\xcc\xe9\x23\xb5\x02"
            "\xff\x03\x81\x1d\xc8\x32\x83\x60\xb0\xde\xce\x71"
            "\x48\x5a\x79\x94\x60\x3d\xd3\xbe",
            "\x99\x9f\x41\xef\x5b\x39\xe0\xfa\xf7\xb2\xfe\xe9"
            "\x73\xb1\x8e\x20\x18\xc8\xd4\xda\x25\x99\x49\xd4"
            "\xbe\xa9\xa5\x95\xda\x07\x02\x69",
            "\xb0\x7d\x63\x19\xb6\x8e\x5a\xa7\xcd\xad\xe4\xfb"
            "\x77\x66\xed\xe1\xbc\x7d\x13\xd1\xcf\xac\x3a\xff"
            "\xd7\x06\xb0\xa4\x24\xe8\xa4\x8c",
            "\x4f\xb7\x88\x7f\x90\xbd\x52\x92\xd4\xc9\x8a\xcd"
            "\x92\x79\x2a\xd4\xc7\xa8\x38\xf8\x33\x87\xb8\xad"
            "\x13\x8f\x02\xc5\xaf\x92\xa0\x90" },
        "\x6d\x2a\x7f\xd6\x6b\x61\x35\xbe\x17\x7d\xe6\xa6"
        "\x21\x15\x44\x30\x10\xbe\x79\x74\xd4\x39\x55\x1d"
        "\x1d\x49\x44\xb8\x9c\xcc\x39\x71" },
#if !defined(OPENSSL_NO_TURBOSHAKE) && !defined(OPENSSL_NO_ECX) \
    && !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    { { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_TURBOSHAKE128,
          OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 },
        32, 32,
        "\xb6\xcc\x2b\x55\xf0\x30\x81\xc2\x77\x65\x79\xd0"
        "\x68\xbf\x73\x9a\x3b\xa0\x8b\x1b\x5f\x40\x24\xa0"
        "\x87\x42\xba\x94\x79\xc8\x4e\xcc",
        "\xbb\xa0\xac\xb2\xba\xe9\x18\x38\x43\xf4\xfc\xab"
        "\x32\x57\x19\xdf\x1f\x85\x18\x5a\xc0\xa4\x32\x1d"
        "\xc0\x7c\x89\x8d\xf2\x87\x70\xc5",
        "\xde\xbf\x05\xa0\x5f\x19\x15\xdd\x70\xce\xd2\x5e"
        "\xe4\x77\x4b\xd5\x4e\x62\xab\xcb\xf5\x99\xd3\x23"
        "\xbf\xe2\xd1\xf2\x04\xc9\x36\x68",
        "\xaf\xf3\x95\x70\x7b\x2a\x24\x2b\x43\xaf\xfd\x25"
        "\xe4\x3d\x58\x77\x6f\xf8\x3c\xa2\xfc\x4f\x41\xd0"
        "\x84\xbc\x87\x1b\xdd\x20\x7e\x10",
        { "\xaa\x62\xe6\xef\xd4\x33\xc6\x1b\x5a\x41\x1c\x11"
          "\xab\x9c\x83\xaf\xde\x2b\xa1\x30\x15\xec\xe2\x4e"
          "\x3f\xe9\x20\x8d\x9d\x6f\xbe\x8a\x66\x5f\x77\x8c"
          "\xc2\xfd\xa3\xe1\x3b\xd1\x9c\x28\x00\x5a\xe0\x25"
          "\x58\x70\xdf\x74\x22\x7a\x2f\x85\x4b\xc1\x60\x1f"
          "\xe3\x13\x52\x67\x04\xc1\x57\x2e\x60\xd9\xb4\xaa"
          "\xb1\xba",
            "\x06\xd3\x19\x29\xc3\xe0\xd0\xc8\xbb\xf5\x1d\x67"
            "\x2f\x8d\x23\x27\x82\xb3\xf3\x9f\x16\x25\x33\x19"
            "\x2b\x31\xb7\x29\xd0\x5d\xab\x06\x1d\x49\x07\xf0"
            "\xbe\x84\x88\xb9\xd4\x0d\x98\x9c\x76\x7d\x01\x6b"
            "\x86\x6a\xdc\x0e\x6e\x1c\x91\x43\x6b\x1b\x00\xb1"
            "\xca\xac\x7e\x29\x0a\xbf\x88\x38\xd3\x3b\xcd\x72"
            "\x28\xcf",
            "\xdd\x31\xf4\x35\xb5\xb6\x1f\x23\xac\x48\xc7\x87"
            "\x73\x10\x2d\x6c\x54\xee\x8b\x51\x9e\xea\x22\x71"
            "\x10\xf6\xfa\x89\xe0\x9c\xd1\x0c\xc1\x2d\x8e\xb1"
            "\xc6\x39\x5b\x09\x61\xa3\xb9\x04\xa7\xee\xa1\x6e"
            "\x55\x78\xae\x8d\xbc\xef\xe4\x69\x97\x77\xda\x2a"
            "\x15\xbd\x59\x7e\x3b\x99\x1f\x05\xa5\xec\x04\xe1"
            "\x9e\xcf" },
        { "\xd7\xf5\x53\x36\xc6\xca\xd3\xb9\x16\x7a\xdf\x02"
          "\x16\xd3\x20\x13\x39\x57\x27\xdd\x37\x7a\xad\xdf"
          "\x40\xb2\x7b\xe6\xbf\xf4\x8d\x66",
            "\xa8\x24\x24\x27\x17\x23\xbe\xce\x12\x98\x51\x43"
            "\x5b\xc5\xa6\xda\xbd\x52\xdb\x0e\xb8\x47\x17\x4c"
            "\x76\xaa\x08\x81\xc3\xd8\xed\x79",
            "\xf0\x3e\xac\x72\x7c\xcf\x10\xfd\x07\xea\x44\x4d"
            "\xb4\x9c\xaf\x24\x3c\x46\xb0\x69\x09\xad\xd8\xae"
            "\x0c\x71\x86\x9a\x74\x37\x97\x73",
            "\x5f\x2c\x26\x08\xb9\x90\xc8\xfc\xe7\xb3\x0b\xad"
            "\xb7\x6d\xb9\xcd\xbb\xa8\x9b\x4f\x16\xb2\xe0\xf7"
            "\xde\xd3\xe6\xda\x70\x05\x51\xae",
            "\xf4\x8f\x36\x3a\x63\xa8\xf0\x50\x00\xe8\xe3\xb2"
            "\x7f\xac\xa5\xdc\x44\xc7\x3a\xea\x1c\xd6\xc0\xe5"
            "\x3a\x3c\x40\xf4\xbd\x01\xfc\x7f" },
        "\xd6\xfc\x2a\x9e\x79\xfd\x02\x41\xb8\x52\x52\x35"
        "\x24\xb0\xc4\x5e\x5d\x67\xaa\x8e\xa7\x54\xed\x4c"
        "\x3b\x1f\x09\x97\xcb\x50\x34\x60" },
    { { OSSL_HPKE_KEM_ID_X448, OSSL_HPKE_KDF_ID_TURBOSHAKE256,
          OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 },
        56, 56,
        "\x5c\xe9\x44\xf4\x54\xaf\xe8\x57\xbc\xfd\xaf\xf8"
        "\xe8\x12\x02\xfd\x6c\x18\x50\xab\x2b\x7f\x81\xac"
        "\x21\x70\x3e\x03\x4c\x87\xda\x2b\x2d\x9a\xba\x7d"
        "\xa4\xa3\xe2\xd1\xa3\x95\xc9\x61\xdb\xe1\x76\x33"
        "\x75\x7f\x32\x42\x74\xb1\x52\x94",
        "\x05\x01\x0b\x60\x19\x87\x48\x05\x34\x14\xd6\x3c"
        "\x47\xba\x70\x5c\x64\x40\xc9\xcb\xe6\x53\x73\x89"
        "\x77\xd0\x8c\x6c\xa3\x2d\x0b\x82\xe2\x7b\xa4\xab"
        "\x99\x64\x12\xf5\x9f\x05\xcb\x73\xac\x7c\xa0\x39"
        "\x7a\xe4\x50\xaa\x8f\x12\xad\x3d",
        "\xfa\xde\x88\xe0\x45\x35\x76\x6e\x15\x3b\xa0\xb0"
        "\x57\xf6\xab\xb2\xdd\x80\x0d\xdc\x7f\x9c\x81\x26"
        "\x1c\x4c\x36\xda\xed\xfe\x24\xfd\xf7\xda\x2f\x55"
        "\x09\xff\xb5\x74\x7f\xe1\x76\xdf\x95\xd2\x68\x5e"
        "\xbf\x31\xa9\x2f\x9d\x35\xd9\x5e",
        "\x63\xf7\xf7\x49\xb7\x17\xb0\x01\x62\x52\x0b\x49"
        "\xa8\x9e\x6a\xd5\x70\xcd\x33\x3b\x68\x54\x68\xda"
        "\xb6\xef\x20\x17\xa9\x9b\x7e\x19\x4f\xa3\xbf\x57"
        "\x2c\xd1\xd4\x47\x66\xf7\xc1\xf2\xa1\xd5\xa0\x64"
        "\x27\x99\xb8\x60\x53\x3a\xde\x01",
        { "\x5a\xd3\xab\x90\x53\x04\x1b\x1c\x06\xff\x23\xff"
          "\x1e\x3d\x6a\x1b\xdf\xfb\x7e\xc3\xc3\x3b\x9c\x03"
          "\xb4\xbd\xe4\x79\xdc\x2d\x0f\x9e\x09\x50\x51\x3f"
          "\xad\xfa\x51\xd4\xa0\x3a\x2f\x81\x22\x21\x36\xf9"
          "\xce\xb7\xe8\xb3\xac\x9d\x03\xb5\xbe\x9a\x17\xe9"
          "\x8e\xb0\x94\x61\x79\x60\x5c\x4a\x8c\x3b\xc8\x07"
          "\x03\x80",
            "\x83\xef\x4e\x57\x03\xb8\xb3\xe3\x84\xf1\x8d\x58"
            "\x60\xfa\xee\x26\x53\xa7\x49\x30\x68\x59\xb4\x05"
            "\xce\x54\xa6\x1f\x0e\xad\x71\x89\xb2\x0f\x71\x79"
            "\x01\xcb\x7a\xa5\x39\x08\xc6\xc9\x99\x95\xf0\x88"
            "\x74\xe9\x84\x05\x3f\x7b\x2d\x9c\xf8\xcb\xe4\x36"
            "\x95\xbd\xe5\x5e\x14\x7b\xa3\xf4\xe2\xd5\x37\x01"
            "\x1f\xf0",
            "\xb0\x23\xa5\x54\x3c\x58\x26\x74\xa3\x0a\x21\x47"
            "\x97\x3e\xe1\x10\x0b\x8c\x47\x9f\xd7\x55\x80\x2d"
            "\xa4\x2c\x46\x6a\x7f\xae\x18\xa4\xbc\xe3\x53\x3e"
            "\x47\xed\x69\x74\x36\x6e\x45\x13\xc2\x82\x78\x27"
            "\x2d\x03\x91\x44\xb0\xc1\xc1\xd5\x33\x89\xd5\x76"
            "\x6d\x42\xa6\x7f\x28\xb3\x78\xab\x01\x5d\xe8\x94"
            "\x0c\x2d" },
        { "\x2d\xa5\xaf\xb4\xfb\x6e\x17\xc7\x5a\xb2\x6c\x04"
          "\x34\x2c\x52\x58\xfa\x49\xb8\x56\x0d\x60\x97\xdf"
          "\x09\xe5\xe1\x85\xfb\x6b\xaf\xa4",
            "\x08\x2f\x74\xe7\x6a\xa2\xaa\xd1\x39\xec\x8d\x16"
            "\xa8\x16\xb6\x41\x57\x26\x7b\x61\x51\x26\x7c\x6a"
            "\xf1\x43\x97\x2b\x63\x87\x8c\xbf",
            "\xbf\xe8\xac\x22\x5e\x0c\x31\x5b\x3a\x89\x6e\x66"
            "\x15\x2b\x65\x90\x0b\xbd\x1e\x68\x57\xab\x13\x17"
            "\xf7\x5b\x5a\xfa\x84\xab\x52\x4b",
            "\x1d\xce\x8c\x05\x32\xf6\x55\x5a\xf6\xc5\x09\xec"
            "\x4e\x10\xe5\xe0\x84\x05\x2f\xdb\x64\x09\xb6\x13"
            "\xdd\x88\xd5\x66\xc6\x48\x72\x8f",
            "\x32\xe3\xb0\x6e\x3d\x4c\xa3\x30\x10\xb2\xed\x02"
            "\x2e\x04\xad\x08\xcb\xc8\xd8\xb6\x6f\x94\x63\x0b"
            "\xf9\x70\x1b\x07\x97\xcb\x62\x59" },
        "\x13\x7b\x9c\x7e\xc6\x8c\x21\x3e\xe7\xfe\x2a\x01"
        "\x01\x8c\xb9\x28\x7a\x78\xde\x21\x8d\x93\xe5\x74"
        "\x27\x5f\xd8\x83\xbe\xd7\x4a\x5c" },
#endif
};

static int test_hpke_single_stage_vectors(int idx)
{
    /* The draft uses ASCII hexadecimal strings for info and plaintext. */
    static const unsigned char info[] = "4f6465206f6e2061204772656369616e2055726e";
    static const unsigned char plaintext[] = "4265617574792069732074727574682c20747275746820626561757479";
    static const unsigned char single_stage_psk[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
                                                    "\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"
                                                    "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23"
                                                    "\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
                                                    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b"
                                                    "\x3c\x3d\x3e\x3f";
    static const unsigned char aad[][8] = {
        "Count-0", "Count-1", "Count-2"
    };
    static const unsigned char exporter_context[][14] = {
        "pseudorandom0", "pseudorandom1", "pseudorandom2",
        "pseudorandom3", "pseudorandom4"
    };
    TEST_BASEDATA basedata = { 0 };
    TEST_AEADDATA aeaddata[3];
    TEST_EXPORTDATA exportdata[5];
    int psk_mode = idx >= (int)OSSL_NELEM(single_stage_tests);
    size_t i;

    idx %= (int)OSSL_NELEM(single_stage_tests);
    basedata.mode = OSSL_HPKE_MODE_BASE;
    basedata.suite = single_stage_tests[idx].suite;
    basedata.ikmE = single_stage_tests[idx].ikmE;
    basedata.ikmElen = single_stage_tests[idx].ikmlen;
    basedata.expected_pkEm = single_stage_tests[idx].enc;
    basedata.expected_pkEmlen = single_stage_tests[idx].publen;
    basedata.ikmR = single_stage_tests[idx].ikmR;
    basedata.ikmRlen = single_stage_tests[idx].ikmlen;
    basedata.expected_pkRm = single_stage_tests[idx].pkRm;
    basedata.expected_pkRmlen = single_stage_tests[idx].publen;
    basedata.ksinfo = info;
    basedata.ksinfolen = sizeof(info) - 1;
    if (psk_mode) {
        basedata.mode = OSSL_HPKE_MODE_PSK;
        basedata.psk = single_stage_psk;
        basedata.psklen = sizeof(single_stage_psk) - 1;
        basedata.pskid = "single-stage-psk";
        exportdata[0].context = NULL;
        exportdata[0].contextlen = 0;
        exportdata[0].expected_secret = single_stage_tests[idx].exported_psk;
        exportdata[0].expected_secretlen = sizeof(single_stage_tests[idx].exported_psk) - 1;
        return do_testhpke(&basedata, NULL, 0, exportdata, 1);
    }
    for (i = 0; i < OSSL_NELEM(aeaddata); i++) {
        aeaddata[i].seq = (int)i;
        aeaddata[i].pt = plaintext;
        aeaddata[i].ptlen = sizeof(plaintext) - 1;
        aeaddata[i].aad = aad[i];
        aeaddata[i].aadlen = sizeof(aad[i]) - 1;
        aeaddata[i].expected_ct = single_stage_tests[idx].ct[i];
        aeaddata[i].expected_ctlen = sizeof(single_stage_tests[idx].ct[i]) - 1;
    }
    for (i = 0; i < OSSL_NELEM(exportdata); i++) {
        exportdata[i].context = exporter_context[i];
        exportdata[i].contextlen = sizeof(exporter_context[i]) - 1;
        exportdata[i].expected_secret = single_stage_tests[idx].exported[i];
        exportdata[i].expected_secretlen = sizeof(single_stage_tests[idx].exported[i]) - 1;
    }
    return do_testhpke(&basedata, aeaddata, OSSL_NELEM(aeaddata),
        exportdata, OSSL_NELEM(exportdata));
}

/*
 * Randomly toss a coin
 */
#define COIN_IS_HEADS (test_random() % 2)

/* tables of HPKE modes and suite values */
static int hpke_mode_list[] = {
    OSSL_HPKE_MODE_BASE,
    OSSL_HPKE_MODE_PSK,
    OSSL_HPKE_MODE_AUTH,
    OSSL_HPKE_MODE_PSKAUTH
};
static uint16_t hpke_kem_list[] = {
    OSSL_HPKE_KEM_ID_P256,
    OSSL_HPKE_KEM_ID_P384,
    OSSL_HPKE_KEM_ID_P521,
#ifndef OPENSSL_NO_ECX
    OSSL_HPKE_KEM_ID_X25519,
    OSSL_HPKE_KEM_ID_X448
#endif
};
static uint16_t hpke_kdf_list[] = {
    OSSL_HPKE_KDF_ID_HKDF_SHA256,
    OSSL_HPKE_KDF_ID_HKDF_SHA384,
    OSSL_HPKE_KDF_ID_HKDF_SHA512,
    OSSL_HPKE_KDF_ID_SHAKE128,
    OSSL_HPKE_KDF_ID_SHAKE256,
#ifndef OPENSSL_NO_TURBOSHAKE
    OSSL_HPKE_KDF_ID_TURBOSHAKE128,
    OSSL_HPKE_KDF_ID_TURBOSHAKE256
#endif
};
static uint16_t hpke_aead_list[] = {
    OSSL_HPKE_AEAD_ID_AES_GCM_128,
    OSSL_HPKE_AEAD_ID_AES_GCM_256,
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    OSSL_HPKE_AEAD_ID_CHACHA_POLY1305
#endif
};

/*
 * Strings that can be used with names or IANA codepoints.
 * Note that the initial entries from these lists should
 * match the lists above, i.e. kem_str_list[0] and
 * hpke_kem_list[0] should refer to the same KEM. We use
 * that for verbose output via TEST_note() below.
 * Subsequent entries are only used for tests of
 * OSSL_HPKE_str2suite()
 */
static const char *mode_str_list[] = {
    "base", "psk", "auth", "pskauth"
};
static const char *kem_str_list[] = {
#ifndef OPENSSL_NO_ECX
    "P-256", "P-384", "P-521", "x25519", "x448",
    "0x10", "0x11", "0x12", "0x20", "0x21",
    "16", "17", "18", "32", "33"
#else
    "P-256", "P-384", "P-521",
    "0x10", "0x11", "0x12",
    "16", "17", "18"
#endif
};
static const char *kdf_str_list[] = {
    "hkdf-sha256", "hkdf-sha384", "hkdf-sha512",
    "shake128", "shake256",
#ifndef OPENSSL_NO_TURBOSHAKE
    "turboshake128", "turboshake256",
#endif
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03",
    "1", "2", "3", "0x10", "0x11", "0x0010", "0x0011", "16", "17",
#ifndef OPENSSL_NO_TURBOSHAKE
    "0x12", "0x13", "0x0012", "0x0013", "18", "19"
#endif
};
static const char *aead_str_list[] = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "exporter",
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03",
    "1", "2", "3",
    "0xff", "255"
};
/* table of bogus strings that better not work */
static const char *bogus_suite_strs[] = {
    "3,33,3",
    "bogus,bogus,bogus",
    "bogus,33,3,1,bogus",
    "bogus,33,3,1",
    "bogus,bogus",
    "bogus",
    /* one bad token */
    "0x10,0x01,bogus",
    "0x10,bogus,0x01",
    "bogus,0x02,0x01",
    /* in reverse order */
    "aes-256-gcm,hkdf-sha512,x25519",
    /* surplus separators */
    ",,0x10,0x01,0x02",
    "0x10,,0x01,0x02",
    "0x10,0x01,,0x02",
    /* embedded NUL chars */
    "0x10,\00x01,,0x02",
    "0x10,\0"
    "0x01,0x02",
    "0x10\0,0x01,0x02",
    "0x10,0x01\0,0x02",
    "0x10,0x01,\0"
    "0x02",
    /* embedded whitespace */
    " aes-256-gcm,hkdf-sha512,x25519",
    "aes-256-gcm, hkdf-sha512,x25519",
    "aes-256-gcm ,hkdf-sha512,x25519",
    "aes-256-gcm,hkdf-sha512, x25519",
    "aes-256-gcm,hkdf-sha512 ,x25519",
    "aes-256-gcm,hkdf-sha512,x25519 ",
    /* good value followed by extra stuff */
    "0x10,0x01,0x02,",
    "0x10,0x01,0x02,,,",
    "0x10,0x01,0x01,0x02",
    "0x10,0x01,0x01,blah",
    "0x10,0x01,0x01 0x02",
    /* too few but good tokens */
    "0x10,0x01",
    "0x10",
    /* empty things */
    NULL,
    "",
    ",",
    ",,"
};

/**
 * @brief round-trips, generating keys, encrypt and decrypt
 *
 * This iterates over all mode and ciphersuite options trying
 * a key gen, encrypt and decrypt for each. The aad, info, and
 * seq inputs are randomly set or omitted each time. EVP and
 * non-EVP key generation are randomly selected.
 *
 * @return 1 for success, other otherwise
 */
static int test_hpke_modes_suites(void)
{
    int overallresult = 1;
    size_t mind = 0; /* index into hpke_mode_list */
    size_t kemind = 0; /* index into hpke_kem_list */
    size_t kdfind = 0; /* index into hpke_kdf_list */
    size_t aeadind = 0; /* index into hpke_aead_list */

    /* iterate over the different modes */
    for (mind = 0; mind < OSSL_NELEM(hpke_mode_list); mind++) {
        int hpke_mode = hpke_mode_list[mind];
        size_t aadlen = OSSL_HPKE_TSTSIZE;
        unsigned char aad[OSSL_HPKE_TSTSIZE];
        unsigned char *aadp = NULL;
        size_t infolen = 32;
        unsigned char info[32];
        unsigned char *infop = NULL;
        unsigned char lpsk[32];
        unsigned char *pskp = NULL;
        char lpskid[32];
        size_t psklen = 32;
        char *pskidp = NULL;
        EVP_PKEY *privp = NULL;
        OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
        size_t plainlen = OSSL_HPKE_TSTSIZE;
        unsigned char plain[OSSL_HPKE_TSTSIZE];
        OSSL_HPKE_CTX *rctx = NULL;
        OSSL_HPKE_CTX *ctx = NULL;

        memset(plain, 0x00, OSSL_HPKE_TSTSIZE);
        strcpy((char *)plain, "a message not in a bottle");
        plainlen = strlen((char *)plain);
        /*
         * Randomly try with/without info, aad, seq. Given mode and suite
         * combos, and this being run even a few times, we'll exercise many
         * code paths fairly quickly. We don't really care what the values
         * are but it'll be easier to debug if they're known, so we set 'em.
         */
        if (COIN_IS_HEADS) {
            aadp = aad;
            memset(aad, 'a', aadlen);
        } else {
            aadlen = 0;
        }
        if (COIN_IS_HEADS) {
            infop = info;
            memset(info, 'i', infolen);
        } else {
            infolen = 0;
        }
        if (hpke_mode == OSSL_HPKE_MODE_PSK
            || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
            pskp = lpsk;
            memset(lpsk, 'P', psklen);
            pskidp = lpskid;
            memset(lpskid, 'I', psklen - 1);
            lpskid[psklen - 1] = '\0';
        } else {
            psklen = 0;
        }
        for (kemind = 0; /* iterate over the kems, kdfs and aeads */
            overallresult == 1 && kemind < OSSL_NELEM(hpke_kem_list);
            kemind++) {
            uint16_t kem_id = hpke_kem_list[kemind];
            size_t authpublen = OSSL_HPKE_TSTSIZE;
            unsigned char authpub[OSSL_HPKE_TSTSIZE];
            unsigned char *authpubp = NULL;
            EVP_PKEY *authpriv = NULL;

            hpke_suite.kem_id = kem_id;
            if (hpke_mode == OSSL_HPKE_MODE_AUTH
                || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, authpub, &authpublen,
                        &authpriv, NULL, 0,
                        testctx, NULL))) {
                    overallresult = 0;
                }
                authpubp = authpub;
            } else {
                authpublen = 0;
            }
            for (kdfind = 0;
                overallresult == 1 && kdfind < OSSL_NELEM(hpke_kdf_list);
                kdfind++) {
                uint16_t kdf_id = hpke_kdf_list[kdfind];

                hpke_suite.kdf_id = kdf_id;
                for (aeadind = 0;
                    overallresult == 1
                    && aeadind < OSSL_NELEM(hpke_aead_list);
                    aeadind++) {
                    uint16_t aead_id = hpke_aead_list[aeadind];
                    size_t publen = OSSL_HPKE_TSTSIZE;
                    unsigned char pub[OSSL_HPKE_TSTSIZE];
                    size_t senderpublen = OSSL_HPKE_TSTSIZE;
                    unsigned char senderpub[OSSL_HPKE_TSTSIZE];
                    size_t cipherlen = OSSL_HPKE_TSTSIZE;
                    unsigned char cipher[OSSL_HPKE_TSTSIZE];
                    size_t clearlen = OSSL_HPKE_TSTSIZE;
                    unsigned char clear[OSSL_HPKE_TSTSIZE];

                    hpke_suite.aead_id = aead_id;
                    if (kdf_id >= OSSL_HPKE_KDF_ID_SHAKE128
                        && (hpke_mode == OSSL_HPKE_MODE_AUTH
                            || hpke_mode == OSSL_HPKE_MODE_PSKAUTH)) {
                        ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                            OSSL_HPKE_ROLE_SENDER, testctx, NULL);
                        rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                            OSSL_HPKE_ROLE_RECEIVER, testctx, NULL);
                        if (!TEST_ptr_null(ctx) || !TEST_ptr_null(rctx))
                            overallresult = 0;
                        OSSL_HPKE_CTX_free(ctx);
                        OSSL_HPKE_CTX_free(rctx);
                        continue;
                    }
                    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite,
                            pub, &publen, &privp,
                            NULL, 0, testctx, NULL)))
                        overallresult = 0;
                    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                      OSSL_HPKE_ROLE_SENDER,
                                      testctx, NULL)))
                        overallresult = 0;
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(ctx, pskidp,
                                pskp, psklen)))
                            overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(ctx,
                                authpriv)))
                            overallresult = 0;
                    }
                    if (!TEST_true(OSSL_HPKE_encap(ctx, senderpub,
                            &senderpublen,
                            pub, publen,
                            infop, infolen)))
                        overallresult = 0;
                    /* throw in a call with a too-short cipherlen */
                    cipherlen = 15;
                    if (!TEST_false(OSSL_HPKE_seal(ctx, cipher, &cipherlen,
                            aadp, aadlen,
                            plain, plainlen)))
                        overallresult = 0;
                    /* fix back real cipherlen */
                    cipherlen = OSSL_HPKE_TSTSIZE;
                    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen,
                            aadp, aadlen,
                            plain, plainlen)))
                        overallresult = 0;
                    OSSL_HPKE_CTX_free(ctx);
                    memset(clear, 0, clearlen);
                    rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                        OSSL_HPKE_ROLE_RECEIVER,
                        testctx, NULL);
                    if (!TEST_ptr(rctx))
                        overallresult = 0;
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        if (!TEST_true(OSSL_HPKE_CTX_set1_psk(rctx, pskidp,
                                pskp, psklen)))
                            overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        /* check a borked p256 key */
                        if (hpke_suite.kem_id == OSSL_HPKE_KEM_ID_P256) {
                            /* set to fail decode of authpub this time */
                            if (!TEST_false(OSSL_HPKE_CTX_set1_authpub(rctx,
                                    authpub,
                                    10)))
                                overallresult = 0;
                        }
                        if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(rctx,
                                authpubp,
                                authpublen)))
                            overallresult = 0;
                    }
                    if (!TEST_true(OSSL_HPKE_decap(rctx, senderpub,
                            senderpublen, privp,
                            infop, infolen)))
                        overallresult = 0;
                    /* throw in a call with a too-short clearlen */
                    clearlen = 15;
                    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen,
                            aadp, aadlen, cipher,
                            cipherlen)))
                        overallresult = 0;
                    /* fix up real clearlen again */
                    clearlen = OSSL_HPKE_TSTSIZE;
                    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen,
                            aadp, aadlen, cipher,
                            cipherlen)))
                        overallresult = 0;
                    OSSL_HPKE_CTX_free(rctx);
                    EVP_PKEY_free(privp);
                    privp = NULL;
                    /* check output */
                    if (!TEST_mem_eq(clear, clearlen, plain, plainlen)) {
                        overallresult = 0;
                    }
                    if (verbose || overallresult != 1) {
                        const char *res = NULL;

                        res = (overallresult == 1 ? "worked" : "failed");
                        TEST_note("HPKE %s for mode: %s/0x%02x, "
                                  "kem: %s/0x%02x, kdf: %s/0x%02x, "
                                  "aead: %s/0x%02x",
                            res,
                            mode_str_list[mind], (int)mind,
                            kem_str_list[kemind], kem_id,
                            kdf_str_list[kdfind], kdf_id,
                            aead_str_list[aeadind], aead_id);
                    }
                }
            }
            EVP_PKEY_free(authpriv);
        }
    }
    return overallresult;
}

/**
 * @brief check roundtrip for export
 * @return 1 for success, other otherwise
 */
static int test_hpke_export(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char exp[32];
    unsigned char exp2[32];
    unsigned char rexp[32];
    unsigned char rexp2[32];
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TSTSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);
    char *estr = "foo";

    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* a few error cases 1st */
    if (!TEST_false(OSSL_HPKE_export(NULL, exp, sizeof(exp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    /* ctx before encap should fail too */
    if (!TEST_false(OSSL_HPKE_export(ctx, exp, sizeof(exp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;
    /* now for real */
    if (!TEST_true(OSSL_HPKE_export(ctx, exp, sizeof(exp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    /* check a 2nd call with same input gives same output */
    if (!TEST_true(OSSL_HPKE_export(ctx, exp2, sizeof(exp2),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    if (!TEST_mem_eq(exp, sizeof(exp), exp2, sizeof(exp2)))
        goto end;
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_export(rctx, rexp, sizeof(rexp),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    /* check a 2nd call with same input gives same output */
    if (!TEST_true(OSSL_HPKE_export(rctx, rexp2, sizeof(rexp2),
            (unsigned char *)estr, strlen(estr))))
        goto end;
    if (!TEST_mem_eq(rexp, sizeof(rexp), rexp2, sizeof(rexp2)))
        goto end;
    if (!TEST_mem_eq(exp, sizeof(exp), rexp, sizeof(rexp)))
        goto end;
    erv = 1;
end:
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(privp);
    return erv;
}

static int test_hpke_export_limits(int idx)
{
    OSSL_HPKE_SUITE suite = {
        OSSL_HPKE_KEM_ID_P256, 0, OSSL_HPKE_AEAD_ID_EXPORTONLY
    };
    OSSL_HPKE_CTX *ctx = NULL, *rctx = NULL;
    EVP_PKEY *priv = NULL;
    unsigned char pub[OSSL_HPKE_TSTSIZE], enc[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub), enclen = sizeof(enc), limit;
    unsigned char *secret = NULL, *rsecret = NULL;
    int ret = 0;

    suite.kdf_id = hpke_kdf_list[idx];
    switch (suite.kdf_id) {
    case OSSL_HPKE_KDF_ID_HKDF_SHA256:
        limit = 255 * 32;
        break;
    case OSSL_HPKE_KDF_ID_HKDF_SHA384:
        limit = 255 * 48;
        break;
    case OSSL_HPKE_KDF_ID_HKDF_SHA512:
        limit = 255 * 64;
        break;
    default:
        limit = 65535;
        break;
    }
    if (!TEST_ptr(secret = OPENSSL_malloc(limit + 1))
        || !TEST_ptr(rsecret = OPENSSL_malloc(limit + 1))
        || !TEST_true(OSSL_HPKE_keygen(suite, pub, &publen, &priv,
            NULL, 0, testctx, testpropq))
        || !TEST_ptr(ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite,
                         OSSL_HPKE_ROLE_SENDER, testctx, testpropq))
        || !TEST_ptr(rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite,
                         OSSL_HPKE_ROLE_RECEIVER, testctx, testpropq))
        || !TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen,
            NULL, 0))
        || !TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, priv, NULL, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_export(ctx, secret, limit + 1, NULL, 0))
        || !TEST_false(OSSL_HPKE_export(rctx, rsecret, limit + 1, NULL, 0))
        || !TEST_true(OSSL_HPKE_export(ctx, secret, limit, NULL, 0))
        || !TEST_true(OSSL_HPKE_export(rctx, rsecret, limit, NULL, 0))
        || !TEST_mem_eq(secret, limit, rsecret, limit))
        goto end;
    ret = 1;
end:
    OPENSSL_free(secret);
    OPENSSL_free(rsecret);
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(priv);
    return ret;
}

/**
 * @brief Check mapping from strings to HPKE suites
 * @return 1 for success, other otherwise
 */
static int test_hpke_suite_strs(void)
{
    int overallresult = 1;
    int kemind = 0;
    int kdfind = 0;
    int aeadind = 0;
    int sind = 0;
    char sstr[128];
    OSSL_HPKE_SUITE stirred;
    char giant[2048];

    for (kemind = 0; kemind != OSSL_NELEM(kem_str_list); kemind++) {
        for (kdfind = 0; kdfind != OSSL_NELEM(kdf_str_list); kdfind++) {
            for (aeadind = 0; aeadind != OSSL_NELEM(aead_str_list); aeadind++) {
                snprintf(sstr, 128, "%s,%s,%s", kem_str_list[kemind],
                    kdf_str_list[kdfind], aead_str_list[aeadind]);
                if (!TEST_true(OSSL_HPKE_str2suite(sstr, &stirred))) {
                    if (verbose)
                        TEST_note("Unexpected str2suite fail for :%s",
                            bogus_suite_strs[sind]);
                    overallresult = 0;
                } else if (kdfind < (int)OSSL_NELEM(hpke_kdf_list)
                    && !TEST_uint_eq(stirred.kdf_id, hpke_kdf_list[kdfind])) {
                    overallresult = 0;
                }
            }
        }
    }
    for (sind = 0; sind != OSSL_NELEM(bogus_suite_strs); sind++) {
        if (!TEST_false(OSSL_HPKE_str2suite(bogus_suite_strs[sind],
                &stirred))) {
            if (verbose)
                TEST_note("OSSL_HPKE_str2suite didn't fail for bogus[%d]:%s",
                    sind, bogus_suite_strs[sind]);
            overallresult = 0;
        }
    }
    /* check a few errors */
    if (!TEST_false(OSSL_HPKE_str2suite("", &stirred)))
        overallresult = 0;
    if (!TEST_false(OSSL_HPKE_str2suite(NULL, &stirred)))
        overallresult = 0;
    if (!TEST_false(OSSL_HPKE_str2suite("", NULL)))
        overallresult = 0;
    memset(giant, 'A', sizeof(giant) - 1);
    giant[sizeof(giant) - 1] = '\0';
    if (!TEST_false(OSSL_HPKE_str2suite(giant, &stirred)))
        overallresult = 0;

    return overallresult;
}

/**
 * @brief try the various GREASEy APIs
 * @return 1 for success, other otherwise
 */
static int test_hpke_grease(void)
{
    int overallresult = 1;
    OSSL_HPKE_SUITE g_suite;
    unsigned char g_pub[OSSL_HPKE_TSTSIZE];
    size_t g_pub_len = OSSL_HPKE_TSTSIZE;
    unsigned char g_cipher[OSSL_HPKE_TSTSIZE];
    size_t g_cipher_len = 266;
    size_t clearlen = 128;
    size_t expanded = 0;
    size_t enclen = 0;
    size_t ikmelen = 0;

    memset(&g_suite, 0, sizeof(OSSL_HPKE_SUITE));
    /* GREASEing */
    /* check too short for public value */
    g_pub_len = 10;
    if (!TEST_false(OSSL_HPKE_get_grease_value(NULL, &g_suite,
            g_pub, &g_pub_len,
            g_cipher, g_cipher_len,
            testctx, NULL))) {
        overallresult = 0;
    }
    /* reset to work */
    g_pub_len = OSSL_HPKE_TSTSIZE;
    if (!TEST_true(OSSL_HPKE_get_grease_value(NULL, &g_suite,
            g_pub, &g_pub_len,
            g_cipher, g_cipher_len,
            testctx, NULL))) {
        overallresult = 0;
    }
    /* expansion */
    expanded = OSSL_HPKE_get_ciphertext_size(g_suite, clearlen);
    if (!TEST_size_t_gt(expanded, clearlen)) {
        overallresult = 0;
    }
    enclen = OSSL_HPKE_get_public_encap_size(g_suite);
    if (!TEST_size_t_ne(enclen, 0))
        overallresult = 0;
    /* not really GREASE but we'll check ikmelen thing */
    ikmelen = OSSL_HPKE_get_recommended_ikmelen(g_suite);
    if (!TEST_size_t_ne(ikmelen, 0))
        overallresult = 0;

    return overallresult;
}

/*
 * Make a set of calls with odd parameters
 */
static int test_hpke_oddcalls(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    int bad_mode = 0xbad;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE bad_suite = { 0xbad, 0xbad, 0xbad };
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TSTSIZE], smallenc[10];
    size_t enclen = sizeof(enc), smallenclen = sizeof(smallenc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);
    unsigned char fake_ikm[OSSL_HPKE_TSTSIZE];
    char *badpropq = "yeah, this won't work";
    uint64_t lseq = 0;
    char giant_pskid[OSSL_HPKE_MAX_PARMLEN + 10];
    unsigned char info[OSSL_HPKE_TSTSIZE];

    /* many of the calls below are designed to get better test coverage */

    /* NULL ctx calls */
    OSSL_HPKE_CTX_free(NULL);
    if (!TEST_false(OSSL_HPKE_CTX_set_seq(NULL, 1)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_get_seq(NULL, &lseq)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpub(NULL, pub, publen)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpriv(NULL, privp)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_ikme(NULL, NULL, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(NULL, NULL, NULL, 0)))
        goto end;

    /* bad suite calls */
    hpke_suite.aead_id = 0xbad;
    if (!TEST_false(OSSL_HPKE_suite_check(hpke_suite)))
        goto end;
    hpke_suite.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_128;
    if (!TEST_false(OSSL_HPKE_suite_check(bad_suite)))
        goto end;
    if (!TEST_false(OSSL_HPKE_get_recommended_ikmelen(bad_suite)))
        goto end;
    if (!TEST_false(OSSL_HPKE_get_public_encap_size(bad_suite)))
        goto end;
    if (!TEST_false(OSSL_HPKE_get_ciphertext_size(bad_suite, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_keygen(bad_suite, pub, &publen, &privp,
            NULL, 0, testctx, badpropq)))
        goto end;
    if (!TEST_false(OSSL_HPKE_keygen(bad_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;

    /* dodgy keygen calls */
    /* no pub */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, NULL, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    /* ikmlen but NULL ikm */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 80, testctx, NULL)))
        goto end;
    /* zero ikmlen but ikm */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            fake_ikm, 0, testctx, NULL)))
        goto end;
    /* GIANT ikmlen */
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            fake_ikm, -1, testctx, NULL)))
        goto end;
    /* short publen */
    publen = 10;
    if (!TEST_false(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    publen = sizeof(pub);

    /* encap/decap with NULLs */
    if (!TEST_false(OSSL_HPKE_encap(NULL, NULL, NULL, NULL, 0, NULL, 0)))
        goto end;
    if (!TEST_false(OSSL_HPKE_decap(NULL, NULL, 0, NULL, NULL, 0)))
        goto end;

    /*
     * run through a sender/recipient set of calls but with
     * failing calls interspersed whenever possible
     */
    /* good keygen */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;

    /* a psk context with no psk => encap fail */
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* set bad length psk */
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(ctx, "foo",
            (unsigned char *)"bar", -1)))
        goto end;
    /* set bad length pskid */
    memset(giant_pskid, 'A', sizeof(giant_pskid) - 1);
    giant_pskid[sizeof(giant_pskid) - 1] = '\0';
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(ctx, giant_pskid,
            (unsigned char *)"bar", 3)))
        goto end;
    /* still no psk really set so encap fails */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    OSSL_HPKE_CTX_free(ctx);

    /* bad suite */
    if (!TEST_ptr_null(ctx = OSSL_HPKE_CTX_new(hpke_mode, bad_suite,
                           OSSL_HPKE_ROLE_SENDER,
                           testctx, NULL)))
        goto end;
    /* bad mode */
    if (!TEST_ptr_null(ctx = OSSL_HPKE_CTX_new(bad_mode, hpke_suite,
                           OSSL_HPKE_ROLE_SENDER,
                           testctx, NULL)))
        goto end;
    /* make good ctx */
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* too long ikm */
    if (!TEST_false(OSSL_HPKE_CTX_set1_ikme(ctx, fake_ikm, -1)))
        goto end;
    /* zero length ikm */
    if (!TEST_false(OSSL_HPKE_CTX_set1_ikme(ctx, fake_ikm, 0)))
        goto end;
    /* NULL authpub */
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpub(ctx, NULL, 0)))
        goto end;
    /* NULL auth priv */
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpriv(ctx, NULL)))
        goto end;
    /* priv good, but mode is bad */
    if (!TEST_false(OSSL_HPKE_CTX_set1_authpriv(ctx, privp)))
        goto end;
    /* bad mode for psk */
    if (!TEST_false(OSSL_HPKE_CTX_set1_psk(ctx, "foo",
            (unsigned char *)"bar", 3)))
        goto end;
    /* seal before encap */
    if (!TEST_false(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;
    /* encap with dodgy public */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, NULL, 0)))
        goto end;
    /* encap with too big info */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, info, -1)))
        goto end;
    /* encap with NULL info & non-zero infolen */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, NULL, 1)))
        goto end;
    /* encap with non-NULL info & zero infolen */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, 1, info, 0)))
        goto end;
    /* encap with too small enc */
    if (!TEST_false(OSSL_HPKE_encap(ctx, smallenc, &smallenclen, pub, 1, NULL, 0)))
        goto end;
    /* good encap */
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    /* second encap fail */
    if (!TEST_false(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    plainlen = 0;
    /* should fail for no plaintext */
    if (!TEST_false(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;
    plainlen = sizeof(plain);
    /* working seal */
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;

    /* receiver side */
    /* decap fail with psk mode but no psk set */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_PSK, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    if (!TEST_false(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* done with PSK mode */
    OSSL_HPKE_CTX_free(rctx);

    /* back good calls for base mode  */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    /* open before decap */
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    /* decap with info too long */
    if (!TEST_false(OSSL_HPKE_decap(rctx, enc, enclen, privp, info, -1)))
        goto end;
    /* good decap */
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* second decap fail */
    if (!TEST_false(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* no space for recovered clear */
    clearlen = 0;
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    clearlen = OSSL_HPKE_TSTSIZE;
    /* seq wrap around test */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, -1)))
        goto end;
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    if (!TEST_mem_eq(plain, plainlen, clear, clearlen))
        goto end;
    erv = 1;
end:
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(privp);
    return erv;
}

#ifndef OPENSSL_NO_ECX
/* from RFC 9180 Appendix A.1.1 */
static const unsigned char ikm25519[] = {
    0x72, 0x68, 0x60, 0x0d, 0x40, 0x3f, 0xce, 0x43,
    0x15, 0x61, 0xae, 0xf5, 0x83, 0xee, 0x16, 0x13,
    0x52, 0x7c, 0xff, 0x65, 0x5c, 0x13, 0x43, 0xf2,
    0x98, 0x12, 0xe6, 0x67, 0x06, 0xdf, 0x32, 0x34
};
static const unsigned char pub25519[] = {
    0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
    0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
    0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
    0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31
};
#endif

/* from RFC9180 Appendix A.3.1 */
static const unsigned char ikmp256[] = {
    0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
    0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
    0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
    0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
};
static const unsigned char pubp256[] = {
    0x04, 0xa9, 0x27, 0x19, 0xc6, 0x19, 0x5d, 0x50,
    0x85, 0x10, 0x4f, 0x46, 0x9a, 0x8b, 0x98, 0x14,
    0xd5, 0x83, 0x8f, 0xf7, 0x2b, 0x60, 0x50, 0x1e,
    0x2c, 0x44, 0x66, 0xe5, 0xe6, 0x7b, 0x32, 0x5a,
    0xc9, 0x85, 0x36, 0xd7, 0xb6, 0x1a, 0x1a, 0xf4,
    0xb7, 0x8e, 0x5b, 0x7f, 0x95, 0x1c, 0x09, 0x00,
    0xbe, 0x86, 0x3c, 0x40, 0x3c, 0xe6, 0x5c, 0x9b,
    0xfc, 0xb9, 0x38, 0x26, 0x57, 0x22, 0x2d, 0x18,
    0xc4
};

/*
 * A test vector that exercises the counter iteration
 * for p256. This was contributed by Ilari L. on the
 * CFRG list, see the mail archive:
 * https://mailarchive.ietf.org/arch/msg/cfrg/4zwl_y5YN6OU9oeWZOMHNOlOa2w/
 */
static const unsigned char ikmiter[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x38, 0xb5, 0xec
};
static const unsigned char pubiter[] = {
    0x04, 0x7d, 0x0c, 0x87, 0xff, 0xd5, 0xd1, 0x45,
    0x54, 0xa7, 0x51, 0xdf, 0xa3, 0x99, 0x26, 0xa9,
    0xe3, 0x0e, 0x7c, 0x3c, 0x65, 0x62, 0x4f, 0x4b,
    0x5f, 0xb3, 0xad, 0x7a, 0xa4, 0xda, 0xc2, 0x4a,
    0xd8, 0xf5, 0xbe, 0xd0, 0xe8, 0x6e, 0xb8, 0x84,
    0x1c, 0xe4, 0x89, 0x2e, 0x0f, 0xc3, 0x87, 0xbb,
    0xdb, 0xfe, 0x16, 0x0d, 0x58, 0x9c, 0x89, 0x2d,
    0xd4, 0xb1, 0x46, 0x4a, 0xc3, 0x51, 0xc5, 0x6f,
    0xb6
};

/* from RFC9180 Appendix A.6.1 */
static const unsigned char ikmp521[] = {
    0x7f, 0x06, 0xab, 0x82, 0x15, 0x10, 0x5f, 0xc4,
    0x6a, 0xce, 0xeb, 0x2e, 0x3d, 0xc5, 0x02, 0x8b,
    0x44, 0x36, 0x4f, 0x96, 0x04, 0x26, 0xeb, 0x0d,
    0x8e, 0x40, 0x26, 0xc2, 0xf8, 0xb5, 0xd7, 0xe7,
    0xa9, 0x86, 0x68, 0x8f, 0x15, 0x91, 0xab, 0xf5,
    0xab, 0x75, 0x3c, 0x35, 0x7a, 0x5d, 0x6f, 0x04,
    0x40, 0x41, 0x4b, 0x4e, 0xd4, 0xed, 0xe7, 0x13,
    0x17, 0x77, 0x2a, 0xc9, 0x8d, 0x92, 0x39, 0xf7,
    0x09, 0x04
};
static const unsigned char pubp521[] = {
    0x04, 0x01, 0x38, 0xb3, 0x85, 0xca, 0x16, 0xbb,
    0x0d, 0x5f, 0xa0, 0xc0, 0x66, 0x5f, 0xbb, 0xd7,
    0xe6, 0x9e, 0x3e, 0xe2, 0x9f, 0x63, 0x99, 0x1d,
    0x3e, 0x9b, 0x5f, 0xa7, 0x40, 0xaa, 0xb8, 0x90,
    0x0a, 0xae, 0xed, 0x46, 0xed, 0x73, 0xa4, 0x90,
    0x55, 0x75, 0x84, 0x25, 0xa0, 0xce, 0x36, 0x50,
    0x7c, 0x54, 0xb2, 0x9c, 0xc5, 0xb8, 0x5a, 0x5c,
    0xee, 0x6b, 0xae, 0x0c, 0xf1, 0xc2, 0x1f, 0x27,
    0x31, 0xec, 0xe2, 0x01, 0x3d, 0xc3, 0xfb, 0x7c,
    0x8d, 0x21, 0x65, 0x4b, 0xb1, 0x61, 0xb4, 0x63,
    0x96, 0x2c, 0xa1, 0x9e, 0x8c, 0x65, 0x4f, 0xf2,
    0x4c, 0x94, 0xdd, 0x28, 0x98, 0xde, 0x12, 0x05,
    0x1f, 0x1e, 0xd0, 0x69, 0x22, 0x37, 0xfb, 0x02,
    0xb2, 0xf8, 0xd1, 0xdc, 0x1c, 0x73, 0xe9, 0xb3,
    0x66, 0xb5, 0x29, 0xeb, 0x43, 0x6e, 0x98, 0xa9,
    0x96, 0xee, 0x52, 0x2a, 0xef, 0x86, 0x3d, 0xd5,
    0x73, 0x9d, 0x2f, 0x29, 0xb0
};

static int test_hpke_random_suites(void)
{
    OSSL_HPKE_SUITE def_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_SUITE suite2 = { 0xff01, 0xff02, 0xff03 };
    unsigned char enc[200];
    size_t enclen = sizeof(enc);
    unsigned char ct[500];
    size_t ctlen = sizeof(ct);

    /* test with NULL/0 inputs */
    if (!TEST_false(OSSL_HPKE_get_grease_value(NULL, NULL,
            NULL, NULL, NULL, 0,
            testctx, NULL)))
        return 0;
    enclen = 10;
    if (!TEST_false(OSSL_HPKE_get_grease_value(&def_suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;

    enclen = sizeof(enc); /* reset, 'cause get_grease() will have set */
    /* test with a should-be-good suite */
    if (!TEST_true(OSSL_HPKE_get_grease_value(&def_suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    /* no suggested suite */
    enclen = sizeof(enc); /* reset, 'cause get_grease() will have set */
    if (!TEST_true(OSSL_HPKE_get_grease_value(NULL, &suite2,
            enc, &enclen,
            ct, ctlen,
            testctx, NULL)))
        return 0;
    /* suggested suite with P-521, just to be sure we hit long values */
    enclen = sizeof(enc); /* reset, 'cause get_grease() will have set */
    suite.kem_id = OSSL_HPKE_KEM_ID_P521;
    if (!TEST_true(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    enclen = sizeof(enc);
    ctlen = 2; /* too-short cttext (can't fit an aead tag) */
    if (!TEST_false(OSSL_HPKE_get_grease_value(NULL, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;

    ctlen = sizeof(ct);
    enclen = sizeof(enc);

    suite.kem_id = OSSL_HPKE_KEM_ID_X25519; /* back to default */
    suite.aead_id = 0x1234; /* bad aead */
    if (!TEST_false(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    enclen = sizeof(enc);
    suite.aead_id = def_suite.aead_id; /* good aead */
    suite.kdf_id = 0x3451; /* bad kdf */
    if (!TEST_false(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    enclen = sizeof(enc);
    suite.kdf_id = def_suite.kdf_id; /* good kdf */
    suite.kem_id = 0x4517; /* bad kem */
    if (!TEST_false(OSSL_HPKE_get_grease_value(&suite, &suite2,
            enc, &enclen, ct, ctlen,
            testctx, NULL)))
        return 0;
    return 1;
}

/*
 * @brief generate a key pair from initial key material (ikm) and check public
 * @param kem_id the KEM to use (RFC9180 code point)
 * @ikm is the initial key material buffer
 * @ikmlen is the length of ikm
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, other otherwise
 *
 * This calls OSSL_HPKE_keygen specifying only the IKM, then
 * compares the key pair values with the already-known values
 * that were input.
 */
static int test_hpke_one_ikm_gen(uint16_t kem_id,
    const unsigned char *ikm, size_t ikmlen,
    const unsigned char *pub, size_t publen)
{
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char lpub[OSSL_HPKE_TSTSIZE];
    size_t lpublen = OSSL_HPKE_TSTSIZE;
    EVP_PKEY *sk = NULL;

    hpke_suite.kem_id = kem_id;
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, lpub, &lpublen, &sk,
            ikm, ikmlen, testctx, NULL)))
        return 0;
    if (!TEST_ptr(sk))
        return 0;
    EVP_PKEY_free(sk);
    if (!TEST_mem_eq(pub, publen, lpub, lpublen))
        return 0;
    return 1;
}

/*
 * @brief test some uses of IKM produce the expected public keys
 */
static int test_hpke_ikms(void)
{
    int res = 1;

#ifndef OPENSSL_NO_ECX
    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_X25519,
        ikm25519, sizeof(ikm25519),
        pub25519, sizeof(pub25519));
    if (res != 1)
        return res;
#endif

    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_P521,
        ikmp521, sizeof(ikmp521),
        pubp521, sizeof(pubp521));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_P256,
        ikmp256, sizeof(ikmp256),
        pubp256, sizeof(pubp256));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(OSSL_HPKE_KEM_ID_P256,
        ikmiter, sizeof(ikmiter),
        pubiter, sizeof(pubiter));
    if (res != 1)
        return res;

    return res;
}

/*
 * Test that use of a compressed format auth public key works
 * We'll do a typical round-trip for auth mode but provide the
 * auth public key in compressed form. That should work.
 */
static int test_hpke_compressed(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    EVP_PKEY *authpriv = NULL;
    unsigned char authpub[OSSL_HPKE_TSTSIZE];
    size_t authpublen = sizeof(authpub);
    int hpke_mode = OSSL_HPKE_MODE_AUTH;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TSTSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);

    hpke_suite.kem_id = OSSL_HPKE_KEM_ID_P256;

    /* generate auth key pair */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, authpub, &authpublen, &authpriv,
            NULL, 0, testctx, NULL)))
        goto end;
    /* now get the compressed form public key */
    if (!TEST_true(EVP_PKEY_set_utf8_string_param(authpriv,
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
            OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED)))
        goto end;
    if (!TEST_true(EVP_PKEY_get_octet_string_param(authpriv,
            OSSL_PKEY_PARAM_PUB_KEY,
            authpub,
            sizeof(authpub),
            &authpublen)))
        goto end;

    /* sender side as usual */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_authpriv(ctx, authpriv)))
        goto end;
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;

    /* receiver side providing compressed form of auth public */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    if (!TEST_true(OSSL_HPKE_CTX_set1_authpub(rctx, authpub, authpublen)))
        goto end;
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    erv = 1;

end:
    EVP_PKEY_free(privp);
    EVP_PKEY_free(authpriv);
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    return erv;
}

/*
 * Test that nonce reuse calls are prevented as we expect
 */
static int test_hpke_noncereuse(void)
{
    int erv = 0;
    EVP_PKEY *privp = NULL;
    unsigned char pub[OSSL_HPKE_TSTSIZE];
    size_t publen = sizeof(pub);
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    unsigned char plain[] = "quick brown fox";
    size_t plainlen = sizeof(plain);
    unsigned char enc[OSSL_HPKE_TSTSIZE];
    size_t enclen = sizeof(enc);
    unsigned char cipher[OSSL_HPKE_TSTSIZE];
    size_t cipherlen = sizeof(cipher);
    unsigned char clear[OSSL_HPKE_TSTSIZE];
    size_t clearlen = sizeof(clear);
    uint64_t seq = 0xbad1dea;

    /* sender side is not allowed set seq once some crypto done */
    if (!TEST_true(OSSL_HPKE_keygen(hpke_suite, pub, &publen, &privp,
            NULL, 0, testctx, NULL)))
        goto end;
    if (!TEST_ptr(ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_SENDER,
                      testctx, NULL)))
        goto end;
    /* set seq will fail before any crypto done */
    if (!TEST_false(OSSL_HPKE_CTX_set_seq(ctx, seq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, NULL, 0)))
        goto end;
    /* set seq will also fail after some crypto done */
    if (!TEST_false(OSSL_HPKE_CTX_set_seq(ctx, seq + 1)))
        goto end;
    if (!TEST_true(OSSL_HPKE_seal(ctx, cipher, &cipherlen, NULL, 0,
            plain, plainlen)))
        goto end;

    /* receiver side is allowed control seq */
    if (!TEST_ptr(rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                      OSSL_HPKE_ROLE_RECEIVER,
                      testctx, NULL)))
        goto end;
    /* set seq will work before any crypto done */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, seq)))
        goto end;
    if (!TEST_true(OSSL_HPKE_decap(rctx, enc, enclen, privp, NULL, 0)))
        goto end;
    /* set seq will work for receivers even after crypto done */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, seq)))
        goto end;
    /* but that value isn't good so decap will fail */
    if (!TEST_false(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    /* reset seq to correct value and _open() should work */
    if (!TEST_true(OSSL_HPKE_CTX_set_seq(rctx, 0)))
        goto end;
    if (!TEST_true(OSSL_HPKE_open(rctx, clear, &clearlen, NULL, 0,
            cipher, cipherlen)))
        goto end;
    erv = 1;

end:
    EVP_PKEY_free(privp);
    OSSL_HPKE_CTX_free(ctx);
    OSSL_HPKE_CTX_free(rctx);
    return erv;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_VERBOSE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "v", OPT_VERBOSE, '-', "Enable verbose mode" },
        { OPT_HELP_STR, 1, '-', "Run HPKE tests\n" },
        { NULL }
    };
    return test_options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_VERBOSE:
            verbose = 1; /* Print progress dots */
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    if (!test_get_libctx(&testctx, &nullprov, NULL, &deflprov, "default"))
        return 0;
#ifndef OPENSSL_NO_ECX
    ADD_TEST(export_only_test);
    ADD_TEST(x25519kdfsha256_hkdfsha256_aes128gcm_base_test);
    ADD_TEST(x25519kdfsha256_hkdfsha256_aes128gcm_psk_test);
#endif
    ADD_TEST(P256kdfsha256_hkdfsha256_aes128gcm_base_test);
    ADD_ALL_TESTS(test_hpke_single_stage_vectors, 2 * OSSL_NELEM(single_stage_tests));
    ADD_TEST(test_hpke_export);
    ADD_ALL_TESTS(test_hpke_export_limits, OSSL_NELEM(hpke_kdf_list));
    ADD_TEST(test_hpke_modes_suites);
    ADD_TEST(test_hpke_suite_strs);
    ADD_TEST(test_hpke_grease);
    ADD_TEST(test_hpke_ikms);
    ADD_TEST(test_hpke_random_suites);
    ADD_TEST(test_hpke_oddcalls);
    ADD_TEST(test_hpke_compressed);
    ADD_TEST(test_hpke_noncereuse);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(deflprov);
    OSSL_PROVIDER_unload(nullprov);
    OSSL_LIB_CTX_free(testctx);
}
