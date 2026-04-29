/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "internal/common.h"
#include "internal/numbers.h" /* includes SIZE_MAX */
#include "internal/sha3.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "turboshake_prov.h"

#define TURBOSHAKE_FLAGS (PROV_DIGEST_FLAG_XOF | PROV_DIGEST_FLAG_ALGID_ABSENT)

#define TURBOSHAKE_DOMAIN_DEFAULT 0x1f
#define TURBOSHAKE_DOMAIN_MIN 0x01
#define TURBOSHAKE_DOMAIN_MAX 0x7f

#include "providers/implementations/digests/turboshake_prov.inc"

typedef struct turboshake_ctx_st {
    KECCAK1600_CTX kctx;
    size_t bitlen;
} TURBOSHAKE_CTX;

static OSSL_FUNC_digest_init_fn turboshake_init;
static OSSL_FUNC_digest_update_fn turboshake_update;
static OSSL_FUNC_digest_final_fn turboshake_final;
static OSSL_FUNC_digest_squeeze_fn turboshake_squeeze;
static OSSL_FUNC_digest_freectx_fn turboshake_freectx;
static OSSL_FUNC_digest_dupctx_fn turboshake_dupctx;
static OSSL_FUNC_digest_copyctx_fn turboshake_copyctx;
static OSSL_FUNC_digest_get_ctx_params_fn turboshake_get_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn turboshake_gettable_ctx_params;
static OSSL_FUNC_digest_set_ctx_params_fn turboshake_set_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn turboshake_settable_ctx_params;

static size_t turboshake_absorb_p12(KECCAK1600_CTX *ctx,
    const unsigned char *inp, size_t len)
{
    return ossl_keccak1600_absorb_p12(ctx->A, inp, len, ctx->block_size);
}

static int turboshake_final_p12(KECCAK1600_CTX *ctx, unsigned char *out,
    size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t num = ctx->bufsz;

    memset(ctx->buf + num, 0, bsz - num);
    ctx->buf[num] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (void)ossl_keccak1600_absorb_p12(ctx->A, ctx->buf, bsz, bsz);
    ossl_keccak1600_squeeze_p12(ctx->A, out, outlen, bsz, 0);
    return 1;
}

static int turboshake_squeeze_p12(KECCAK1600_CTX *ctx, unsigned char *out,
    size_t outlen)
{
    size_t bsz = ctx->block_size;
    size_t num = ctx->bufsz;
    size_t len;
    int next = 1;

    if (ctx->xof_state != XOF_STATE_SQUEEZE) {
        memset(ctx->buf + num, 0, bsz - num);
        ctx->buf[num] = ctx->pad;
        ctx->buf[bsz - 1] |= 0x80;
        (void)ossl_keccak1600_absorb_p12(ctx->A, ctx->buf, bsz, bsz);
        num = ctx->bufsz = 0;
        next = 0;
    }

    if (num != 0) {
        len = outlen > ctx->bufsz ? ctx->bufsz : outlen;
        memcpy(out, ctx->buf + bsz - ctx->bufsz, len);
        out += len;
        outlen -= len;
        ctx->bufsz -= len;
    }
    if (outlen == 0)
        return 1;

    if (outlen >= bsz) {
        len = bsz * (outlen / bsz);
        ossl_keccak1600_squeeze_p12(ctx->A, out, len, bsz, next);
        next = 1;
        out += len;
        outlen -= len;
    }
    if (outlen > 0) {
        ossl_keccak1600_squeeze_p12(ctx->A, ctx->buf, bsz, bsz, next);
        memcpy(out, ctx->buf, outlen);
        ctx->bufsz = bsz - outlen;
    }
    return 1;
}

static PROV_SHA3_METHOD turboshake_p12_md = {
    turboshake_absorb_p12,
    turboshake_final_p12,
    turboshake_squeeze_p12
};

int ossl_turboshake_init_keccak(KECCAK1600_CTX *ctx, size_t bitlen,
    unsigned int domain, size_t xoflen)
{
    if (domain < TURBOSHAKE_DOMAIN_MIN || domain > TURBOSHAKE_DOMAIN_MAX)
        return 0;
    if (!ossl_sha3_init(ctx, (unsigned char)domain, bitlen))
        return 0;
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
    ctx->md_size = xoflen;
    ctx->meth = turboshake_p12_md;
    return 1;
}

static void *turboshake_newctx(void *provctx, size_t bitlen)
{
    TURBOSHAKE_CTX *ctx;

    DIGEST_PROV_CHECK(provctx, SHA3_256);
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->bitlen = bitlen;
    if (!ossl_turboshake_init_keccak(&ctx->kctx, bitlen,
            TURBOSHAKE_DOMAIN_DEFAULT, bitlen == 128 ? 32 : 64)) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return NULL;
    }
    return ctx;
}

static int turboshake_init(void *vctx, const OSSL_PARAM params[])
{
    TURBOSHAKE_CTX *ctx = vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    return ossl_turboshake_init_keccak(&ctx->kctx, ctx->bitlen,
        TURBOSHAKE_DOMAIN_DEFAULT, ctx->bitlen == 128 ? 32 : 64)
        && turboshake_set_ctx_params(vctx, params);
}

static int turboshake_update(void *vctx, const unsigned char *inp, size_t len)
{
    TURBOSHAKE_CTX *ctx = vctx;

    return ossl_sha3_absorb(&ctx->kctx, inp, len);
}

static int turboshake_final(void *vctx, unsigned char *out, size_t *outl,
    size_t outsz)
{
    TURBOSHAKE_CTX *ctx = vctx;
    size_t xoflen = ctx->kctx.md_size;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    if (outsz < xoflen)
        return 0;
    if (xoflen > 0 && !ossl_sha3_final(&ctx->kctx, out, xoflen))
        return 0;
    if (outl != NULL)
        *outl = xoflen;
    return 1;
}

static int turboshake_squeeze(void *vctx, unsigned char *out, size_t *outl,
    size_t outsz)
{
    TURBOSHAKE_CTX *ctx = vctx;

    if (ossl_unlikely(!ossl_prov_is_running()))
        return 0;
    if (outsz > 0 && !ossl_sha3_squeeze(&ctx->kctx, out, outsz))
        return 0;
    if (outl != NULL)
        *outl = outsz;
    return 1;
}

static void turboshake_freectx(void *vctx)
{
    TURBOSHAKE_CTX *ctx = vctx;

    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *turboshake_dupctx(void *vctx)
{
    TURBOSHAKE_CTX *in = vctx;
    TURBOSHAKE_CTX *ret = ossl_prov_is_running() ? OPENSSL_malloc(sizeof(*ret))
                                                 : NULL;

    if (ret != NULL)
        *ret = *in;
    return ret;
}

static void turboshake_copyctx(void *voutctx, void *vinctx)
{
    TURBOSHAKE_CTX *outctx = voutctx;
    TURBOSHAKE_CTX *inctx = vinctx;

    *outctx = *inctx;
}

static const OSSL_PARAM *turboshake_gettable_ctx_params(
    ossl_unused void *ctx, ossl_unused void *provctx)
{
    return turboshake_get_ctx_params_list;
}

static int turboshake_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    TURBOSHAKE_CTX *ctx = vctx;
    struct turboshake_get_ctx_params_st p;
    size_t xoflen;
    unsigned int domain;

    if (ctx == NULL || !turboshake_get_ctx_params_decoder(params, &p))
        return 0;

    xoflen = ctx->kctx.md_size;
    if (p.size != NULL && !OSSL_PARAM_set_size_t(p.size, xoflen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    if (p.xoflen != NULL && !OSSL_PARAM_set_size_t(p.xoflen, xoflen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    domain = ctx->kctx.pad;
    if (p.domain != NULL && !OSSL_PARAM_set_uint(p.domain, domain)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    return 1;
}

static const OSSL_PARAM *turboshake_settable_ctx_params(
    ossl_unused void *ctx, ossl_unused void *provctx)
{
    return turboshake_set_ctx_params_list;
}

static int turboshake_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    TURBOSHAKE_CTX *ctx = vctx;
    struct turboshake_set_ctx_params_st p;
    int has_change = 0;

    if (ctx == NULL || !turboshake_set_ctx_params_decoder(params, &p))
        return 0;

    has_change = p.xoflen != NULL || p.domain != NULL;
    if (has_change && (ctx->kctx.xof_state == XOF_STATE_FINAL
            || ctx->kctx.xof_state == XOF_STATE_SQUEEZE))
        return 0;

    if (p.xoflen != NULL
        && !OSSL_PARAM_get_size_t(p.xoflen, &ctx->kctx.md_size)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }
    if (p.domain != NULL) {
        unsigned int domain;

        if (!OSSL_PARAM_get_uint(p.domain, &domain)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (domain < TURBOSHAKE_DOMAIN_MIN || domain > TURBOSHAKE_DOMAIN_MAX) {
            ERR_raise(ERR_LIB_PROV, PROV_R_VALUE_ERROR);
            return 0;
        }
        ctx->kctx.pad = (unsigned char)domain;
    }
    return 1;
}

static const unsigned char turboshake_magic[] = "TSHAKEv1";
#define TURBOSHAKE_MAGIC_LEN (sizeof(turboshake_magic) - 1)
#define TURBOSHAKE_SERIALIZATION_LEN                                                \
    (                                                                               \
        TURBOSHAKE_MAGIC_LEN                                                        \
        + sizeof(uint64_t)                                                          \
        + sizeof(uint64_t)                                                          \
        + (sizeof(uint64_t) * 4)                                                     \
        + (sizeof(uint64_t) * 5 * 5)                                                 \
        + (KECCAK1600_WIDTH / 8 - 32)                                                \
    )

static int turboshake_serialize_ctx(TURBOSHAKE_CTX *ctx, int impl_id,
    unsigned char *output, size_t *outlen)
{
    KECCAK1600_CTX *c = &ctx->kctx;
    unsigned char *p;
    int i, j;

    if (output == NULL) {
        if (outlen == NULL)
            return 0;
        *outlen = TURBOSHAKE_SERIALIZATION_LEN;
        return 1;
    }

    if (outlen != NULL && *outlen < TURBOSHAKE_SERIALIZATION_LEN)
        return 0;

    p = output;
    memcpy(p, turboshake_magic, TURBOSHAKE_MAGIC_LEN);
    p += TURBOSHAKE_MAGIC_LEN;

    p = OPENSSL_store_u64_le(p, impl_id);
    p = OPENSSL_store_u64_le(p, c->md_size);
    p = OPENSSL_store_u64_le(p, c->block_size);
    p = OPENSSL_store_u64_le(p, c->bufsz);
    p = OPENSSL_store_u64_le(p, c->pad);
    p = OPENSSL_store_u64_le(p, c->xof_state);

    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++)
            p = OPENSSL_store_u64_le(p, c->A[i][j]);

    memcpy(p, c->buf, sizeof(c->buf));
    if (outlen != NULL)
        *outlen = TURBOSHAKE_SERIALIZATION_LEN;
    return 1;
}

static int turboshake_deserialize_ctx(TURBOSHAKE_CTX *ctx, int impl_id,
    const unsigned char *input, size_t inlen)
{
    KECCAK1600_CTX *c = &ctx->kctx;
    const unsigned char *p;
    uint64_t val;
    int i, j;

    if (ctx == NULL || input == NULL || inlen != TURBOSHAKE_SERIALIZATION_LEN)
        return 0;
    if (memcmp(input, turboshake_magic, TURBOSHAKE_MAGIC_LEN) != 0)
        return 0;

    p = input + TURBOSHAKE_MAGIC_LEN;
    p = OPENSSL_load_u64_le(&val, p);
    if (val != (uint64_t)impl_id)
        return 0;

    p = OPENSSL_load_u64_le(&val, p);
    if (val > SIZE_MAX)
        return 0;
    c->md_size = (size_t)val;

    p = OPENSSL_load_u64_le(&val, p);
    if (val != c->block_size)
        return 0;

    p = OPENSSL_load_u64_le(&val, p);
    if (val > c->block_size)
        return 0;
    c->bufsz = (size_t)val;

    p = OPENSSL_load_u64_le(&val, p);
    if (val < TURBOSHAKE_DOMAIN_MIN || val > TURBOSHAKE_DOMAIN_MAX)
        return 0;
    c->pad = (unsigned char)val;

    p = OPENSSL_load_u64_le(&val, p);
    if (val > XOF_STATE_SQUEEZE)
        return 0;
    c->xof_state = (int)val;

    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++) {
            p = OPENSSL_load_u64_le(&val, p);
            c->A[i][j] = val;
        }

    memcpy(c->buf, p, sizeof(c->buf));
    return 1;
}

#define TURBOSHAKE_SER_ID 0x98610000

#define IMPLEMENT_TURBOSHAKE(bitlen)                                             \
    static OSSL_FUNC_digest_newctx_fn turboshake_##bitlen##_newctx;              \
    static OSSL_FUNC_digest_serialize_fn turboshake_##bitlen##_serialize;        \
    static OSSL_FUNC_digest_deserialize_fn turboshake_##bitlen##_deserialize;    \
    static void *turboshake_##bitlen##_newctx(void *provctx)                     \
    {                                                                            \
        return turboshake_newctx(provctx, bitlen);                               \
    }                                                                            \
    static int turboshake_##bitlen##_serialize(void *vctx, unsigned char *out,   \
        size_t *outlen)                                                          \
    {                                                                            \
        return turboshake_serialize_ctx(vctx, TURBOSHAKE_SER_ID + bitlen, out,   \
            outlen);                                                             \
    }                                                                            \
    static int turboshake_##bitlen##_deserialize(void *vctx,                     \
        const unsigned char *in, size_t inlen)                                   \
    {                                                                            \
        return turboshake_deserialize_ctx(vctx, TURBOSHAKE_SER_ID + bitlen, in,  \
            inlen);                                                              \
    }                                                                            \
    PROV_FUNC_DIGEST_GET_PARAM(turboshake_##bitlen, SHA3_BLOCKSIZE(bitlen),      \
        bitlen == 128 ? 32 : 64, TURBOSHAKE_FLAGS)                               \
    const OSSL_DISPATCH ossl_turboshake_##bitlen##_functions[] = {               \
        { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))turboshake_##bitlen##_newctx }, \
        { OSSL_FUNC_DIGEST_INIT, (void (*)(void))turboshake_init },              \
        { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))turboshake_update },          \
        { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))turboshake_final },            \
        { OSSL_FUNC_DIGEST_SQUEEZE, (void (*)(void))turboshake_squeeze },        \
        { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))turboshake_freectx },        \
        { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))turboshake_dupctx },          \
        { OSSL_FUNC_DIGEST_COPYCTX, (void (*)(void))turboshake_copyctx },        \
        { OSSL_FUNC_DIGEST_SERIALIZE, (void (*)(void))turboshake_##bitlen##_serialize }, \
        { OSSL_FUNC_DIGEST_DESERIALIZE, (void (*)(void))turboshake_##bitlen##_deserialize }, \
        { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void))turboshake_set_ctx_params }, \
        { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,                                  \
            (void (*)(void))turboshake_settable_ctx_params },                    \
        { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))turboshake_get_ctx_params }, \
        { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,                                  \
            (void (*)(void))turboshake_gettable_ctx_params },                    \
        PROV_DISPATCH_FUNC_DIGEST_GET_PARAMS(turboshake_##bitlen),               \
        PROV_DISPATCH_FUNC_DIGEST_CONSTRUCT_END

/* ossl_turboshake_128_functions */
IMPLEMENT_TURBOSHAKE(128)
/* ossl_turboshake_256_functions */
IMPLEMENT_TURBOSHAKE(256)
