/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - RSA Signature Operations
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "keyring_provider.h"

/* Forward declarations */
static OSSL_FUNC_signature_newctx_fn keyring_sig_newctx;
static OSSL_FUNC_signature_freectx_fn keyring_sig_freectx;
static OSSL_FUNC_signature_dupctx_fn keyring_sig_dupctx;
static OSSL_FUNC_signature_sign_init_fn keyring_sig_sign_init;
static OSSL_FUNC_signature_sign_fn keyring_sig_sign;
static OSSL_FUNC_signature_verify_init_fn keyring_sig_verify_init;
static OSSL_FUNC_signature_verify_fn keyring_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn keyring_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn keyring_sig_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn keyring_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn keyring_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn keyring_sig_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn keyring_sig_digest_verify_final;
static OSSL_FUNC_signature_get_ctx_params_fn keyring_sig_get_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn keyring_sig_set_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn keyring_sig_gettable_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn keyring_sig_settable_ctx_params;

/* Dispatch table */
const OSSL_DISPATCH keyring_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))keyring_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))keyring_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))keyring_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))keyring_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))keyring_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))keyring_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))keyring_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))keyring_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))keyring_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))keyring_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))keyring_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))keyring_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))keyring_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))keyring_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))keyring_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))keyring_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))keyring_sig_settable_ctx_params },
    { 0, NULL }
};

/* Create new signature context */
static void *keyring_sig_newctx(void *provctx, const char *propq)
{
    keyring_sig_ctx_t *ctx;

    (void)propq; /* Property queries not used */

    ctx = keyring_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = (keyring_prov_ctx_t *)provctx;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    ctx->pad_mode = (char *)keyring_default_pad_mode;  /* Static constant, freed via pointer comparison */
#pragma GCC diagnostic pop
    ctx->saltlen = -1;  /* Default salt length for PSS */

    return ctx;
}

/* Free signature context */
static void keyring_sig_freectx(void *vctx)
{
    keyring_sig_ctx_t *ctx = vctx;

    if (ctx == NULL)
        return;

    keyring_key_free(ctx->key_ctx);
    if (ctx->md != NULL)
        EVP_MD_free(ctx->md);

    /* Free dynamically allocated strings (mdname is always dynamically allocated if not NULL) */
    keyring_free(ctx->mdname);
    /* pad_mode: only free if not pointing to static keyring_default_pad_mode constant */
    if (ctx->pad_mode != NULL && ctx->pad_mode != keyring_default_pad_mode)
        keyring_free(ctx->pad_mode);

    keyring_free(ctx);
}

/* Duplicate signature context */
static void *keyring_sig_dupctx(void *vctx)
{
    keyring_sig_ctx_t *src = vctx;
    keyring_sig_ctx_t *dst;

    if (src == NULL)
        return NULL;

    dst = keyring_sig_newctx(src->provctx, NULL);
    if (dst == NULL)
        return NULL;

    if (src->key_ctx != NULL) {
        dst->key_ctx = src->key_ctx;
        keyring_key_up_ref(dst->key_ctx);
    }

    dst->mdname = src->mdname;
    dst->pad_mode = src->pad_mode;
    dst->saltlen = src->saltlen;

    if (src->md != NULL) {
        dst->md = src->md;
        EVP_MD_up_ref(dst->md);
    }

    return dst;
}

/* Initialize signature operation */
static int keyring_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    keyring_sig_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ctx->key_ctx = key;
    keyring_key_up_ref(key);

    return keyring_sig_set_ctx_params(ctx, params);
}

/* Perform signature (on already-hashed data) */
static int keyring_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    keyring_sig_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key;

    if (ctx == NULL || ctx->key_ctx == NULL)
        return 0;

    key = ctx->key_ctx;

    /* If sig is NULL, caller is querying for signature size */
    if (sig == NULL) {
        assert(key->key_size >= 0 && key->key_size <= INT_MAX); /* Key size in bits, always positive */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
        *siglen = (key->key_size + 7) / 8;  /* Return key size in bytes */
#pragma GCC diagnostic pop
        return 1;
    }

    /* Check buffer size */
    if (sigsize < (size_t)((key->key_size + 7) / 8)) {
        /* Buffer too small */
        return 0;
    }

    /* Use kernel keyring API - works for both software and TPM-backed keys */
    return keyring_pkey_sign(key->key_serial, tbs, tbslen, sig, siglen,
                            ctx->mdname, ctx->pad_mode);
}

/* Initialize verify operation */
static int keyring_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    keyring_sig_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ctx->key_ctx = key;
    keyring_key_up_ref(key);

    return keyring_sig_set_ctx_params(ctx, params);
}

/* Verify signature */
static int keyring_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen)
{
    keyring_sig_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key;
    EVP_PKEY_CTX *pkey_ctx;
    int ret;

    if (ctx == NULL || ctx->key_ctx == NULL)
        return 0;

    key = ctx->key_ctx;

    /* Verification always uses the public key via OpenSSL */
    if (key->evp_pkey == NULL) {
        /* Need to create EVP_PKEY from public key data */
        const unsigned char *p = key->public_key;
        assert(key->public_key_len <= LONG_MAX); /* d2i_PUBKEY takes long, ensure safe conversion */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
        key->evp_pkey = d2i_PUBKEY(NULL, &p, key->public_key_len);
#pragma GCC diagnostic pop
        if (key->evp_pkey == NULL)
            return 0;
    }

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (pkey_ctx == NULL)
        return 0;

    if (EVP_PKEY_verify_init(pkey_ctx) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return 0;
    }

    /* Set padding mode */
    if (strcmp(ctx->pad_mode, "pss") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            return 0;
        }
        if (ctx->saltlen >= 0) {
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, ctx->saltlen);
        }
    } else {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            return 0;
        }
    }

    /* Set digest if specified */
    if (ctx->md != NULL) {
        if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, ctx->md) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            return 0;
        }
    }

    ret = EVP_PKEY_verify(pkey_ctx, sig, siglen, tbs, tbslen);
    EVP_PKEY_CTX_free(pkey_ctx);

    return ret > 0;
}

/* Digest + sign operations */
static int keyring_sig_digest_sign_init(void *vctx, const char *mdname, void *vkey,
                                        const OSSL_PARAM params[])
{
    keyring_sig_ctx_t *ctx = vctx;

    if (ctx == NULL)
        return 0;

    /* Free old mdname if exists and duplicate new one */
    keyring_free(ctx->mdname);
    ctx->mdname = mdname ? keyring_strdup(mdname) : NULL;

    /* Fetch the digest */
    if (ctx->mdname != NULL && ctx->provctx != NULL) {
        ctx->md = EVP_MD_fetch(ctx->provctx->libctx, ctx->mdname, NULL);
        if (ctx->md == NULL)
            return 0;
    }

    return keyring_sig_sign_init(ctx, vkey, params);
}

static int keyring_sig_digest_sign_update(void *vctx, const unsigned char *data,
                                          size_t datalen)
{
    (void)vctx; (void)data; (void)datalen; /* Digest streaming not implemented */
    /* TODO: Implement digest streaming if needed */
    /* For now, we expect single-shot operations */
    return 0;
}

static int keyring_sig_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                                         size_t sigsize)
{
    (void)vctx; (void)sig; (void)siglen; (void)sigsize; /* Digest streaming not implemented */
    /* TODO: Implement digest finalization if needed */
    return 0;
}

/* Digest + verify operations */
static int keyring_sig_digest_verify_init(void *vctx, const char *mdname, void *vkey,
                                          const OSSL_PARAM params[])
{
    keyring_sig_ctx_t *ctx = vctx;

    if (ctx == NULL)
        return 0;

    /* Free old mdname if exists and duplicate new one */
    keyring_free(ctx->mdname);
    ctx->mdname = mdname ? keyring_strdup(mdname) : NULL;

    /* Fetch the digest */
    if (ctx->mdname != NULL && ctx->provctx != NULL) {
        ctx->md = EVP_MD_fetch(ctx->provctx->libctx, ctx->mdname, NULL);
        if (ctx->md == NULL)
            return 0;
    }

    return keyring_sig_verify_init(ctx, vkey, params);
}

static int keyring_sig_digest_verify_update(void *vctx, const unsigned char *data,
                                            size_t datalen)
{
    (void)vctx; (void)data; (void)datalen; /* Digest streaming not implemented */
    /* TODO: Implement digest streaming if needed */
    return 0;
}

static int keyring_sig_digest_verify_final(void *vctx, const unsigned char *sig,
                                           size_t siglen)
{
    (void)vctx; (void)sig; (void)siglen; /* Digest streaming not implemented */
    /* TODO: Implement digest finalization if needed */
    return 0;
}

/* Parameter handling */
static const OSSL_PARAM keyring_sig_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keyring_sig_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx; (void)provctx; /* Static list, no context needed */
    return keyring_sig_settable_ctx_param_types;
}

static int keyring_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    keyring_sig_ctx_t *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0))
            return 0;

        /* Free old mdname if it exists */
        keyring_free(ctx->mdname);
        /* Duplicate the string so we own it */
        ctx->mdname = keyring_strdup(mdname);
        OPENSSL_free(mdname);

        if (ctx->md != NULL)
            EVP_MD_free(ctx->md);
        if (ctx->provctx != NULL && ctx->mdname != NULL)
            ctx->md = EVP_MD_fetch(ctx->provctx->libctx, ctx->mdname, NULL);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        char *pad = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &pad, 0))
            return 0;

        /* Free old pad_mode if it's not the default static constant */
        if (ctx->pad_mode != NULL && ctx->pad_mode != keyring_default_pad_mode)
            keyring_free(ctx->pad_mode);
        /* Duplicate the string so we own it */
        ctx->pad_mode = keyring_strdup(pad);
        OPENSSL_free(pad);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &ctx->saltlen))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM keyring_sig_gettable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keyring_sig_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx; (void)provctx; /* Static list, no context needed */
    return keyring_sig_gettable_ctx_param_types;
}

static int keyring_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    keyring_sig_ctx_t *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->pad_mode))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->saltlen))
        return 0;

    return 1;
}
