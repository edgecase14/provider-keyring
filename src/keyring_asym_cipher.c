/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - RSA Asymmetric Cipher Operations
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "keyring_provider.h"

/* Forward declarations */
static OSSL_FUNC_asym_cipher_newctx_fn keyring_cipher_newctx;
static OSSL_FUNC_asym_cipher_freectx_fn keyring_cipher_freectx;
static OSSL_FUNC_asym_cipher_dupctx_fn keyring_cipher_dupctx;
static OSSL_FUNC_asym_cipher_encrypt_init_fn keyring_cipher_encrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn keyring_cipher_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn keyring_cipher_decrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_fn keyring_cipher_decrypt;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn keyring_cipher_get_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn keyring_cipher_set_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn keyring_cipher_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn keyring_cipher_settable_ctx_params;

/* Dispatch table */
const OSSL_DISPATCH keyring_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))keyring_cipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))keyring_cipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))keyring_cipher_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))keyring_cipher_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))keyring_cipher_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))keyring_cipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))keyring_cipher_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))keyring_cipher_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))keyring_cipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))keyring_cipher_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))keyring_cipher_settable_ctx_params },
    { 0, NULL }
};

/* Create new cipher context */
static void *keyring_cipher_newctx(void *provctx)
{
    keyring_cipher_ctx_t *ctx;

    ctx = keyring_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = (keyring_prov_ctx_t *)provctx;
    ctx->pad_mode = "pkcs1";  /* Default padding */

    return ctx;
}

/* Free cipher context */
static void keyring_cipher_freectx(void *vctx)
{
    keyring_cipher_ctx_t *ctx = vctx;

    if (ctx == NULL)
        return;

    keyring_key_free(ctx->key_ctx);

    if (ctx->oaep_md != NULL)
        EVP_MD_free(ctx->oaep_md);
    if (ctx->mgf1_md != NULL)
        EVP_MD_free(ctx->mgf1_md);

    keyring_free(ctx->oaep_label);
    keyring_free(ctx);
}

/* Duplicate cipher context */
static void *keyring_cipher_dupctx(void *vctx)
{
    keyring_cipher_ctx_t *src = vctx;
    keyring_cipher_ctx_t *dst;

    if (src == NULL)
        return NULL;

    dst = keyring_cipher_newctx(src->provctx);
    if (dst == NULL)
        return NULL;

    if (src->key_ctx != NULL) {
        dst->key_ctx = src->key_ctx;
        keyring_key_up_ref(dst->key_ctx);
    }

    dst->pad_mode = src->pad_mode;

    if (src->oaep_md != NULL) {
        dst->oaep_md = src->oaep_md;
        EVP_MD_up_ref(dst->oaep_md);
    }

    if (src->mgf1_md != NULL) {
        dst->mgf1_md = src->mgf1_md;
        EVP_MD_up_ref(dst->mgf1_md);
    }

    if (src->oaep_label != NULL && src->oaep_label_len > 0) {
        dst->oaep_label = keyring_malloc(src->oaep_label_len);
        if (dst->oaep_label != NULL) {
            memcpy(dst->oaep_label, src->oaep_label, src->oaep_label_len);
            dst->oaep_label_len = src->oaep_label_len;
        }
    }

    return dst;
}

/* Initialize encryption operation */
static int keyring_cipher_encrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    keyring_cipher_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ctx->key_ctx = key;
    keyring_key_up_ref(key);

    return keyring_cipher_set_ctx_params(ctx, params);
}

/* Perform encryption */
static int keyring_cipher_encrypt(void *vctx, unsigned char *out, size_t *outlen,
                                  size_t outsize, const unsigned char *in, size_t inlen)
{
    keyring_cipher_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key;
    EVP_PKEY_CTX *pkey_ctx;
    int ret;

    if (ctx == NULL || ctx->key_ctx == NULL)
        return 0;

    key = ctx->key_ctx;

    /* Encryption uses public key via OpenSSL */
    if (key->evp_pkey == NULL) {
        /* Create EVP_PKEY from public key data */
        const unsigned char *p = key->public_key;
        key->evp_pkey = d2i_PUBKEY(NULL, &p, key->public_key_len);
        if (key->evp_pkey == NULL)
            return 0;
    }

    pkey_ctx = EVP_PKEY_CTX_new(key->evp_pkey, NULL);
    if (pkey_ctx == NULL)
        return 0;

    if (EVP_PKEY_encrypt_init(pkey_ctx) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return 0;
    }

    /* Set padding mode */
    if (strcmp(ctx->pad_mode, "oaep") == 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            return 0;
        }

        /* Set OAEP digest */
        if (ctx->oaep_md != NULL) {
            if (EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, ctx->oaep_md) <= 0) {
                EVP_PKEY_CTX_free(pkey_ctx);
                return 0;
            }
        }

        /* Set MGF1 digest */
        if (ctx->mgf1_md != NULL) {
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, ctx->mgf1_md) <= 0) {
                EVP_PKEY_CTX_free(pkey_ctx);
                return 0;
            }
        }

        /* Set OAEP label */
        if (ctx->oaep_label != NULL && ctx->oaep_label_len > 0) {
            /* EVP_PKEY_CTX takes ownership of the label */
            unsigned char *label_copy = OPENSSL_memdup(ctx->oaep_label, ctx->oaep_label_len);
            if (label_copy == NULL) {
                EVP_PKEY_CTX_free(pkey_ctx);
                return 0;
            }
            if (EVP_PKEY_CTX_set0_rsa_oaep_label(pkey_ctx, label_copy, ctx->oaep_label_len) <= 0) {
                OPENSSL_free(label_copy);
                EVP_PKEY_CTX_free(pkey_ctx);
                return 0;
            }
        }
    } else {
        /* PKCS#1 v1.5 padding (default) */
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
            EVP_PKEY_CTX_free(pkey_ctx);
            return 0;
        }
    }

    ret = EVP_PKEY_encrypt(pkey_ctx, out, outlen, in, inlen);
    EVP_PKEY_CTX_free(pkey_ctx);

    return ret > 0;
}

/* Initialize decryption operation */
static int keyring_cipher_decrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    keyring_cipher_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key = vkey;

    if (ctx == NULL || key == NULL)
        return 0;

    ctx->key_ctx = key;
    keyring_key_up_ref(key);

    return keyring_cipher_set_ctx_params(ctx, params);
}

/* Perform decryption */
static int keyring_cipher_decrypt(void *vctx, unsigned char *out, size_t *outlen,
                                  size_t outsize, const unsigned char *in, size_t inlen)
{
    keyring_cipher_ctx_t *ctx = vctx;
    keyring_key_ctx_t *key;

    if (ctx == NULL || ctx->key_ctx == NULL)
        return 0;

    key = ctx->key_ctx;

    /* Use kernel keyring API - works for both software and TPM-backed keys */
    return keyring_pkey_decrypt(key->key_serial, in, inlen, out, outlen,
                               ctx->pad_mode);
}

/* Parameter handling */
static const OSSL_PARAM keyring_cipher_settable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keyring_cipher_settable_ctx_params(void *vctx, void *provctx)
{
    return keyring_cipher_settable_ctx_param_types;
}

static int keyring_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    keyring_cipher_ctx_t *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        char *pad = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &pad, 0))
            return 0;
        ctx->pad_mode = pad;  /* TODO: Should strdup this */
        OPENSSL_free(pad);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL) {
        char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0))
            return 0;

        if (ctx->oaep_md != NULL)
            EVP_MD_free(ctx->oaep_md);
        if (ctx->provctx != NULL)
            ctx->oaep_md = EVP_MD_fetch(ctx->provctx->libctx, mdname, NULL);
        OPENSSL_free(mdname);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0))
            return 0;

        if (ctx->mgf1_md != NULL)
            EVP_MD_free(ctx->mgf1_md);
        if (ctx->provctx != NULL)
            ctx->mgf1_md = EVP_MD_fetch(ctx->provctx->libctx, mdname, NULL);
        OPENSSL_free(mdname);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
    if (p != NULL) {
        void *label = NULL;
        size_t label_len = 0;

        if (!OSSL_PARAM_get_octet_string(p, &label, 0, &label_len))
            return 0;

        keyring_free(ctx->oaep_label);
        ctx->oaep_label = label;
        ctx->oaep_label_len = label_len;
    }

    return 1;
}

static const OSSL_PARAM keyring_cipher_gettable_ctx_param_types[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keyring_cipher_gettable_ctx_params(void *vctx, void *provctx)
{
    return keyring_cipher_gettable_ctx_param_types;
}

static int keyring_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    keyring_cipher_ctx_t *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->pad_mode))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
    if (p != NULL && ctx->oaep_md != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(ctx->oaep_md)))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
    if (p != NULL && ctx->mgf1_md != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(ctx->mgf1_md)))
            return 0;
    }

    return 1;
}
