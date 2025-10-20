/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - RSA Key Management
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "keyring_provider.h"

/* Forward declarations */
static OSSL_FUNC_keymgmt_new_fn keyring_rsa_new;
static OSSL_FUNC_keymgmt_free_fn keyring_rsa_free;
static OSSL_FUNC_keymgmt_has_fn keyring_rsa_has;
static OSSL_FUNC_keymgmt_match_fn keyring_rsa_match;
static OSSL_FUNC_keymgmt_import_fn keyring_rsa_import;
static OSSL_FUNC_keymgmt_import_types_fn keyring_rsa_import_types;
static OSSL_FUNC_keymgmt_export_fn keyring_rsa_export;
static OSSL_FUNC_keymgmt_export_types_fn keyring_rsa_export_types;
static OSSL_FUNC_keymgmt_get_params_fn keyring_rsa_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn keyring_rsa_gettable_params;
static OSSL_FUNC_keymgmt_query_operation_name_fn keyring_rsa_query_operation_name;

/* Dispatch table */
const OSSL_DISPATCH keyring_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keyring_rsa_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keyring_rsa_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keyring_rsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keyring_rsa_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))keyring_rsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))keyring_rsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))keyring_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))keyring_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))keyring_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))keyring_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))keyring_rsa_query_operation_name },
    { 0, NULL }
};

/* Create new key context */
keyring_key_ctx_t *keyring_key_new(void)
{
    keyring_key_ctx_t *ctx;

    ctx = keyring_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->refcount = 1;
    ctx->key_serial = -1;

    return ctx;
}

/* Free key context */
void keyring_key_free(keyring_key_ctx_t *ctx)
{
    if (ctx == NULL)
        return;

    if (--ctx->refcount > 0)
        return;

    keyring_free(ctx->description);
    keyring_free(ctx->public_key);

    if (ctx->evp_pkey != NULL)
        EVP_PKEY_free(ctx->evp_pkey);

    keyring_free(ctx);
}

/* Increment reference count */
int keyring_key_up_ref(keyring_key_ctx_t *ctx)
{
    if (ctx == NULL)
        return 0;

    ctx->refcount++;
    return 1;
}

/* Load key by serial ID */
int keyring_key_load_by_id(key_serial_t id, keyring_key_ctx_t *ctx)
{
    unsigned char *pubkey_data = NULL;
    size_t pubkey_len = 0;
    char *desc = NULL;

    if (ctx == NULL || id < 0)
        return 0;

    /* Get key description */
    desc = keyring_key_get_description(id);
    if (desc == NULL)
        return 0;

    /* Get public key data */
    if (!keyring_key_get_public(id, &pubkey_data, &pubkey_len)) {
        keyring_free(desc);
        return 0;
    }

    /* Store in context */
    ctx->key_serial = id;
    ctx->description = desc;
    ctx->public_key = pubkey_data;
    ctx->public_key_len = pubkey_len;

    /* Parse public key to get key size and cache EVP_PKEY for public operations */
    const unsigned char *p = pubkey_data;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, pubkey_len);
    if (pkey != NULL) {
        ctx->key_size = EVP_PKEY_bits(pkey);
        /* Cache EVP_PKEY for public key operations (verify, encrypt) */
        ctx->evp_pkey = pkey;
    }

    return 1;
}

/* Load key by description */
int keyring_key_load_by_description(const char *desc, keyring_type_t keyring_type,
                                    keyring_key_ctx_t *ctx)
{
    key_serial_t key_serial;

    if (desc == NULL || ctx == NULL)
        return 0;

    key_serial = keyring_search_key(desc, keyring_type);
    if (key_serial < 0)
        return 0;

    return keyring_key_load_by_id(key_serial, ctx);
}

/* Keymgmt functions */

static void *keyring_rsa_new(void *provctx __attribute__((unused)))
{
    return keyring_key_new();
}

static void keyring_rsa_free(void *keydata)
{
    keyring_key_free((keyring_key_ctx_t *)keydata);
}

static int keyring_rsa_has(const void *keydata, int selection)
{
    const keyring_key_ctx_t *ctx = keydata;

    if (ctx == NULL || ctx->key_serial < 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        return ctx->public_key != NULL;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* We have a private key reference in the keyring */
        return 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* RSA doesn't have domain parameters */
        return 0;
    }

    return 0;
}

static int keyring_rsa_match(const void *keydata1, const void *keydata2,
                            int selection __attribute__((unused)))
{
    const keyring_key_ctx_t *ctx1 = keydata1;
    const keyring_key_ctx_t *ctx2 = keydata2;

    if (ctx1 == NULL || ctx2 == NULL)
        return 0;

    /* Match by keyring serial ID */
    if (ctx1->key_serial == ctx2->key_serial && ctx1->key_serial >= 0)
        return 1;

    /* Match by public key data */
    if (ctx1->public_key != NULL && ctx2->public_key != NULL &&
        ctx1->public_key_len == ctx2->public_key_len &&
        memcmp(ctx1->public_key, ctx2->public_key, ctx1->public_key_len) == 0)
        return 1;

    return 0;
}

static const OSSL_PARAM *keyring_rsa_import_types(int selection __attribute__((unused)))
{
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_octet_string("data", NULL, 0),  /* Generic data param */
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

static int keyring_rsa_import(void *keydata, int selection __attribute__((unused)),
                             const OSSL_PARAM params[])
{
    keyring_key_ctx_t *ctx = keydata;

    if (ctx == NULL || params == NULL)
        return 0;

    /* TODO: Import from parameters for key creation */
    /* For now, keys are loaded via the loader interface */
    return 0;
}

static const OSSL_PARAM *keyring_rsa_export_types(int selection __attribute__((unused)))
{
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    return export_types;
}

static int keyring_rsa_export(void *keydata, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg)
{
    keyring_key_ctx_t *ctx = keydata;
    OSSL_PARAM params[6];
    BIGNUM *n = NULL, *e = NULL;
    int i = 0;
    int ret = 0;

    if (ctx == NULL || ctx->evp_pkey == NULL)
        return 0;

    /* Export public key parameters using OpenSSL 3.0 API */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* Get RSA modulus (n) and exponent (e) using EVP API */
        if (EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_N, &n) &&
            EVP_PKEY_get_bn_param(ctx->evp_pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {

            if (n != NULL)
                params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                                      (unsigned char *)n, BN_num_bytes(n));
            if (e != NULL)
                params[i++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                                      (unsigned char *)e, BN_num_bytes(e));
        }
    }

    /* Export key size info */
    params[i++] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &ctx->key_size);
    params[i++] = OSSL_PARAM_construct_end();

    ret = param_cb(params, cbarg);

    /* Clean up BIGNUMs */
    BN_free(n);
    BN_free(e);

    return ret;
}

static const OSSL_PARAM keyring_rsa_gettable_param_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keyring_rsa_gettable_params(void *provctx __attribute__((unused)))
{
    return keyring_rsa_gettable_param_types;
}

static int keyring_rsa_get_params(void *keydata, OSSL_PARAM params[])
{
    keyring_key_ctx_t *ctx = keydata;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->key_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int security_bits = ctx->key_size >= 15360 ? 256 :
                           ctx->key_size >= 7680 ? 192 :
                           ctx->key_size >= 3072 ? 128 :
                           ctx->key_size >= 2048 ? 112 :
                           ctx->key_size >= 1024 ? 80 : 0;
        if (!OSSL_PARAM_set_int(p, security_bits))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        int max_size = (ctx->key_size + 7) / 8;
        if (!OSSL_PARAM_set_int(p, max_size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SHA256"))
        return 0;

    return 1;
}

static const char *keyring_rsa_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return "RSA";
    case OSSL_OP_ASYM_CIPHER:
        return "RSA";
    }
    return NULL;
}
