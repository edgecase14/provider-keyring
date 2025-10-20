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
static OSSL_FUNC_keymgmt_load_fn keyring_rsa_load;
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
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))keyring_rsa_load },
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
    unsigned int key_size_bits = 0;

    if (ctx == NULL || id < 0)
        return 0;

    /* Get key description */
    desc = keyring_key_get_description(id);
    if (desc == NULL)
        return 0;

    /* Try to get public key data (works for "user" type keys) */
    if (keyring_key_get_public(id, &pubkey_data, &pubkey_len)) {
        /* Successfully read public key - parse it */
        const unsigned char *p = pubkey_data;
        EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, pubkey_len);
        if (pkey != NULL) {
            ctx->key_size = EVP_PKEY_bits(pkey);
            /* Cache EVP_PKEY for public key operations (verify, encrypt) */
            ctx->evp_pkey = pkey;
        }

        ctx->public_key = pubkey_data;
        ctx->public_key_len = pubkey_len;
    } else {
        /* Reading failed - this is an asymmetric key (X.509 cert, TPM key)
         * Use keyctl_pkey_query to get key information */
        if (!keyring_key_query(id, &key_size_bits, NULL)) {
            keyring_free(desc);
            return 0;
        }

        ctx->key_size = (int)key_size_bits;
        ctx->public_key = NULL;
        ctx->public_key_len = 0;
        ctx->evp_pkey = NULL;

        /* For asymmetric keys without public key data, verification will need
         * to use an external public key or extract from the cert file */
    }

    /* Store in context */
    ctx->key_serial = id;
    ctx->description = desc;

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
    void *ctx = keyring_key_new();
    fprintf(stderr, "DEBUG: keyring_rsa_new called, returning %p\n", ctx);
    return ctx;
}

static void keyring_rsa_free(void *keydata)
{
    keyring_key_free((keyring_key_ctx_t *)keydata);
}

static int keyring_rsa_has(const void *keydata, int selection)
{
    const keyring_key_ctx_t *ctx = keydata;
    int result;

    fprintf(stderr, "DEBUG: keyring_rsa_has called, ctx=%p, selection=0x%x\n", keydata, selection);

    if (ctx == NULL || ctx->key_serial < 0) {
        fprintf(stderr, "DEBUG: keyring_rsa_has returning 0 (ctx=%p, serial=%d)\n",
                ctx, ctx ? ctx->key_serial : -999);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        result = ctx->public_key != NULL;
        fprintf(stderr, "DEBUG: keyring_rsa_has PUBLIC_KEY check, returning %d\n", result);
        return result;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* We have a private key reference in the keyring */
        fprintf(stderr, "DEBUG: keyring_rsa_has PRIVATE_KEY check, returning 1\n");
        return 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* RSA doesn't have domain parameters */
        fprintf(stderr, "DEBUG: keyring_rsa_has DOMAIN_PARAMETERS check, returning 0\n");
        return 0;
    }

    fprintf(stderr, "DEBUG: keyring_rsa_has no match, returning 0\n");
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
        OSSL_PARAM_octet_ptr(OSSL_OBJECT_PARAM_REFERENCE, NULL, 0),  /* Key reference */
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
    const OSSL_PARAM *p;

    fprintf(stderr, "DEBUG: keyring_rsa_import called, selection=0x%x\n", selection);

    if (ctx == NULL || params == NULL) {
        fprintf(stderr, "DEBUG: import failed - ctx=%p params=%p\n", ctx, params);
        return 0;
    }

    /* Check if this is a reference to an already-loaded key */
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    fprintf(stderr, "DEBUG: REFERENCE param lookup: p=%p\n", p);

    if (p != NULL) {
        fprintf(stderr, "DEBUG: REFERENCE found, data_type=%u (OCTET_PTR=%u)\n",
                p->data_type, OSSL_PARAM_OCTET_PTR);
    }

    if (p != NULL && p->data_type == OSSL_PARAM_OCTET_PTR) {
        /* This is a reference from STORE loader - just copy the key context */
        keyring_key_ctx_t *src_key = NULL;
        void **ptr = (void **)p->data;

        fprintf(stderr, "DEBUG: ptr=%p, *ptr=%p\n", ptr, ptr ? *ptr : NULL);

        if (ptr && *ptr) {
            src_key = (keyring_key_ctx_t *)*ptr;
            fprintf(stderr, "DEBUG: src_key=%p, serial=%d\n", src_key, src_key->key_serial);

            /* Copy key information */
            ctx->key_serial = src_key->key_serial;
            ctx->key_size = src_key->key_size;

            if (src_key->description) {
                ctx->description = keyring_strdup(src_key->description);
            }

            if (src_key->public_key && src_key->public_key_len > 0) {
                ctx->public_key = keyring_malloc(src_key->public_key_len);
                if (ctx->public_key) {
                    memcpy(ctx->public_key, src_key->public_key, src_key->public_key_len);
                    ctx->public_key_len = src_key->public_key_len;
                }
            }

            if (src_key->evp_pkey) {
                ctx->evp_pkey = src_key->evp_pkey;
                EVP_PKEY_up_ref(ctx->evp_pkey);
            }

            fprintf(stderr, "DEBUG: import SUCCESS - returning 1\n");
            return 1;
        }
    }

    /* Check for generic "data" parameter containing our key context */
    p = OSSL_PARAM_locate_const(params, "data");
    fprintf(stderr, "DEBUG: data param lookup: p=%p\n", p);

    if (p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING) {
        fprintf(stderr, "DEBUG: data param found, size=%zu (expected %zu)\n",
                p->data_size, sizeof(keyring_key_ctx_t));

        if (p->data_size == sizeof(keyring_key_ctx_t)) {
            /* Copy the key context structure */
            keyring_key_ctx_t *src_key = (keyring_key_ctx_t *)p->data;

            ctx->key_serial = src_key->key_serial;
            ctx->key_size = src_key->key_size;

            if (src_key->description) {
                ctx->description = keyring_strdup(src_key->description);
            }

            if (src_key->public_key && src_key->public_key_len > 0) {
                ctx->public_key = keyring_malloc(src_key->public_key_len);
                if (ctx->public_key) {
                    memcpy(ctx->public_key, src_key->public_key, src_key->public_key_len);
                    ctx->public_key_len = src_key->public_key_len;
                }
            }

            if (src_key->evp_pkey) {
                ctx->evp_pkey = src_key->evp_pkey;
                EVP_PKEY_up_ref(ctx->evp_pkey);
            }

            fprintf(stderr, "DEBUG: import SUCCESS via data param - returning 1\n");
            return 1;
        }
    }

    /* Standard RSA parameter import not implemented */
    fprintf(stderr, "DEBUG: import FAILED - no valid params found, returning 0\n");
    return 0;
}

/* Load a key from a reference */
static void *keyring_rsa_load(const void *reference, size_t reference_sz)
{
    keyring_key_ctx_t *new_ctx = NULL;
    keyring_key_ctx_t *src_key = NULL;

    fprintf(stderr, "DEBUG: keyring_rsa_load called, reference=%p, size=%zu\n",
            reference, reference_sz);

    if (reference == NULL) {
        fprintf(stderr, "DEBUG: load failed - reference is NULL\n");
        return NULL;
    }

    /* The reference IS the pointer to our key context */
    src_key = (keyring_key_ctx_t *)reference;

    fprintf(stderr, "DEBUG: load using src_key=%p\n", (void *)src_key);

    if (src_key->key_serial < 0) {
        fprintf(stderr, "DEBUG: load failed - invalid source key, serial=%d\n", src_key->key_serial);
        return NULL;
    }

    fprintf(stderr, "DEBUG: load found source key: serial=%d\n", src_key->key_serial);

    /* Create new key context */
    new_ctx = keyring_key_new();
    if (new_ctx == NULL) {
        fprintf(stderr, "DEBUG: load failed - couldn't allocate new context\n");
        return NULL;
    }

    /* Copy key information from source */
    new_ctx->key_serial = src_key->key_serial;
    new_ctx->key_size = src_key->key_size;

    if (src_key->description) {
        new_ctx->description = keyring_strdup(src_key->description);
    }

    if (src_key->public_key && src_key->public_key_len > 0) {
        new_ctx->public_key = keyring_malloc(src_key->public_key_len);
        if (new_ctx->public_key) {
            memcpy(new_ctx->public_key, src_key->public_key, src_key->public_key_len);
            new_ctx->public_key_len = src_key->public_key_len;
        }
    }

    if (src_key->evp_pkey) {
        new_ctx->evp_pkey = src_key->evp_pkey;
        EVP_PKEY_up_ref(new_ctx->evp_pkey);
    }

    fprintf(stderr, "DEBUG: load SUCCESS - returning %p with serial=%d\n",
            (void *)new_ctx, new_ctx->key_serial);

    return new_ctx;
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
