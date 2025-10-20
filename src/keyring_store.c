/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - STORE Loader
 *
 * Implements OSSL_STORE interface for loading keys from keyring: URIs
 */

#include "keyring_provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/store.h>

/* Store context */
typedef struct {
    keyring_prov_ctx_t *provctx;
    char *uri;
    keyring_uri_t parsed_uri;
    keyring_key_ctx_t *key;
    int loaded;  /* Whether we've loaded the key yet */
    int eof;     /* End of file flag */
} keyring_store_ctx_t;

/* Forward declarations */
static OSSL_FUNC_store_open_fn keyring_store_open;
static OSSL_FUNC_store_attach_fn keyring_store_attach;
static OSSL_FUNC_store_settable_ctx_params_fn keyring_store_settable_ctx_params;
static OSSL_FUNC_store_set_ctx_params_fn keyring_store_set_ctx_params;
static OSSL_FUNC_store_load_fn keyring_store_load;
static OSSL_FUNC_store_eof_fn keyring_store_eof;
static OSSL_FUNC_store_close_fn keyring_store_close;

/* Dispatch table */
const OSSL_DISPATCH keyring_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))keyring_store_open },
    { OSSL_FUNC_STORE_ATTACH, (void (*)(void))keyring_store_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))keyring_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))keyring_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))keyring_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))keyring_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))keyring_store_close },
    { 0, NULL }
};

/* Open keyring store */
static void *keyring_store_open(void *provctx, const char *uri)
{
    keyring_store_ctx_t *ctx;
    keyring_prov_ctx_t *pctx = provctx;

    fprintf(stderr, "DEBUG: keyring_store_open called with URI: %s\n", uri ? uri : "(null)");

    if (uri == NULL || strncmp(uri, "keyring:", 8) != 0) {
        fprintf(stderr, "DEBUG: URI not recognized as keyring URI\n");
        return NULL;
    }

    ctx = keyring_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = pctx;
    ctx->uri = keyring_strdup(uri);
    if (ctx->uri == NULL) {
        keyring_free(ctx);
        return NULL;
    }

    /* Parse URI */
    if (!keyring_uri_parse(uri, &ctx->parsed_uri)) {
        fprintf(stderr, "DEBUG: Failed to parse URI\n");
        keyring_free(ctx->uri);
        keyring_free(ctx);
        return NULL;
    }

    fprintf(stderr, "DEBUG: STORE opened successfully\n");
    ctx->loaded = 0;
    ctx->eof = 0;

    return ctx;
}

/* Attach to existing BIO - not supported */
static void *keyring_store_attach(void *provctx, OSSL_CORE_BIO *bio)
{
    return NULL;
}

/* Settable context parameters */
static const OSSL_PARAM *keyring_store_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END
    };
    return params;
}

/* Set context parameters */
static int keyring_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    return 1;
}

/* Load key from keyring */
static int keyring_store_load(void *loaderctx, OSSL_CALLBACK *object_cb,
                              void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb,
                              void *pw_cbarg)
{
    keyring_store_ctx_t *ctx = loaderctx;
    keyring_key_ctx_t *key = NULL;
    key_serial_t key_serial = -1;
    OSSL_PARAM params[6];
    int object_type;
    const char *data_type = "RSA";
    const char *desc = "Keyring key";
    const char *properties = "provider=keyring";
    int param_idx = 0;

    fprintf(stderr, "DEBUG: keyring_store_load called\n");

    if (ctx == NULL || ctx->loaded || ctx->eof) {
        fprintf(stderr, "DEBUG: Invalid context or already loaded\n");
        return 0;
    }

    /* Allocate key context */
    key = keyring_key_new();
    if (key == NULL) {
        fprintf(stderr, "DEBUG: Failed to allocate key context\n");
        goto err;
    }

    /* Load key based on URI attributes */
    if (ctx->parsed_uri.has_id) {
        /* Load by serial ID */
        key_serial = ctx->parsed_uri.id;
        fprintf(stderr, "DEBUG: Loading key by ID: %d (0x%x)\n", key_serial, key_serial);
        if (!keyring_key_load_by_id(key_serial, key)) {
            fprintf(stderr, "DEBUG: Failed to load key by ID\n");
            goto err;
        }
    } else if (ctx->parsed_uri.has_object) {
        /* Load by description */
        fprintf(stderr, "DEBUG: Loading key by description: %s\n", ctx->parsed_uri.object);
        if (!keyring_key_load_by_description(ctx->parsed_uri.object,
                                              ctx->parsed_uri.keyring, key)) {
            fprintf(stderr, "DEBUG: Failed to load key by description\n");
            goto err;
        }
    } else {
        /* No identifier specified */
        fprintf(stderr, "DEBUG: No ID or object specified\n");
        goto err;
    }

    fprintf(stderr, "DEBUG: Key loaded successfully, serial=%d\n", key->key_serial);

    /* Store key in ctx FIRST - we need a stable address, not a stack variable */
    ctx->key = key;

    /* Determine object type based on key type */
    switch (ctx->parsed_uri.type) {
    case KEYRING_KEY_TYPE_PRIVATE:
        object_type = OSSL_OBJECT_PKEY;
        break;
    case KEYRING_KEY_TYPE_PUBLIC:
        object_type = OSSL_OBJECT_PKEY;  /* Public keys are also PKEY */
        break;
    case KEYRING_KEY_TYPE_CERT:
        object_type = OSSL_OBJECT_CERT;
        break;
    case KEYRING_KEY_TYPE_UNKNOWN:
    default:
        object_type = OSSL_OBJECT_PKEY;  /* Default to private key */
        break;
    }

    /* Build parameter array for object callback */
    params[param_idx++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[param_idx++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                           (char *)data_type, 0);
    params[param_idx++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DESC,
                                                           (char *)desc, 0);

    /* Pass address of ctx->key (stable memory, not stack) */
    fprintf(stderr, "DEBUG: Passing stable key reference: &ctx->key=%p, ctx->key=%p, serial=%d\n",
            (void *)&ctx->key, (void *)ctx->key, ctx->key->key_serial);
    params[param_idx++] = OSSL_PARAM_construct_octet_ptr(OSSL_OBJECT_PARAM_REFERENCE,
                                                         (void **)&ctx->key, 0);
    params[param_idx++] = OSSL_PARAM_construct_end();

    fprintf(stderr, "DEBUG: Calling object callback with object_type=%d, param_count=%d\n",
            object_type, param_idx);

    /* Call the object callback */
    if (!object_cb(params, object_cbarg)) {
        fprintf(stderr, "DEBUG: Object callback returned failure\n");
        goto err;
    }

    fprintf(stderr, "DEBUG: Object callback succeeded\n");

    /* Mark as loaded and EOF */
    ctx->loaded = 1;
    ctx->eof = 1;
    /* ctx->key already set earlier before callback */

    fprintf(stderr, "DEBUG: keyring_store_load returning success\n");
    return 1;

err:
    if (key != NULL) {
        keyring_key_free(key);
        ctx->key = NULL;  /* Clear pointer since we freed it */
    }
    ctx->eof = 1;
    return 0;
}

/* Check if EOF */
static int keyring_store_eof(void *loaderctx)
{
    keyring_store_ctx_t *ctx = loaderctx;
    return ctx == NULL || ctx->eof;
}

/* Close store */
static int keyring_store_close(void *loaderctx)
{
    keyring_store_ctx_t *ctx = loaderctx;

    if (ctx == NULL)
        return 1;

    keyring_uri_free(&ctx->parsed_uri);
    keyring_free(ctx->uri);

    /* Note: ctx->key is managed by the key management layer, don't free here */

    keyring_free(ctx);
    return 1;
}
