/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - Main Entry Point
 */


#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "keyring_provider.h"

/* Provider context */
static keyring_prov_ctx_t *provider_ctx = NULL;

/* Provider initialization */
static OSSL_FUNC_provider_gettable_params_fn keyring_gettable_params;
static OSSL_FUNC_provider_teardown_fn keyring_teardown;

/* Algorithm dispatch tables */
static const OSSL_ALGORITHM keyring_keymgmt[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=keyring",
      keyring_rsa_keymgmt_functions, "Keyring RSA Key Management" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM keyring_signature[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=keyring",
      keyring_rsa_signature_functions, "Keyring RSA Signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM keyring_asym_cipher[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=keyring",
      keyring_rsa_asym_cipher_functions, "Keyring RSA Asymmetric Cipher" },
    { NULL, NULL, NULL, NULL }
};

/* Store dispatch table */
static const OSSL_ALGORITHM keyring_store_alg[] = {
    { "keyring", "provider=keyring", keyring_store_functions,
      "Keyring Store" },
    { NULL, NULL, NULL, NULL }
};

/* Gettable parameters */
static const OSSL_PARAM keyring_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keyring_gettable_params(void *provctx __attribute__((unused)))
{
    return keyring_param_types;
}

int keyring_get_params(void *provctx __attribute__((unused)), OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Keyring Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYRING_PROVIDER_VERSION_STR))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Keyring Provider Build"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))  /* 1 = running */
        return 0;

    return 1;
}

const OSSL_ALGORITHM *keyring_query_operation(void *provctx __attribute__((unused)), int operation_id,
                                               int *no_cache)
{
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return keyring_keymgmt;
    case OSSL_OP_SIGNATURE:
        return keyring_signature;
    case OSSL_OP_ASYM_CIPHER:
        return keyring_asym_cipher;
    case OSSL_OP_STORE:
        return keyring_store_alg;
    }

    return NULL;
}

/* Error reason strings */
static const OSSL_ITEM reason_strings[] = {
    {KEYRING_ERR_INVALID_URI, "Invalid keyring URI"},
    {KEYRING_ERR_KEY_NOT_FOUND, "Key not found in keyring"},
    {KEYRING_ERR_PERMISSION, "Permission denied"},
    {KEYRING_ERR_TPM_INIT, "TPM initialization failed"},
    {KEYRING_ERR_OPERATION, "Keyring operation failed"},
    {0, NULL}
};

const OSSL_ITEM *keyring_get_reason_strings(void *provctx __attribute__((unused)))
{
    return reason_strings;
}

static void keyring_teardown(void *provctx)
{
    keyring_prov_ctx_t *ctx = (keyring_prov_ctx_t *)provctx;

    if (ctx == NULL)
        return;

    keyring_pkey_cleanup(ctx);
    keyring_free(ctx);
    provider_ctx = NULL;
}

/* Provider entry point */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    static const OSSL_DISPATCH dispatch_table[] = {
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))keyring_gettable_params },
        { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))keyring_get_params },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))keyring_query_operation },
        { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))keyring_get_reason_strings },
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))keyring_teardown },
        { 0, NULL }
    };

    keyring_prov_ctx_t *ctx;
    OSSL_LIB_CTX *libctx = NULL;

    /* Allocate provider context */
    ctx = keyring_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->core_handle = handle;

    /* Get library context from core */
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            {
                OSSL_FUNC_core_get_libctx_fn *get_libctx =
                    OSSL_FUNC_core_get_libctx(in);
                libctx = (OSSL_LIB_CTX *)get_libctx(handle);
            }
            break;
        default:
            /* Ignore other functions */
            break;
        }
    }

    ctx->libctx = libctx;

    /* Initialize kernel keyring crypto support */
    if (keyring_pkey_init(ctx) == 0) {
        /* Keyring crypto not available, but continue anyway */
        ctx->tpm_available = 0;
    } else {
        ctx->tpm_available = 1;
    }

    *provctx = ctx;
    *out = dispatch_table;
    provider_ctx = ctx;

    return 1;
}
