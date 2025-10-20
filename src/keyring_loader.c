/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - Key Loader/Store
 */


#include "keyring_provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <keyutils.h>
#include <openssl/evp.h>

/*
 * Load a key from keyring using URI
 */
void *keyring_load(void *provctx __attribute__((unused)), const char *uri, int expect_type __attribute__((unused)))
{
    keyring_uri_t parsed_uri;
    keyring_key_ctx_t *key_ctx;
    int result;

    if (uri == NULL)
        return NULL;

    /* Parse the URI */
    if (!keyring_uri_parse(uri, &parsed_uri)) {
        keyring_error(0, KEYRING_ERR_INVALID_URI,
                     "Failed to parse keyring URI: %s", uri);
        return NULL;
    }

    /* Create key context */
    key_ctx = keyring_key_new();
    if (key_ctx == NULL) {
        keyring_uri_free(&parsed_uri);
        return NULL;
    }

    /* Load key by ID or description */
    if (parsed_uri.has_id) {
        result = keyring_key_load_by_id(parsed_uri.id, key_ctx);
    } else if (parsed_uri.has_object) {
        result = keyring_key_load_by_description(parsed_uri.object,
                                                 parsed_uri.keyring,
                                                 key_ctx);
    } else {
        keyring_error(0, KEYRING_ERR_INVALID_URI,
                     "URI must specify either id or object");
        keyring_key_free(key_ctx);
        keyring_uri_free(&parsed_uri);
        return NULL;
    }

    if (!result) {
        keyring_error(0, KEYRING_ERR_KEY_NOT_FOUND,
                     "Failed to load key from keyring");
        keyring_key_free(key_ctx);
        keyring_uri_free(&parsed_uri);
        return NULL;
    }

    keyring_uri_free(&parsed_uri);
    return key_ctx;
}

/*
 * Store a key to keyring
 * Used for key generation/import via OSSL_STORE
 */
int keyring_store(void *provctx __attribute__((unused)), const void *keydata, const char *uri)
{
    keyring_uri_t parsed_uri;
    EVP_PKEY *pkey;
    key_serial_t keyring_id;
    key_serial_t new_key_id;
    unsigned char *der = NULL;
    int der_len;
    unsigned char *p;

    if (uri == NULL || keydata == NULL)
        return 0;

    /* Parse the URI to get description and target keyring */
    if (!keyring_uri_parse(uri, &parsed_uri)) {
        keyring_error(0, KEYRING_ERR_INVALID_URI,
                     "Failed to parse keyring URI for store: %s", uri);
        return 0;
    }

    /* Must have object (description) specified */
    if (!parsed_uri.has_object) {
        keyring_error(0, KEYRING_ERR_INVALID_URI,
                     "URI must specify object (key description) for store");
        keyring_uri_free(&parsed_uri);
        return 0;
    }

    /* keydata is an EVP_PKEY from the generating provider */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    pkey = (EVP_PKEY *)keydata;  /* OpenSSL OSSL_STORE API requires const void* */
#pragma GCC diagnostic pop
    if (pkey == NULL) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Invalid key data for store");
        keyring_uri_free(&parsed_uri);
        return 0;
    }

    /* Convert to PKCS#8 PrivateKeyInfo DER format */
    der_len = i2d_PrivateKey(pkey, NULL);
    if (der_len <= 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to get DER encoding length");
        keyring_uri_free(&parsed_uri);
        return 0;
    }

    der = keyring_malloc((size_t)der_len);
    if (der == NULL) {
        keyring_uri_free(&parsed_uri);
        return 0;
    }

    p = der;
    if (i2d_PrivateKey(pkey, (unsigned char **)&p) <= 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to encode key to DER format");
        keyring_free(der);
        keyring_uri_free(&parsed_uri);
        return 0;
    }

    /* Determine target keyring */
    switch (parsed_uri.keyring) {
    case KEYRING_SESSION:
        keyring_id = KEY_SPEC_SESSION_KEYRING;
        break;
    case KEYRING_USER:
        keyring_id = KEY_SPEC_USER_KEYRING;
        break;
    case KEYRING_PERSISTENT:
#ifdef KEY_SPEC_PERSISTENT_KEYRING
        keyring_id = KEY_SPEC_PERSISTENT_KEYRING;
#else
        keyring_id = KEY_SPEC_USER_KEYRING;
#endif
        break;
    case KEYRING_SEARCH_ALL:
    default:
        keyring_id = KEY_SPEC_USER_KEYRING;
        break;
    }

    /* Use add_key() to store in keyring */
    new_key_id = add_key("asymmetric", parsed_uri.object, der, (size_t)der_len, keyring_id);
    if (new_key_id < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to add key to keyring: %d", new_key_id);
        keyring_clear_free(der, (size_t)der_len);
        keyring_uri_free(&parsed_uri);
        return 0;
    }

    /* Success */
    keyring_clear_free(der, (size_t)der_len);
    keyring_uri_free(&parsed_uri);
    return 1;
}

/*
 * Enumerate keys in keyring
 * Calls callback for each key found
 */
int keyring_enumerate(void *provctx __attribute__((unused)), const char *uri,
                     int (*callback)(const char *uri, void *cbarg),
                     void *cbarg)
{
    keyring_uri_t parsed_uri;
    keyring_type_t target_keyring;
    key_serial_t keyring_id;
    long ret;
    void *buffer = NULL;
    size_t buflen = 0;
    int *key_list;
    int num_keys;
    int i;

    /* Parse URI to determine which keyring to enumerate */
    if (uri != NULL && *uri != '\0') {
        if (!keyring_uri_parse(uri, &parsed_uri)) {
            return 0;
        }
        target_keyring = parsed_uri.keyring;
        keyring_uri_free(&parsed_uri);
    } else {
        target_keyring = KEYRING_SEARCH_ALL;
    }

    /* Determine keyring ID */
    switch (target_keyring) {
    case KEYRING_SESSION:
        keyring_id = KEY_SPEC_SESSION_KEYRING;
        break;
    case KEYRING_USER:
        keyring_id = KEY_SPEC_USER_KEYRING;
        break;
    case KEYRING_PERSISTENT:
#ifdef KEY_SPEC_PERSISTENT_KEYRING
        keyring_id = KEY_SPEC_PERSISTENT_KEYRING;
#else
        /* Fallback to user keyring if persistent not available */
        keyring_id = KEY_SPEC_USER_KEYRING;
#endif
        break;
    case KEYRING_SEARCH_ALL:
    default:
        /* Enumerate user keyring by default */
        keyring_id = KEY_SPEC_USER_KEYRING;
        break;
    }

    /* Read keyring to get list of keys */
    ret = keyctl_read(keyring_id, NULL, 0);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to read keyring size: %ld", ret);
        return 0;
    }

    buflen = (size_t)ret;
    buffer = keyring_malloc(buflen);
    if (buffer == NULL)
        return 0;

    ret = keyctl_read(keyring_id, buffer, buflen);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to read keyring: %ld", ret);
        keyring_free(buffer);
        return 0;
    }

    /* Parse key list (array of key_serial_t) */
    key_list = (int *)buffer;
    /* ret is guaranteed positive here (checked above), but verify for safety */
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Unexpected negative return from keyctl_read: %ld", ret);
        keyring_free(buffer);
        return 0;
    }
    if ((size_t)ret % sizeof(key_serial_t) != 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Invalid keyring data size: %ld bytes not multiple of %zu",
                     ret, sizeof(key_serial_t));
        keyring_free(buffer);
        return 0;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    num_keys = (int)(ret / sizeof(key_serial_t));
#pragma GCC diagnostic pop

    /* Iterate through keys and call callback */
    for (i = 0; i < num_keys; i++) {
        key_serial_t key_id = key_list[i];
        char *desc;
        char uri_buf[512];

        /* Get key description */
        desc = keyring_key_get_description(key_id);
        if (desc == NULL)
            continue;

        /* Check if it's an asymmetric key */
        if (strstr(desc, "asymmetric") == NULL) {
            keyring_free(desc);
            continue;
        }

        /* Build URI for this key */
        snprintf(uri_buf, sizeof(uri_buf), "keyring:id=%x", key_id);

        /* Call the callback */
        if (callback != NULL) {
            if (!callback(uri_buf, cbarg)) {
                keyring_free(desc);
                break;
            }
        }

        keyring_free(desc);
    }

    keyring_free(buffer);
    return 1;
}
