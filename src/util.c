/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - Utility Functions
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <keyutils.h>
#include <openssl/crypto.h>
#include "keyring_provider.h"

/* Shared constants */
const char *const keyring_default_pad_mode = "pkcs1";

/* Memory allocation wrappers using OpenSSL memory functions */
void *keyring_malloc(size_t size)
{
    void *ptr = OPENSSL_malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "keyring: OPENSSL_malloc(%zu) failed\n", size);
    }
    return ptr;
}

void *keyring_zalloc(size_t size)
{
    void *ptr = OPENSSL_zalloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "keyring: OPENSSL_zalloc(%zu) failed\n", size);
    }
    return ptr;
}

void *keyring_realloc(void *ptr, size_t size)
{
    void *new_ptr = OPENSSL_realloc(ptr, size);
    if (new_ptr == NULL && size > 0) {
        fprintf(stderr, "keyring: OPENSSL_realloc(%zu) failed\n", size);
    }
    return new_ptr;
}

void keyring_free(void *ptr)
{
    if (ptr != NULL)
        OPENSSL_free(ptr);
}

void keyring_clear_free(void *ptr, size_t len)
{
    if (ptr != NULL)
        OPENSSL_clear_free(ptr, len);
}

char *keyring_strdup(const char *s)
{
    char *dup;

    if (s == NULL)
        return NULL;

    dup = OPENSSL_strdup(s);
    if (dup == NULL) {
        fprintf(stderr, "keyring: OPENSSL_strdup() failed\n");
    }

    return dup;
}

/* Error handling */
void keyring_error(int lib __attribute__((unused)), int reason __attribute__((unused)), const char *fmt, ...)
{
    va_list args;
    char buf[256];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    fprintf(stderr, "keyring error: %s\n", buf);

    /* TODO: Push to OpenSSL error stack when we have access to OSSL_FUNC_ERR_* */
}

/* Info logging */
void keyring_info(const char *fmt, ...)
{
    va_list args;
    char buf[256];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    fprintf(stderr, "keyring info: %s\n", buf);
}

/* Read public key from kernel keyring */
int keyring_key_get_public(key_serial_t key_serial, unsigned char **data,
                           size_t *len)
{
    long ret;
    void *buffer = NULL;
    size_t buflen = 0;

    /* Try to read the key data (works for "user" type keys, not "asymmetric") */
    ret = keyctl_read(key_serial, NULL, 0);
    if (ret < 0) {
        /* Reading failed - likely an asymmetric key
         * For asymmetric keys (X.509 certs, TPM keys), the kernel doesn't
         * allow reading the raw key data. We'll need to extract the public
         * key from the certificate using a different method.
         * Return failure here and let the caller handle it.
         */
        *data = NULL;
        *len = 0;
        return 0;  /* Not an error - just means key is asymmetric type */
    }

    buflen = (size_t)ret;
    buffer = keyring_malloc(buflen);
    if (buffer == NULL)
        return 0;

    /* Second call to read the actual data */
    ret = keyctl_read(key_serial, buffer, buflen);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to read key data for serial %d: %ld",
                     key_serial, ret);
        keyring_free(buffer);
        return 0;
    }

    *data = buffer;
    *len = (size_t)ret;
    return 1;
}

/* Query asymmetric key information using kernel pkey API */
int keyring_key_query(key_serial_t key_serial, unsigned int *key_size,
                      unsigned int *supported_ops)
{
    struct keyctl_pkey_query result;
    long ret;

    memset(&result, 0, sizeof(result));

    ret = keyctl_pkey_query(key_serial, "", &result);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to query key %d: %ld", key_serial, ret);
        return 0;
    }

    if (key_size != NULL)
        *key_size = result.key_size;
    if (supported_ops != NULL)
        *supported_ops = result.supported_ops;

    return 1;
}

/* Get key description from kernel keyring */
char *keyring_key_get_description(key_serial_t key_serial)
{
    char *desc = NULL;
    long ret;

    /* First call to get size */
    ret = keyctl_describe(key_serial, NULL, 0);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to get description size for serial %d: %ld",
                     key_serial, ret);
        return NULL;
    }

    desc = keyring_malloc((size_t)ret);
    if (desc == NULL)
        return NULL;

    /* Second call to get actual description */
    ret = keyctl_describe(key_serial, desc, (size_t)ret);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to get description for serial %d: %ld",
                     key_serial, ret);
        keyring_free(desc);
        return NULL;
    }

    return desc;
}

/* Search for key in keyring by description */
key_serial_t keyring_search_key(const char *description, keyring_type_t keyring_type)
{
    key_serial_t keyring;
    long result;

    /* Determine which keyring to search */
    switch (keyring_type) {
    case KEYRING_SESSION:
        keyring = KEY_SPEC_SESSION_KEYRING;
        break;
    case KEYRING_USER:
        keyring = KEY_SPEC_USER_KEYRING;
        break;
    case KEYRING_PERSISTENT:
#ifdef KEY_SPEC_PERSISTENT_KEYRING
        keyring = KEY_SPEC_PERSISTENT_KEYRING;
#else
        /* Fallback to user keyring if persistent not available */
        keyring = KEY_SPEC_USER_KEYRING;
#endif
        break;
    case KEYRING_SEARCH_ALL:
    default:
        /* Try user keyring first, then session */
        result = keyctl_search(KEY_SPEC_USER_KEYRING, "asymmetric",
                              description, 0);
        if (result > 0)
            return (key_serial_t)result;

        result = keyctl_search(KEY_SPEC_SESSION_KEYRING, "asymmetric",
                              description, 0);
        if (result > 0)
            return (key_serial_t)result;

        /* Try persistent keyring if available */
#ifdef KEY_SPEC_PERSISTENT_KEYRING
        keyring = KEY_SPEC_PERSISTENT_KEYRING;
#else
        /* Fallback to user keyring */
        return -1;
#endif
        break;
    }

    /* Search in specified keyring */
    result = keyctl_search(keyring, "asymmetric", description, 0);
    if (result < 0) {
        keyring_error(0, KEYRING_ERR_KEY_NOT_FOUND,
                     "Key '%s' not found in keyring", description);
        return -1;
    }

    return (key_serial_t)result;
}

/* Parse key type string */
keyring_key_type_t keyring_parse_key_type(const char *type_str)
{
    if (type_str == NULL)
        return KEYRING_KEY_TYPE_UNKNOWN;

    if (strcmp(type_str, "private") == 0)
        return KEYRING_KEY_TYPE_PRIVATE;
    if (strcmp(type_str, "public") == 0)
        return KEYRING_KEY_TYPE_PUBLIC;
    if (strcmp(type_str, "cert") == 0)
        return KEYRING_KEY_TYPE_CERT;

    return KEYRING_KEY_TYPE_UNKNOWN;
}

/* Parse keyring type string */
keyring_type_t keyring_parse_keyring_type(const char *keyring_str)
{
    if (keyring_str == NULL)
        return KEYRING_SEARCH_ALL;

    if (strcmp(keyring_str, "session") == 0)
        return KEYRING_SESSION;
    if (strcmp(keyring_str, "user") == 0)
        return KEYRING_USER;
    if (strcmp(keyring_str, "persistent") == 0)
        return KEYRING_PERSISTENT;

    return KEYRING_SEARCH_ALL;
}
