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

/* Read public key from kernel keyring */
int keyring_key_get_public(key_serial_t key_serial, unsigned char **data,
                           size_t *len)
{
    long ret;
    void *buffer = NULL;
    size_t buflen = 0;

    /* First call to get the size */
    ret = keyctl_read(key_serial, NULL, 0);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Failed to read key size for serial %d: %ld",
                     key_serial, ret);
        return 0;
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
    key_serial_t key;

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
        key = keyctl_search(KEY_SPEC_USER_KEYRING, "asymmetric",
                           description, 0);
        if (key > 0)
            return key;

        key = keyctl_search(KEY_SPEC_SESSION_KEYRING, "asymmetric",
                           description, 0);
        if (key > 0)
            return key;

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
    key = keyctl_search(keyring, "asymmetric", description, 0);
    if (key < 0) {
        keyring_error(0, KEYRING_ERR_KEY_NOT_FOUND,
                     "Key '%s' not found in keyring", description);
        return -1;
    }

    return key;
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
