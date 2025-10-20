/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - TPM Support
 *
 * This module handles TPM key detection and kernel keyring hardware-offloaded operations.
 * All TPM operations are performed through the Linux kernel's asymmetric key interface,
 * which provides unified access to both software and TPM-backed keys.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyring_provider.h"

/* Initialize kernel keyring crypto support */
int keyring_pkey_init(keyring_prov_ctx_t *ctx)
{
    if (ctx == NULL)
        return 0;

    /*
     * No initialization needed - the Linux kernel keyring handles
     * all crypto operations (both software and TPM-backed) through
     * the asymmetric key type.
     */
    ctx->tpm_available = 1;

    return 1;
}

/* Cleanup kernel keyring crypto resources */
void keyring_pkey_cleanup(keyring_prov_ctx_t *ctx)
{
    /*
     * No cleanup needed - kernel keyring manages all resources.
     */
    if (ctx != NULL)
        ctx->tpm_available = 0;
}

/*
 * Backend detection removed - kernel keyring handles both software
 * and TPM-backed keys transparently through the same API.
 */

/* Perform signature operation via kernel keyring */
int keyring_pkey_sign(key_serial_t key_serial, const unsigned char *tbs,
                      size_t tbslen, unsigned char *sig, size_t *siglen,
                      const char *mdname, const char *pad_mode)
{
    /*
     * Signing through kernel keyring asymmetric key API.
     *
     * The Linux kernel's asymmetric key type provides a unified interface
     * for both software and TPM-backed keys. The kernel automatically
     * routes operations to the appropriate backend (TPM hardware or
     * software) based on how the key was created.
     */
    char info[128];
    long ret;

    /* Build info string: "enc=<encoding> hash=<hash>" */
    if (pad_mode != NULL && strcmp(pad_mode, "pss") == 0) {
        snprintf(info, sizeof(info), "enc=pss hash=%s",
                mdname ? mdname : "sha256");
    } else {
        snprintf(info, sizeof(info), "enc=pkcs1 hash=%s",
                mdname ? mdname : "sha256");
    }

    /* Perform signature via kernel keyring */
    ret = keyctl_pkey_sign(key_serial, info, tbs, tbslen, sig, *siglen);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Keyring sign operation failed: %ld", ret);
        return 0;
    }

    *siglen = (size_t)ret;
    return 1;
}

/* Perform encryption operation via kernel keyring */
int keyring_pkey_encrypt(key_serial_t key_serial, const unsigned char *in,
                        size_t inlen, unsigned char *out, size_t *outlen,
                        const char *pad_mode)
{
    /*
     * Encryption through kernel keyring asymmetric key API.
     *
     * The Linux kernel's asymmetric key type provides a unified interface
     * for both software and TPM-backed keys. The kernel automatically
     * routes operations to the appropriate backend (TPM hardware or
     * software) based on how the key was created.
     */
    struct keyctl_pkey_query result;
    char info[128];
    long ret;

    /* Build info string */
    if (pad_mode != NULL && strcmp(pad_mode, "oaep") == 0) {
        snprintf(info, sizeof(info), "enc=oaep");
    } else {
        snprintf(info, sizeof(info), "enc=pkcs1");
    }

    /* Query key first to ensure kernel has necessary information */
    if (keyctl_pkey_query(key_serial, info, &result) < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Keyring query operation failed for encrypt");
        return 0;
    }

    /* Verify output buffer is large enough */
    if (*outlen < result.max_dec_size) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Output buffer too small for encryption: need %u, have %zu",
                     result.max_dec_size, *outlen);
        return 0;
    }

    /* Perform encryption via kernel keyring */
    ret = keyctl_pkey_encrypt(key_serial, info, in, inlen, out, result.max_dec_size);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Keyring encrypt operation failed: %ld", ret);
        return 0;
    }

    *outlen = (size_t)ret;
    return 1;
}

/* Perform decryption operation via kernel keyring */
int keyring_pkey_decrypt(key_serial_t key_serial, const unsigned char *in,
                        size_t inlen, unsigned char *out, size_t *outlen,
                        const char *pad_mode)
{
    /*
     * Decryption through kernel keyring asymmetric key API.
     *
     * The Linux kernel's asymmetric key type provides a unified interface
     * for both software and TPM-backed keys. The kernel automatically
     * routes operations to the appropriate backend (TPM hardware or
     * software) based on how the key was created.
     */
    struct keyctl_pkey_query result;
    char info[128];
    long ret;

    /* Build info string */
    if (pad_mode != NULL && strcmp(pad_mode, "oaep") == 0) {
        snprintf(info, sizeof(info), "enc=oaep");
    } else {
        snprintf(info, sizeof(info), "enc=pkcs1");
    }

    /* Query key first to ensure kernel has necessary information */
    if (keyctl_pkey_query(key_serial, info, &result) < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Keyring query operation failed for decrypt");
        return 0;
    }

    /* Verify output buffer is large enough */
    if (*outlen < result.max_enc_size) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Output buffer too small for decryption: need %u, have %zu",
                     result.max_enc_size, *outlen);
        return 0;
    }

    /* Perform decryption via kernel keyring */
    ret = keyctl_pkey_decrypt(key_serial, info, in, inlen, out, result.max_enc_size);
    if (ret < 0) {
        keyring_error(0, KEYRING_ERR_OPERATION,
                     "Keyring decrypt operation failed: %ld", ret);
        return 0;
    }

    *outlen = (size_t)ret;
    return 1;
}
