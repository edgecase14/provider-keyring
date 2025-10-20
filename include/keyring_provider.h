/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider
 *
 * Provides RSA operations using Linux kernel keyring asymmetric keys
 * with TPM 1.2/2.0 hardware offload support
 */

#ifndef KEYRING_PROVIDER_H
#define KEYRING_PROVIDER_H

/* Disable deprecated OpenSSL APIs */
#define OPENSSL_NO_DEPRECATED

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include <keyutils.h>

/* Provider version */
#define KEYRING_PROVIDER_VERSION_STR "0.1.0"
#define KEYRING_PROVIDER_VERSION_MAJOR 0
#define KEYRING_PROVIDER_VERSION_MINOR 1
#define KEYRING_PROVIDER_VERSION_PATCH 0

/* URI scheme */
#define KEYRING_URI_SCHEME "keyring"
#define KEYRING_URI_SCHEME_LEN 7

/* Error codes */
#define KEYRING_ERR_INVALID_URI     1
#define KEYRING_ERR_KEY_NOT_FOUND   2
#define KEYRING_ERR_PERMISSION      3
#define KEYRING_ERR_TPM_INIT        4
#define KEYRING_ERR_OPERATION       5

/* Key types */
typedef enum {
    KEYRING_KEY_TYPE_UNKNOWN = 0,
    KEYRING_KEY_TYPE_PRIVATE,
    KEYRING_KEY_TYPE_PUBLIC,
    KEYRING_KEY_TYPE_CERT
} keyring_key_type_t;

/* Backend types - kept for backward compatibility but no longer used */

/* Keyring types */
typedef enum {
    KEYRING_SEARCH_ALL = 0,
    KEYRING_SESSION,
    KEYRING_USER,
    KEYRING_PERSISTENT
} keyring_type_t;

/* URI structure */
typedef struct {
    /* Path attributes */
    key_serial_t id;                    /* Keyring serial ID */
    char *object;                       /* Key description/label */
    keyring_key_type_t type;           /* Key type */
    keyring_type_t keyring;            /* Target keyring */

    /* Query attributes */
    char *pin_source;                  /* PIN source URI */
    char *module_path;                 /* TPM library path */

    /* Flags */
    int has_id;                        /* ID specified */
    int has_object;                    /* Object specified */
} keyring_uri_t;

/* Key context */
typedef struct {
    key_serial_t key_serial;           /* Kernel keyring serial */
    char *description;                 /* Key description */
    int key_size;                      /* Key size in bits */
    unsigned char *public_key;         /* Public key data (DER) */
    size_t public_key_len;             /* Public key length */
    EVP_PKEY *evp_pkey;               /* Cached EVP_PKEY (for public key operations) */
    int refcount;                      /* Reference count */
} keyring_key_ctx_t;

/* Provider context */
typedef struct {
    const OSSL_CORE_HANDLE *core_handle;
    OSSL_LIB_CTX *libctx;

    /* TPM availability flag */
    int tpm_available;
} keyring_prov_ctx_t;

/* Signature context */
typedef struct {
    keyring_prov_ctx_t *provctx;       /* Provider context */
    keyring_key_ctx_t *key_ctx;
    const char *mdname;                /* Digest algorithm name */
    EVP_MD *md;                        /* Digest algorithm */
    const char *pad_mode;              /* Padding mode */
    int saltlen;                       /* PSS salt length */
} keyring_sig_ctx_t;

/* Cipher context */
typedef struct {
    keyring_prov_ctx_t *provctx;       /* Provider context */
    keyring_key_ctx_t *key_ctx;
    const char *pad_mode;              /* Padding mode */
    EVP_MD *oaep_md;                  /* OAEP digest */
    EVP_MD *mgf1_md;                  /* MGF1 digest */
    unsigned char *oaep_label;        /* OAEP label */
    size_t oaep_label_len;            /* OAEP label length */
} keyring_cipher_ctx_t;

/* Function declarations */

/* provider.c */
const OSSL_ALGORITHM *keyring_query_operation(void *provctx, int operation_id,
                                               int *no_cache);
const OSSL_ITEM *keyring_get_reason_strings(void *provctx);
int keyring_get_params(void *provctx, OSSL_PARAM params[]);

/* keyring_uri.c */
int keyring_uri_parse(const char *uri, keyring_uri_t *parsed);
void keyring_uri_free(keyring_uri_t *uri);
char *keyring_uri_unescape(const char *str, size_t len);
int keyring_uri_validate(const keyring_uri_t *uri);

/* keyring_loader.c */
void *keyring_load(void *provctx, const char *uri, int expect_type);
int keyring_store(void *provctx, const void *keydata, const char *uri);
int keyring_enumerate(void *provctx, const char *uri,
                     int (*callback)(const char *uri, void *cbarg),
                     void *cbarg);

/* keyring_rsa.c */
extern const OSSL_DISPATCH keyring_rsa_keymgmt_functions[];
keyring_key_ctx_t *keyring_key_new(void);
void keyring_key_free(keyring_key_ctx_t *ctx);
int keyring_key_up_ref(keyring_key_ctx_t *ctx);
int keyring_key_load_by_id(key_serial_t id, keyring_key_ctx_t *ctx);
int keyring_key_load_by_description(const char *desc, keyring_type_t keyring_type,
                                    keyring_key_ctx_t *ctx);

/* keyring_signature.c */
extern const OSSL_DISPATCH keyring_rsa_signature_functions[];

/* keyring_asym_cipher.c */
extern const OSSL_DISPATCH keyring_rsa_asym_cipher_functions[];

/* keyring_store.c */
extern const OSSL_DISPATCH keyring_store_functions[];

/* keyring_tpm.c - kernel keyring crypto operations */
int keyring_pkey_init(keyring_prov_ctx_t *ctx);
void keyring_pkey_cleanup(keyring_prov_ctx_t *ctx);
int keyring_pkey_sign(key_serial_t key_serial, const unsigned char *tbs,
                      size_t tbslen, unsigned char *sig, size_t *siglen,
                      const char *mdname, const char *pad_mode);
int keyring_pkey_decrypt(key_serial_t key_serial, const unsigned char *in,
                        size_t inlen, unsigned char *out, size_t *outlen,
                        const char *pad_mode);

/* util.c */
void *keyring_malloc(size_t size);
void *keyring_zalloc(size_t size);
void *keyring_realloc(void *ptr, size_t size);
void keyring_free(void *ptr);
void keyring_clear_free(void *ptr, size_t len);
char *keyring_strdup(const char *s);
void keyring_error(int lib, int reason, const char *fmt, ...);
int keyring_key_get_public(key_serial_t key_serial, unsigned char **data,
                          size_t *len);
int keyring_key_query(key_serial_t key_serial, unsigned int *key_size,
                      unsigned int *supported_ops);
char *keyring_key_get_description(key_serial_t key_serial);
key_serial_t keyring_search_key(const char *description, keyring_type_t keyring_type);
keyring_key_type_t keyring_parse_key_type(const char *type_str);
keyring_type_t keyring_parse_keyring_type(const char *keyring_str);

#endif /* KEYRING_PROVIDER_H */
