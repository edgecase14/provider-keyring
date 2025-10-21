/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Test Parameter Export - Verify EVP_PKEY_get_bn_param works with keyring keys
 *
 * This test verifies that applications can extract RSA parameters (modulus and
 * exponent) from keys loaded through the keyring provider using the standard
 * OpenSSL 3.x parameter API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <keyutils.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/store.h>

#define TEST_PASS() do { printf("  [PASS] %s\n", __func__); return 0; } while(0)
#define TEST_FAIL(msg) do { printf("  [FAIL] %s: %s\n", __func__, msg); return 1; } while(0)

/* Global test resources */
static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *default_prov = NULL;
static OSSL_PROVIDER *keyring_prov = NULL;
static key_serial_t test_key_serial = 0;

static void cleanup_test_key(void)
{
    if (test_key_serial > 0) {
        keyctl_unlink(test_key_serial, KEY_SPEC_USER_KEYRING);
        test_key_serial = 0;
    }
}

static void cleanup_providers(void)
{
    if (keyring_prov != NULL) {
        OSSL_PROVIDER_unload(keyring_prov);
        keyring_prov = NULL;
    }
    if (default_prov != NULL) {
        OSSL_PROVIDER_unload(default_prov);
        default_prov = NULL;
    }
    if (libctx != NULL) {
        OSSL_LIB_CTX_free(libctx);
        libctx = NULL;
    }
}

static int setup_providers(void)
{
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        return 0;
    }

    /* Load default provider for key generation */
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (default_prov == NULL) {
        cleanup_providers();
        return 0;
    }

    /* Load keyring provider */
    keyring_prov = OSSL_PROVIDER_load(libctx, "keyring");
    if (keyring_prov == NULL) {
        cleanup_providers();
        return 0;
    }

    return 1;
}

/*
 * Generate an RSA key and load it into the kernel keyring
 * Returns the key serial, or 0 on failure
 */
static key_serial_t generate_and_load_test_key(const char *description)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    key_serial_t key_id = 0;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *cert_der = NULL;
    int cert_der_len;

    /* Generate 2048-bit RSA key */
    pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (pctx == NULL)
        goto cleanup;

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
        goto cleanup;

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        goto cleanup;

    /*
     * The kernel keyring asymmetric key type expects either:
     * 1. X.509 certificate in DER format
     * 2. Raw public key in specific format (kernel-internal)
     *
     * We'll create a self-signed certificate which is most reliable.
     */
    cert = X509_new();
    if (cert == NULL)
        goto cleanup;

    /* Set version to X509 v3 */
    if (!X509_set_version(cert, 2))
        goto cleanup;

    /* Set serial number */
    if (!ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
        goto cleanup;

    /* Set validity period */
    if (!X509_gmtime_adj(X509_get_notBefore(cert), 0))
        goto cleanup;
    if (!X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60))
        goto cleanup;

    /* Set subject name */
    name = X509_get_subject_name(cert);
    if (name == NULL)
        goto cleanup;
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                     (unsigned char *)description, -1, -1, 0))
        goto cleanup;

    /* Set issuer name (self-signed) */
    if (!X509_set_issuer_name(cert, name))
        goto cleanup;

    /* Set public key */
    if (!X509_set_pubkey(cert, pkey))
        goto cleanup;

    /* Sign the certificate */
    if (!X509_sign(cert, pkey, EVP_sha256()))
        goto cleanup;

    /* Convert certificate to DER format */
    cert_der_len = i2d_X509(cert, NULL);
    if (cert_der_len <= 0)
        goto cleanup;

    cert_der = malloc((size_t)cert_der_len);
    if (cert_der == NULL)
        goto cleanup;

    unsigned char *p = cert_der;
    if (i2d_X509(cert, &p) <= 0)
        goto cleanup;

    /* Load into kernel keyring */
    key_id = add_key("asymmetric", description, cert_der, (size_t)cert_der_len,
                     KEY_SPEC_USER_KEYRING);

cleanup:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (md_ctx != NULL)
        EVP_MD_CTX_free(md_ctx);
    if (cert != NULL)
        X509_free(cert);
    if (cert_der != NULL)
        free(cert_der);

    return key_id;
}

static int test_export_via_keymgmt(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    char uri[256];
    BIGNUM *n = NULL, *e = NULL;
    int ret = 1;

    /* Setup providers */
    if (!setup_providers()) {
        TEST_FAIL("Failed to setup providers");
    }

    /* Generate and load test key */
    test_key_serial = generate_and_load_test_key("test-export-keymgmt");
    if (test_key_serial <= 0) {
        cleanup_providers();
        TEST_FAIL("Failed to generate and load test key");
    }

    printf("    Generated test key with serial: 0x%08x\n", test_key_serial);

    /* Load key from keyring via OSSL_STORE */
    snprintf(uri, sizeof(uri), "keyring:id=%x", test_key_serial);
    printf("    Loading key via URI: %s\n", uri);

    store_ctx = OSSL_STORE_open_ex(uri, libctx, NULL, NULL, NULL, NULL, NULL, NULL);
    if (store_ctx == NULL) {
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to open OSSL_STORE context");
    }

    /* Load the key */
    while (!OSSL_STORE_eof(store_ctx)) {
        info = OSSL_STORE_load(store_ctx);
        if (info == NULL)
            break;

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (pkey == NULL) {
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to load key from keyring");
    }

    printf("    Successfully loaded EVP_PKEY from keyring\n");

    /* Test 1: Extract RSA modulus (n) */
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
        EVP_PKEY_free(pkey);
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to extract RSA modulus (n)");
    }

    printf("    ✓ Extracted RSA modulus (n): %d bits\n", BN_num_bits(n));

    /* Test 2: Extract RSA exponent (e) */
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
        BN_free(n);
        EVP_PKEY_free(pkey);
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to extract RSA exponent (e)");
    }

    printf("    ✓ Extracted RSA exponent (e): %s\n", BN_bn2dec(e));

    /* Verify parameters are reasonable */
    if (BN_num_bits(n) < 2048 || BN_num_bits(n) > 2048) {
        printf("    Warning: Expected 2048-bit modulus, got %d bits\n", BN_num_bits(n));
    }

    /* Common RSA exponents are 3, 17, or 65537 */
    if (!BN_is_word(e, 65537) && !BN_is_word(e, 3) && !BN_is_word(e, 17)) {
        printf("    Warning: Unusual RSA exponent value\n");
    }

    /* Success! */
    ret = 0;

    BN_free(n);
    BN_free(e);
    EVP_PKEY_free(pkey);
    cleanup_test_key();
    cleanup_providers();

    if (ret == 0) {
        TEST_PASS();
    }
    return ret;
}

static int test_export_via_params_api(void)
{
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    char uri[256];
    OSSL_PARAM params[3];
    BIGNUM *n = NULL, *e = NULL;
    int ret = 1;

    /* Setup providers */
    if (!setup_providers()) {
        TEST_FAIL("Failed to setup providers");
    }

    /* Generate and load test key */
    test_key_serial = generate_and_load_test_key("test-export-params");
    if (test_key_serial <= 0) {
        cleanup_providers();
        TEST_FAIL("Failed to generate and load test key");
    }

    printf("    Generated test key with serial: 0x%08x\n", test_key_serial);

    /* Load key from keyring */
    snprintf(uri, sizeof(uri), "keyring:id=%x", test_key_serial);

    store_ctx = OSSL_STORE_open_ex(uri, libctx, NULL, NULL, NULL, NULL, NULL, NULL);
    if (store_ctx == NULL) {
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to open OSSL_STORE context");
    }

    while (!OSSL_STORE_eof(store_ctx)) {
        info = OSSL_STORE_load(store_ctx);
        if (info == NULL)
            break;

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (pkey == NULL) {
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to load key from keyring");
    }

    printf("    Successfully loaded EVP_PKEY from keyring\n");

    /* Test using OSSL_PARAM API to get multiple parameters at once */
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_get_params(pkey, params)) {
        EVP_PKEY_free(pkey);
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to get RSA parameters via OSSL_PARAM API");
    }

    /* Extract BIGNUMs from params */
    if (!OSSL_PARAM_get_BN(&params[0], &n)) {
        EVP_PKEY_free(pkey);
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to extract modulus from OSSL_PARAM");
    }

    if (!OSSL_PARAM_get_BN(&params[1], &e)) {
        BN_free(n);
        EVP_PKEY_free(pkey);
        cleanup_test_key();
        cleanup_providers();
        TEST_FAIL("Failed to extract exponent from OSSL_PARAM");
    }

    printf("    ✓ Extracted parameters via OSSL_PARAM API\n");
    printf("    ✓ Modulus: %d bits\n", BN_num_bits(n));
    printf("    ✓ Exponent: %s\n", BN_bn2dec(e));

    /* Success! */
    ret = 0;

    BN_free(n);
    BN_free(e);
    EVP_PKEY_free(pkey);
    cleanup_test_key();
    cleanup_providers();

    if (ret == 0) {
        TEST_PASS();
    }
    return ret;
}

static int test_compare_exported_params(void)
{
    EVP_PKEY *pkey_orig = NULL;
    EVP_PKEY *pkey_keyring = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    char uri[256];
    BIGNUM *n_orig = NULL, *e_orig = NULL;
    BIGNUM *n_keyring = NULL, *e_keyring = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    unsigned char *cert_der = NULL;
    int cert_der_len;
    int ret = 1;

    /* Setup providers */
    if (!setup_providers()) {
        TEST_FAIL("Failed to setup providers");
    }

    /* Generate original RSA key */
    pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (pctx == NULL) {
        cleanup_providers();
        TEST_FAIL("Failed to create PKEY context");
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey_orig) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        cleanup_providers();
        TEST_FAIL("Failed to generate RSA key");
    }
    EVP_PKEY_CTX_free(pctx);

    /* Extract parameters from original key */
    if (!EVP_PKEY_get_bn_param(pkey_orig, OSSL_PKEY_PARAM_RSA_N, &n_orig) ||
        !EVP_PKEY_get_bn_param(pkey_orig, OSSL_PKEY_PARAM_RSA_E, &e_orig)) {
        EVP_PKEY_free(pkey_orig);
        cleanup_providers();
        TEST_FAIL("Failed to extract parameters from original key");
    }

    printf("    Original key: n=%d bits, e=%s\n", BN_num_bits(n_orig), BN_bn2dec(e_orig));

    /* Create self-signed certificate */
    cert = X509_new();
    if (cert == NULL)
        goto cleanup_compare;

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (unsigned char *)"test-compare", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, pkey_orig);
    X509_sign(cert, pkey_orig, EVP_sha256());

    /* Convert to DER and load into keyring */
    cert_der_len = i2d_X509(cert, NULL);
    if (cert_der_len <= 0)
        goto cleanup_compare;

    cert_der = malloc((size_t)cert_der_len);
    if (cert_der == NULL)
        goto cleanup_compare;

    unsigned char *p = cert_der;
    i2d_X509(cert, &p);

    test_key_serial = add_key("asymmetric", "test-compare", cert_der,
                              (size_t)cert_der_len, KEY_SPEC_USER_KEYRING);
    if (test_key_serial <= 0)
        goto cleanup_compare;

    printf("    Loaded key into keyring with serial: 0x%08x\n", test_key_serial);

    /* Load from keyring */
    snprintf(uri, sizeof(uri), "keyring:id=%x", test_key_serial);
    store_ctx = OSSL_STORE_open_ex(uri, libctx, NULL, NULL, NULL, NULL, NULL, NULL);
    if (store_ctx == NULL)
        goto cleanup_compare;

    while (!OSSL_STORE_eof(store_ctx)) {
        info = OSSL_STORE_load(store_ctx);
        if (info == NULL)
            break;

        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            pkey_keyring = OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(store_ctx);

    if (pkey_keyring == NULL)
        goto cleanup_compare;

    /* Extract parameters from keyring key */
    if (!EVP_PKEY_get_bn_param(pkey_keyring, OSSL_PKEY_PARAM_RSA_N, &n_keyring) ||
        !EVP_PKEY_get_bn_param(pkey_keyring, OSSL_PKEY_PARAM_RSA_E, &e_keyring)) {
        goto cleanup_compare;
    }

    printf("    Keyring key: n=%d bits, e=%s\n", BN_num_bits(n_keyring), BN_bn2dec(e_keyring));

    /* Compare parameters */
    if (BN_cmp(n_orig, n_keyring) != 0) {
        printf("    ERROR: Modulus mismatch!\n");
        goto cleanup_compare;
    }

    if (BN_cmp(e_orig, e_keyring) != 0) {
        printf("    ERROR: Exponent mismatch!\n");
        goto cleanup_compare;
    }

    printf("    ✓ Parameters match perfectly!\n");
    ret = 0;

cleanup_compare:
    if (n_orig) BN_free(n_orig);
    if (e_orig) BN_free(e_orig);
    if (n_keyring) BN_free(n_keyring);
    if (e_keyring) BN_free(e_keyring);
    if (pkey_orig) EVP_PKEY_free(pkey_orig);
    if (pkey_keyring) EVP_PKEY_free(pkey_keyring);
    if (cert) X509_free(cert);
    if (cert_der) free(cert_der);
    cleanup_test_key();
    cleanup_providers();

    if (ret == 0) {
        TEST_PASS();
    } else {
        TEST_FAIL("Parameter comparison failed");
    }
    return ret;
}

int main(void)
{
    int failed = 0;

    printf("Running Parameter Export Tests...\n");
    printf("Note: These tests require keyctl support and OPENSSL_MODULES path\n\n");

    /* Check for keyctl support */
    if (add_key("user", "test-check", "test", 4, KEY_SPEC_USER_KEYRING) < 0) {
        printf("ERROR: keyctl not available or insufficient permissions\n");
        printf("Try: sudo setcap cap_sys_admin+ep <test_binary>\n");
        return 1;
    }

    failed += test_export_via_keymgmt();
    failed += test_export_via_params_api();
    failed += test_compare_exported_params();

    printf("\nParameter Export Tests: %d test(s) failed\n", failed);

    return failed > 0 ? 1 : 0;
}
