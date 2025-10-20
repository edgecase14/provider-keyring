/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Test Provider Loading - Verify provider can be loaded by OpenSSL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#define TEST_PASS() do { printf("  [PASS] %s\n", __func__); return 0; } while(0)
#define TEST_FAIL(msg) do { printf("  [FAIL] %s: %s\n", __func__, msg); return 1; } while(0)

static int test_provider_load(void)
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_LIB_CTX *libctx = NULL;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_FAIL("Failed to create library context");
    }

    /* Try to load the keyring provider */
    prov = OSSL_PROVIDER_load(libctx, "keyring");
    if (prov == NULL) {
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to load keyring provider");
    }

    /* Provider loaded successfully */
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    TEST_PASS();
}

static int test_provider_get_params(void)
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PARAM params[4];
    const char *name = NULL;
    const char *version = NULL;
    const char *buildinfo = NULL;
    int status = 0;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_FAIL("Failed to create library context");
    }

    prov = OSSL_PROVIDER_load(libctx, "keyring");
    if (prov == NULL) {
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to load keyring provider");
    }

    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME,
                                               (char **)&name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION,
                                               (char **)&version, 0);
    params[2] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO,
                                               (char **)&buildinfo, 0);
    params[3] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_get_params(prov, params)) {
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to get provider parameters");
    }

    printf("    Provider Name: %s\n", name ? name : "(null)");
    printf("    Provider Version: %s\n", version ? version : "(null)");
    printf("    Provider Buildinfo: %s\n", buildinfo ? buildinfo : "(null)");

    if (name == NULL || strcmp(name, "OpenSSL Keyring Provider") != 0) {
        status = 1;
    }

    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    if (status) {
        TEST_FAIL("Provider name mismatch");
    }

    TEST_PASS();
}

static int test_provider_query_keymgmt(void)
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_KEYMGMT *keymgmt = NULL;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_FAIL("Failed to create library context");
    }

    prov = OSSL_PROVIDER_load(libctx, "keyring");
    if (prov == NULL) {
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to load keyring provider");
    }

    /* Query for RSA keymgmt */
    keymgmt = EVP_KEYMGMT_fetch(libctx, "RSA", "provider=keyring");
    if (keymgmt == NULL) {
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to fetch RSA keymgmt from provider");
    }

    printf("    Successfully fetched RSA keymgmt from keyring provider\n");

    EVP_KEYMGMT_free(keymgmt);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    TEST_PASS();
}

static int test_provider_query_signature(void)
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_SIGNATURE *sig = NULL;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_FAIL("Failed to create library context");
    }

    prov = OSSL_PROVIDER_load(libctx, "keyring");
    if (prov == NULL) {
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to load keyring provider");
    }

    /* Query for RSA signature */
    sig = EVP_SIGNATURE_fetch(libctx, "RSA", "provider=keyring");
    if (sig == NULL) {
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to fetch RSA signature from provider");
    }

    printf("    Successfully fetched RSA signature from keyring provider\n");

    EVP_SIGNATURE_free(sig);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    TEST_PASS();
}

static int test_provider_query_asym_cipher(void)
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_ASYM_CIPHER *cipher = NULL;

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_FAIL("Failed to create library context");
    }

    prov = OSSL_PROVIDER_load(libctx, "keyring");
    if (prov == NULL) {
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to load keyring provider");
    }

    /* Query for RSA asym_cipher */
    cipher = EVP_ASYM_CIPHER_fetch(libctx, "RSA", "provider=keyring");
    if (cipher == NULL) {
        OSSL_PROVIDER_unload(prov);
        OSSL_LIB_CTX_free(libctx);
        TEST_FAIL("Failed to fetch RSA asym_cipher from provider");
    }

    printf("    Successfully fetched RSA asym_cipher from keyring provider\n");

    EVP_ASYM_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);

    TEST_PASS();
}

int main(void)
{
    int failed = 0;

    printf("Running Provider Loading Tests...\n");
    printf("Note: These tests require the provider to be in OPENSSL_MODULES path\n\n");

    failed += test_provider_load();
    failed += test_provider_get_params();
    failed += test_provider_query_keymgmt();
    failed += test_provider_query_signature();
    failed += test_provider_query_asym_cipher();

    printf("\nProvider Loading Tests: %d test(s) failed\n", failed);

    return failed > 0 ? 1 : 0;
}
