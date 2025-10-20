/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Test URI Parser - RFC 7512 compliant URI parsing tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/keyring_provider.h"

#define TEST_PASS() do { printf("  [PASS] %s\n", __func__); return 0; } while(0)
#define TEST_FAIL(msg) do { printf("  [FAIL] %s: %s\n", __func__, msg); return 1; } while(0)

static int test_uri_parse_by_id(void)
{
    keyring_uri_t uri;
    const char *uri_str = "keyring:id=12ab;type=private";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse URI");
    }

    if (!uri.has_id || uri.id != 0x12ab) {
        TEST_FAIL("Key ID not parsed correctly");
    }

    if (uri.type != KEYRING_KEY_TYPE_PRIVATE) {
        TEST_FAIL("Key type not parsed correctly");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

static int test_uri_parse_by_object(void)
{
    keyring_uri_t uri;
    const char *uri_str = "keyring:object=my-server-key;type=public";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse URI");
    }

    if (!uri.has_object || uri.object == NULL || strcmp(uri.object, "my-server-key") != 0) {
        TEST_FAIL("Object label not parsed correctly");
    }

    if (uri.type != KEYRING_KEY_TYPE_PUBLIC) {
        TEST_FAIL("Key type not parsed correctly");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

static int test_uri_parse_with_backend(void)
{
    keyring_uri_t uri;
    /* Backend parameter is now deprecated and ignored, but should still parse */
    const char *uri_str = "keyring:object=tpm-key;backend=tpm1.2;type=private";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse URI with backend parameter");
    }

    if (!uri.has_object || uri.object == NULL || strcmp(uri.object, "tpm-key") != 0) {
        TEST_FAIL("Object not parsed correctly");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

static int test_uri_parse_with_keyring_type(void)
{
    keyring_uri_t uri;
    const char *uri_str = "keyring:object=session-key;keyring=session;type=private";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse URI");
    }

    if (uri.keyring != KEYRING_SESSION) {
        TEST_FAIL("Keyring type not parsed correctly");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

static int test_uri_parse_percent_encoding(void)
{
    keyring_uri_t uri;
    const char *uri_str = "keyring:object=my%20key%20name;type=private";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse URI");
    }

    if (uri.object == NULL || strcmp(uri.object, "my key name") != 0) {
        TEST_FAIL("Percent encoding not decoded correctly");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

static int test_uri_parse_invalid_scheme(void)
{
    keyring_uri_t uri;
    const char *uri_str = "pkcs11:object=test;type=private";

    memset(&uri, 0, sizeof(uri));

    /* Should fail - wrong scheme */
    if (keyring_uri_parse(uri_str, &uri)) {
        keyring_uri_free(&uri);
        TEST_FAIL("Should have rejected non-keyring URI");
    }

    TEST_PASS();
}

static int test_uri_parse_minimal(void)
{
    keyring_uri_t uri;
    const char *uri_str = "keyring:id=1234";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse minimal URI");
    }

    if (!uri.has_id || uri.id != 0x1234) {
        TEST_FAIL("Key ID not parsed correctly");
    }

    /* Type should default to UNKNOWN */
    if (uri.type != KEYRING_KEY_TYPE_UNKNOWN) {
        TEST_FAIL("Key type should default to UNKNOWN");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

static int test_uri_parse_all_attributes(void)
{
    keyring_uri_t uri;
    const char *uri_str = "keyring:id=abcd;object=full-test;type=private;backend=software;keyring=user";

    memset(&uri, 0, sizeof(uri));

    if (!keyring_uri_parse(uri_str, &uri)) {
        TEST_FAIL("Failed to parse URI with all attributes");
    }

    if (!uri.has_id || uri.id != 0xabcd) {
        TEST_FAIL("Key ID not parsed correctly");
    }

    if (!uri.has_object || uri.object == NULL || strcmp(uri.object, "full-test") != 0) {
        TEST_FAIL("Object label not parsed correctly");
    }

    if (uri.type != KEYRING_KEY_TYPE_PRIVATE) {
        TEST_FAIL("Key type not parsed correctly");
    }

    /* Backend parameter is deprecated and ignored, but should still parse */

    if (uri.keyring != KEYRING_USER) {
        TEST_FAIL("Keyring type not parsed correctly");
    }

    keyring_uri_free(&uri);
    TEST_PASS();
}

int main(void)
{
    int failed = 0;

    printf("Running URI Parser Tests...\n");

    failed += test_uri_parse_by_id();
    failed += test_uri_parse_by_object();
    failed += test_uri_parse_with_backend();
    failed += test_uri_parse_with_keyring_type();
    failed += test_uri_parse_percent_encoding();
    failed += test_uri_parse_invalid_scheme();
    failed += test_uri_parse_minimal();
    failed += test_uri_parse_all_attributes();

    printf("\nURI Parser Tests: %d test(s) failed\n", failed);

    return failed > 0 ? 1 : 0;
}
