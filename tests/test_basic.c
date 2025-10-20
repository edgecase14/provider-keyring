/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Test Basic Functionality - Simple tests that don't require keys
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/keyring_provider.h"

#define TEST_PASS() do { printf("  [PASS] %s\n", __func__); return 0; } while(0)
#define TEST_FAIL(msg) do { printf("  [FAIL] %s: %s\n", __func__, msg); return 1; } while(0)

/* Backend parsing test removed - backends are no longer exposed */

static int test_parse_keyring_type_strings(void)
{
    if (keyring_parse_keyring_type("session") != KEYRING_SESSION) {
        TEST_FAIL("Failed to parse 'session'");
    }

    if (keyring_parse_keyring_type("user") != KEYRING_USER) {
        TEST_FAIL("Failed to parse 'user'");
    }

    if (keyring_parse_keyring_type("persistent") != KEYRING_PERSISTENT) {
        TEST_FAIL("Failed to parse 'persistent'");
    }

    if (keyring_parse_keyring_type(NULL) != KEYRING_SEARCH_ALL) {
        TEST_FAIL("Failed to handle NULL");
    }

    if (keyring_parse_keyring_type("invalid") != KEYRING_SEARCH_ALL) {
        TEST_FAIL("Failed to handle invalid input");
    }

    TEST_PASS();
}

static int test_parse_key_type_strings(void)
{
    if (keyring_parse_key_type("private") != KEYRING_KEY_TYPE_PRIVATE) {
        TEST_FAIL("Failed to parse 'private'");
    }

    if (keyring_parse_key_type("public") != KEYRING_KEY_TYPE_PUBLIC) {
        TEST_FAIL("Failed to parse 'public'");
    }

    if (keyring_parse_key_type("cert") != KEYRING_KEY_TYPE_CERT) {
        TEST_FAIL("Failed to parse 'cert'");
    }

    if (keyring_parse_key_type(NULL) != KEYRING_KEY_TYPE_UNKNOWN) {
        TEST_FAIL("Failed to handle NULL");
    }

    if (keyring_parse_key_type("invalid") != KEYRING_KEY_TYPE_UNKNOWN) {
        TEST_FAIL("Failed to handle invalid input");
    }

    TEST_PASS();
}

static int test_memory_functions(void)
{
    void *ptr1, *ptr2;
    char *str;

    /* Test malloc */
    ptr1 = keyring_malloc(100);
    if (ptr1 == NULL) {
        TEST_FAIL("keyring_malloc failed");
    }

    /* Test realloc */
    ptr2 = keyring_realloc(ptr1, 200);
    if (ptr2 == NULL) {
        keyring_free(ptr1);
        TEST_FAIL("keyring_realloc failed");
    }

    /* Test strdup */
    str = keyring_strdup("test string");
    if (str == NULL) {
        keyring_free(ptr2);
        TEST_FAIL("keyring_strdup failed");
    }

    if (strcmp(str, "test string") != 0) {
        keyring_free(ptr2);
        keyring_free(str);
        TEST_FAIL("keyring_strdup produced incorrect result");
    }

    /* Test free (should not crash) */
    keyring_free(ptr2);
    keyring_free(str);
    keyring_free(NULL);  /* Should be safe */

    TEST_PASS();
}

int main(void)
{
    int failed = 0;

    printf("Running Basic Functionality Tests...\n");

    failed += test_parse_keyring_type_strings();
    failed += test_parse_key_type_strings();
    failed += test_memory_functions();

    printf("\nBasic Tests: %d test(s) failed\n", failed);

    return failed > 0 ? 1 : 0;
}
