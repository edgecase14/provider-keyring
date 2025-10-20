/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OpenSSL Keyring Provider - RFC 7512 Compatible URI Parser
 *
 * URI Format: keyring:path-attributes[?query-attributes]
 *
 * Path Attributes (semicolon-separated):
 *   id=<hex-serial>        - Keyring serial ID
 *   object=<description>   - Key description/label
 *   type=<key-type>        - Key type (private, public, cert)
 *   keyring=<name>         - Target keyring (session, user, persistent)
 *   backend=<tpm-version>  - TPM backend (auto, software, tpm1.2, tpm2)
 *
 * Query Attributes (ampersand-separated):
 *   pin-source=<uri>       - PIN source URI
 *   module-path=<path>     - TPM library path
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "keyring_provider.h"

/* Convert hex character to integer */
static int hex_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Percent-decode a URI component */
char *keyring_uri_unescape(const char *str, size_t len)
{
    char *result;
    size_t i, j;

    if (str == NULL)
        return NULL;

    if (len == 0)
        len = strlen(str);

    result = keyring_malloc(len + 1);
    if (result == NULL)
        return NULL;

    for (i = 0, j = 0; i < len; i++, j++) {
        if (str[i] == '%' && i + 2 < len) {
            int high = hex_to_int(str[i + 1]);
            int low = hex_to_int(str[i + 2]);

            if (high >= 0 && low >= 0) {
                result[j] = (char)((high << 4) | low);
                i += 2;
            } else {
                result[j] = str[i];
            }
        } else if (str[i] == '+') {
            /* Some implementations use + for space */
            result[j] = ' ';
        } else {
            result[j] = str[i];
        }
    }

    result[j] = '\0';
    return result;
}

/* Parse a single attribute (key=value) */
static int parse_attribute(keyring_uri_t *uri, const char *key, const char *value)
{
    char *decoded_value;

    if (strcmp(key, "id") == 0) {
        /* Parse hex serial ID */
        char *endptr;
        long long id_val;

        id_val = strtoll(value, &endptr, 16);
        if (*endptr != '\0' || id_val < 0) {
            keyring_error(0, KEYRING_ERR_INVALID_URI,
                         "Invalid keyring serial ID: %s", value);
            return 0;
        }

        uri->id = (key_serial_t)id_val;
        uri->has_id = 1;
        return 1;
    }

    /* Decode value for string attributes */
    decoded_value = keyring_uri_unescape(value, 0);
    if (decoded_value == NULL)
        return 0;

    if (strcmp(key, "object") == 0) {
        keyring_free(uri->object);
        uri->object = decoded_value;
        uri->has_object = 1;
        return 1;
    }

    if (strcmp(key, "type") == 0) {
        uri->type = keyring_parse_key_type(decoded_value);
        keyring_free(decoded_value);
        if (uri->type == KEYRING_KEY_TYPE_UNKNOWN) {
            keyring_error(0, KEYRING_ERR_INVALID_URI,
                         "Invalid key type: %s", value);
            return 0;
        }
        return 1;
    }

    if (strcmp(key, "keyring") == 0) {
        uri->keyring = keyring_parse_keyring_type(decoded_value);
        keyring_free(decoded_value);
        return 1;
    }

    if (strcmp(key, "backend") == 0) {
        /* Backend parameter is deprecated and ignored - kernel keyring handles all keys transparently */
        keyring_free(decoded_value);
        return 1;
    }

    if (strcmp(key, "pin-source") == 0) {
        keyring_free(uri->pin_source);
        uri->pin_source = decoded_value;
        return 1;
    }

    if (strcmp(key, "module-path") == 0) {
        keyring_free(uri->module_path);
        uri->module_path = decoded_value;
        return 1;
    }

    /* Unknown attribute - ignore per RFC 7512 */
    keyring_free(decoded_value);
    return 1;
}

/* Parse path or query attributes */
static int parse_attributes(keyring_uri_t *uri, const char *attr_str, char separator)
{
    char *str_copy, *saveptr, *token;
    int result = 1;

    if (attr_str == NULL || *attr_str == '\0')
        return 1;

    str_copy = keyring_strdup(attr_str);
    if (str_copy == NULL)
        return 0;

    token = strtok_r(str_copy, &separator, &saveptr);
    while (token != NULL) {
        char *equals = strchr(token, '=');

        if (equals != NULL) {
            *equals = '\0';
            if (!parse_attribute(uri, token, equals + 1)) {
                result = 0;
                break;
            }
        } else if (*token != '\0') {
            /* Attribute without value - treat as boolean flag */
            keyring_error(0, KEYRING_ERR_INVALID_URI,
                         "Attribute without value: %s", token);
            result = 0;
            break;
        }

        token = strtok_r(NULL, &separator, &saveptr);
    }

    keyring_free(str_copy);
    return result;
}

/* Initialize URI structure */
static void keyring_uri_init(keyring_uri_t *uri)
{
    memset(uri, 0, sizeof(*uri));
    uri->type = KEYRING_KEY_TYPE_UNKNOWN;
    uri->keyring = KEYRING_SEARCH_ALL;
}

/* Free URI structure contents */
void keyring_uri_free(keyring_uri_t *uri)
{
    if (uri == NULL)
        return;

    keyring_free(uri->object);
    keyring_free(uri->pin_source);
    keyring_free(uri->module_path);
    keyring_uri_init(uri);
}

/* Validate URI structure */
int keyring_uri_validate(const keyring_uri_t *uri)
{
    if (uri == NULL)
        return 0;

    /* Must have either ID or object (or neither for enumeration) */
    /* Both is also allowed - object can be used for verification */

    return 1;
}

/* Parse keyring URI */
int keyring_uri_parse(const char *uri_str, keyring_uri_t *parsed)
{
    const char *path_start, *query_start;
    char *path_copy = NULL;
    int result = 0;

    if (uri_str == NULL || parsed == NULL)
        return 0;

    keyring_uri_init(parsed);

    /* Check for keyring: scheme */
    if (strncmp(uri_str, KEYRING_URI_SCHEME ":", KEYRING_URI_SCHEME_LEN + 1) != 0) {
        keyring_error(0, KEYRING_ERR_INVALID_URI,
                     "URI does not start with '%s:'", KEYRING_URI_SCHEME);
        return 0;
    }

    /* Skip scheme */
    path_start = uri_str + KEYRING_URI_SCHEME_LEN + 1;

    /* Find query separator */
    query_start = strchr(path_start, '?');

    /* Parse path attributes (semicolon-separated) */
    if (query_start != NULL) {
        size_t path_len = query_start - path_start;
        path_copy = keyring_malloc(path_len + 1);
        if (path_copy == NULL)
            goto cleanup;
        memcpy(path_copy, path_start, path_len);
        path_copy[path_len] = '\0';

        if (!parse_attributes(parsed, path_copy, ';'))
            goto cleanup;

        /* Parse query attributes (ampersand-separated) */
        if (!parse_attributes(parsed, query_start + 1, '&'))
            goto cleanup;
    } else {
        /* No query part */
        if (!parse_attributes(parsed, path_start, ';'))
            goto cleanup;
    }

    /* Validate parsed URI */
    if (!keyring_uri_validate(parsed))
        goto cleanup;

    result = 1;

cleanup:
    keyring_free(path_copy);
    if (!result)
        keyring_uri_free(parsed);
    return result;
}
