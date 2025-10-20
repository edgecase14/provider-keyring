/* SPDX-License-Identifier: Apache-2.0 */
/*
 * keyinfo - Display information about keys in kernel keyring
 */

#include "../include/keyring_provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <keyutils.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options] <keyring-uri>\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -p, --export-public    Export public key to stdout (PEM format)\n");
    fprintf(stderr, "  -h, --help             Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s 'keyring:object=my-key'\n", prog);
    fprintf(stderr, "  %s 'keyring:id=12345678'\n", prog);
    fprintf(stderr, "  %s -p 'keyring:object=server-key' > pubkey.pem\n", prog);
}

int main(int argc, char **argv)
{
    int opt;
    int export_public = 0;
    const char *uri_str;
    keyring_uri_t uri;
    keyring_key_ctx_t *key_ctx;
    int result = 1;

    static struct option long_options[] = {
        {"export-public", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "ph", long_options, NULL)) != -1) {
        switch (opt) {
        case 'p':
            export_public = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Check for URI argument */
    if (optind >= argc) {
        fprintf(stderr, "Error: Missing keyring URI\n\n");
        usage(argv[0]);
        return 1;
    }

    uri_str = argv[optind];

    /* Parse URI */
    if (!keyring_uri_parse(uri_str, &uri)) {
        fprintf(stderr, "Error: Invalid keyring URI: %s\n", uri_str);
        return 1;
    }

    /* Load key */
    key_ctx = keyring_key_new();
    if (key_ctx == NULL) {
        fprintf(stderr, "Error: Failed to allocate key context\n");
        keyring_uri_free(&uri);
        return 1;
    }

    if (uri.has_id) {
        if (!keyring_key_load_by_id(uri.id, key_ctx)) {
            fprintf(stderr, "Error: Failed to load key by ID %d\n", uri.id);
            goto cleanup;
        }
    } else if (uri.has_object) {
        if (!keyring_key_load_by_description(uri.object, uri.keyring, key_ctx)) {
            fprintf(stderr, "Error: Failed to load key '%s'\n", uri.object);
            goto cleanup;
        }
    } else {
        fprintf(stderr, "Error: URI must specify either 'id' or 'object'\n");
        goto cleanup;
    }

    /* Display key information */
    if (!export_public) {
        printf("Keyring Key Information\n");
        printf("=======================\n\n");
        printf("Serial ID:    %d (0x%x)\n", key_ctx->key_serial, key_ctx->key_serial);
        printf("Description:  %s\n", key_ctx->description ? key_ctx->description : "(none)");
        printf("Key Size:     %d bits\n", key_ctx->key_size);
        printf("\nKeyring URI:\n");
        printf("  keyring:id=%x;type=private\n", key_ctx->key_serial);
        if (key_ctx->description) {
            /* Extract simple name from description (format: type;subtype;name) */
            char *name = strchr(key_ctx->description, ';');
            if (name != NULL) {
                name = strchr(name + 1, ';');
                if (name != NULL) {
                    name++;
                    printf("  keyring:object=%s;type=private\n", name);
                }
            }
        }
        printf("\n");
    }

    /* Export public key if requested */
    if (export_public) {
        if (key_ctx->public_key != NULL && key_ctx->public_key_len > 0) {
            const unsigned char *p = key_ctx->public_key;
            EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, key_ctx->public_key_len);

            if (pkey != NULL) {
                PEM_write_PUBKEY(stdout, pkey);
                EVP_PKEY_free(pkey);
            } else {
                fprintf(stderr, "Error: Failed to parse public key\n");
                goto cleanup;
            }
        } else {
            fprintf(stderr, "Error: No public key data available\n");
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    keyring_key_free(key_ctx);
    keyring_uri_free(&uri);
    return result;
}
