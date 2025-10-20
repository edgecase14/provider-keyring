/* SPDX-License-Identifier: Apache-2.0 */
/*
 * keyattest - TPM attestation of keyring keys
 *
 * This tool performs TPM attestation operations on keys stored in the kernel
 * keyring. It demonstrates how to use trousers library for TPM operations
 * independently of the provider.
 */

#include "../include/keyring_provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <keyutils.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <keyring-uri> [options]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -o, --output <file>       Write attestation data to file\n");
    fprintf(stderr, "  -h, --help                Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s 'keyring:object=my-tpm-key;backend=tpm1.2'\n", prog);
    fprintf(stderr, "  %s 'keyring:id=12345678' -o attestation.bin\n", prog);
}

int main(int argc, char **argv)
{
    int opt;
    const char *uri_str;
    const char *output_file = NULL;
    keyring_uri_t uri;
    keyring_key_ctx_t *key_ctx;
    TSS_HCONTEXT hContext = 0;
    TSS_HTPM hTPM = 0;
    TSS_RESULT result;
    int ret = 1;

    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "o:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'o':
            output_file = optarg;
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
            fprintf(stderr, "Error: Failed to load key by ID\n");
            goto cleanup;
        }
    } else if (uri.has_object) {
        if (!keyring_key_load_by_description(uri.object, uri.keyring, key_ctx)) {
            fprintf(stderr, "Error: Failed to load key\n");
            goto cleanup;
        }
    } else {
        fprintf(stderr, "Error: URI must specify either 'id' or 'object'\n");
        goto cleanup;
    }

    /*
     * Note: This tool assumes the key is TPM-backed.
     * The kernel keyring no longer exposes backend detection, so users
     * should only use this tool with keys they know are TPM-backed.
     */

    printf("TPM Attestation\n");
    printf("===============\n\n");
    printf("Key Serial ID: %d (0x%x)\n", key_ctx->key_serial, key_ctx->key_serial);
    printf("Description:   %s\n\n", key_ctx->description ? key_ctx->description : "(unknown)");

    /* Initialize TPM */
    result = Tspi_Context_Create(&hContext);
    if (result != TSS_SUCCESS) {
        fprintf(stderr, "Error: Failed to create TSS context: 0x%x\n", result);
        goto cleanup;
    }

    result = Tspi_Context_Connect(hContext, NULL);
    if (result != TSS_SUCCESS) {
        fprintf(stderr, "Error: Failed to connect to TPM: 0x%x\n", result);
        fprintf(stderr, "Is tcsd daemon running?\n");
        goto cleanup;
    }

    result = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (result != TSS_SUCCESS) {
        fprintf(stderr, "Error: Failed to get TPM object: 0x%x\n", result);
        goto cleanup;
    }

    printf("TPM connection established\n\n");

    /*
     * TODO: Implement actual attestation operations
     *
     * This would involve:
     * 1. Creating an AIK (Attestation Identity Key)
     * 2. Using TPM_Quote to attest to the key
     * 3. Signing the attestation with the AIK
     * 4. Optionally saving attestation data to file
     *
     * For now, we just verify TPM connectivity and key type
     */

    printf("Attestation functionality is a placeholder.\n");
    printf("To fully implement, add:\n");
    printf("  - AIK creation/loading\n");
    printf("  - TPM_Quote operation\n");
    printf("  - Attestation signature verification\n");

    if (output_file != NULL) {
        printf("\nOutput file specified but not yet implemented: %s\n", output_file);
    }

    ret = 0;

cleanup:
    if (hContext != 0) {
        Tspi_Context_Close(hContext);
    }

    keyring_key_free(key_ctx);
    keyring_uri_free(&uri);
    return ret;
}
