/* SPDX-License-Identifier: Apache-2.0 */
/*
 * keygen - Generate RSA keys and store in kernel keyring
 */

#include "../include/keyring_provider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <keyutils.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -k <description> -b <bits> [options]\n", prog);
    fprintf(stderr, "\nRequired:\n");
    fprintf(stderr, "  -k, --description <name>  Key description/label\n");
    fprintf(stderr, "  -b, --bits <size>         Key size in bits (2048, 3072, 4096)\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -t, --tpm                 Generate key in TPM (not yet implemented)\n");
    fprintf(stderr, "  -r, --keyring <type>      Target keyring (session, user, persistent)\n");
    fprintf(stderr, "                            Default: user\n");
    fprintf(stderr, "  -h, --help                Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -k my-server-key -b 2048\n", prog);
    fprintf(stderr, "  %s -k test-key -b 4096 -r session\n", prog);
}

static key_serial_t get_keyring_id(const char *keyring_str)
{
    if (keyring_str == NULL || strcmp(keyring_str, "user") == 0) {
        return KEY_SPEC_USER_KEYRING;
    } else if (strcmp(keyring_str, "session") == 0) {
        return KEY_SPEC_SESSION_KEYRING;
    } else if (strcmp(keyring_str, "persistent") == 0) {
#ifdef KEY_SPEC_PERSISTENT_KEYRING
        return KEY_SPEC_PERSISTENT_KEYRING;
#else
        fprintf(stderr, "Warning: Persistent keyring not supported, using user keyring\n");
        return KEY_SPEC_USER_KEYRING;
#endif
    }

    return KEY_SPEC_USER_KEYRING;
}

int main(int argc, char **argv)
{
    int opt;
    const char *description = NULL;
    int key_bits = 0;
    int use_tpm = 0;
    const char *keyring_str = "user";
    key_serial_t keyring_id;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char *pubkey_der = NULL;
    int pubkey_der_len;
    key_serial_t key_id;
    int result = 1;

    static struct option long_options[] = {
        {"description", required_argument, 0, 'k'},
        {"bits", required_argument, 0, 'b'},
        {"tpm", no_argument, 0, 't'},
        {"keyring", required_argument, 0, 'r'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "k:b:tr:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'k':
            description = optarg;
            break;
        case 'b':
            key_bits = atoi(optarg);
            break;
        case 't':
            use_tpm = 1;
            break;
        case 'r':
            keyring_str = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Validate required arguments */
    if (description == NULL) {
        fprintf(stderr, "Error: Key description is required (-k)\n\n");
        usage(argv[0]);
        return 1;
    }

    if (key_bits == 0) {
        fprintf(stderr, "Error: Key size is required (-b)\n\n");
        usage(argv[0]);
        return 1;
    }

    if (key_bits != 2048 && key_bits != 3072 && key_bits != 4096) {
        fprintf(stderr, "Error: Key size must be 2048, 3072, or 4096 bits\n");
        return 1;
    }

    if (use_tpm) {
        fprintf(stderr, "Error: TPM key generation not yet implemented\n");
        fprintf(stderr, "For now, generate software keys only\n");
        return 1;
    }

    printf("Generating %d-bit RSA key...\n", key_bits);

    /* Generate RSA key pair using OpenSSL */
    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pkey_ctx == NULL) {
        fprintf(stderr, "Error: Failed to create PKEY context\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        fprintf(stderr, "Error: Failed to initialize keygen\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, key_bits) <= 0) {
        fprintf(stderr, "Error: Failed to set key size\n");
        goto cleanup;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        fprintf(stderr, "Error: Failed to generate key\n");
        goto cleanup;
    }

    printf("Key generated successfully\n");

    /* Convert public key to DER format */
    pubkey_der_len = i2d_PUBKEY(pkey, &pubkey_der);
    if (pubkey_der_len <= 0) {
        fprintf(stderr, "Error: Failed to serialize public key\n");
        goto cleanup;
    }

    /* Get target keyring */
    keyring_id = get_keyring_id(keyring_str);

    /* Add key to kernel keyring */
    printf("Adding key to %s keyring...\n", keyring_str);

    key_id = add_key("asymmetric", description, pubkey_der, pubkey_der_len, keyring_id);
    if (key_id < 0) {
        perror("add_key");
        fprintf(stderr, "Error: Failed to add key to keyring\n");
        fprintf(stderr, "Note: This operation typically requires root privileges or CAP_SYS_ADMIN\n");
        goto cleanup;
    }

    printf("\nKey successfully added to keyring!\n\n");
    printf("Serial ID:    %d (0x%x)\n", key_id, key_id);
    printf("Description:  %s\n", description);
    printf("Key Size:     %d bits\n", key_bits);
    printf("\nKeyring URIs:\n");
    printf("  keyring:id=%x;type=private\n", key_id);
    printf("  keyring:object=%s;type=private\n", description);
    printf("\nUsage example:\n");
    printf("  openssl dgst -sha256 -sign 'keyring:object=%s' -out sig.bin file.txt\n", description);

    result = 0;

cleanup:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pkey_ctx != NULL)
        EVP_PKEY_CTX_free(pkey_ctx);
    if (pubkey_der != NULL)
        OPENSSL_free(pubkey_der);

    return result;
}
