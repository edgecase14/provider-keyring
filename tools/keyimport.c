/* SPDX-License-Identifier: Apache-2.0 */
/*
 * keyimport - Import existing PEM/DER keys to kernel keyring
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
    fprintf(stderr, "Usage: %s -i <file> -k <description> [options]\n", prog);
    fprintf(stderr, "\nRequired:\n");
    fprintf(stderr, "  -i, --input <file>        Input key file (PEM or DER format)\n");
    fprintf(stderr, "  -k, --description <name>  Key description in keyring\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -r, --keyring <type>      Target keyring (session, user, persistent)\n");
    fprintf(stderr, "                            Default: user\n");
    fprintf(stderr, "  -h, --help                Show this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -i server.key -k imported-server-key\n", prog);
    fprintf(stderr, "  %s -i key.pem -k my-key -r session\n", prog);
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
    const char *input_file = NULL;
    const char *description = NULL;
    const char *keyring_str = "user";
    key_serial_t keyring_id;
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_der = NULL;
    int pubkey_der_len;
    key_serial_t key_id;
    int result = 1;

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"description", required_argument, 0, 'k'},
        {"keyring", required_argument, 0, 'r'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "i:k:r:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            input_file = optarg;
            break;
        case 'k':
            description = optarg;
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
    if (input_file == NULL) {
        fprintf(stderr, "Error: Input file is required (-i)\n\n");
        usage(argv[0]);
        return 1;
    }

    if (description == NULL) {
        fprintf(stderr, "Error: Key description is required (-k)\n\n");
        usage(argv[0]);
        return 1;
    }

    printf("Importing key from %s...\n", input_file);

    /* Read key from file */
    fp = fopen(input_file, "rb");
    if (fp == NULL) {
        perror("fopen");
        fprintf(stderr, "Error: Failed to open %s\n", input_file);
        return 1;
    }

    /* Try PEM format first */
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pkey == NULL) {
        /* Try DER format */
        rewind(fp);
        pkey = d2i_PrivateKey_fp(fp, NULL);
    }

    fclose(fp);
    fp = NULL;

    if (pkey == NULL) {
        fprintf(stderr, "Error: Failed to read key from file\n");
        fprintf(stderr, "Supported formats: PEM, DER\n");
        goto cleanup;
    }

    /* Verify it's an RSA key */
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        fprintf(stderr, "Error: Only RSA keys are currently supported\n");
        goto cleanup;
    }

    printf("Key loaded successfully\n");
    printf("Key type: RSA\n");
    printf("Key size: %d bits\n", EVP_PKEY_bits(pkey));

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

    printf("\nKey successfully imported to keyring!\n\n");
    printf("Serial ID:    %d (0x%x)\n", key_id, key_id);
    printf("Description:  %s\n", description);
    printf("\nKeyring URIs:\n");
    printf("  keyring:id=%x;type=private\n", key_id);
    printf("  keyring:object=%s;type=private\n", description);
    printf("\nNote: Only the public key is stored in the keyring.\n");
    printf("The private key remains in the original file.\n");

    result = 0;

cleanup:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pubkey_der != NULL)
        OPENSSL_free(pubkey_der);
    if (fp != NULL)
        fclose(fp);

    return result;
}
