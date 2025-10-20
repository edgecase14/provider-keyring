/* SPDX-License-Identifier: Apache-2.0 */
/*
 * keyring-keygen - Generate RSA key and load into kernel keyring
 *
 * This utility combines the steps of:
 *   1. openssl genrsa -out key.pem <bits>
 *   2. openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8
 *   3. keyctl padd asymmetric <description> @u < key.pk8
 *
 * Into a single command.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <keyutils.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Generate RSA key and load into kernel keyring\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -b, --bits <size>        Key size in bits (default: 2048)\n");
    fprintf(stderr, "  -d, --description <name> Key description/name (required)\n");
    fprintf(stderr, "  -k, --keyring <type>     Target keyring: user, session, persistent (default: user)\n");
    fprintf(stderr, "  -h, --help               Show this help message\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s -b 2048 -d mykey\n", prog);
    fprintf(stderr, "  %s -b 4096 -d mykey -k session\n", prog);
    fprintf(stderr, "\n");
}

static key_serial_t parse_keyring_type(const char *type_str)
{
    if (strcmp(type_str, "session") == 0)
        return KEY_SPEC_SESSION_KEYRING;
    if (strcmp(type_str, "user") == 0)
        return KEY_SPEC_USER_KEYRING;
    if (strcmp(type_str, "persistent") == 0) {
#ifdef KEY_SPEC_PERSISTENT_KEYRING
        return KEY_SPEC_PERSISTENT_KEYRING;
#else
        fprintf(stderr, "Warning: persistent keyring not available, using user keyring\n");
        return KEY_SPEC_USER_KEYRING;
#endif
    }

    fprintf(stderr, "Invalid keyring type: %s\n", type_str);
    fprintf(stderr, "Valid types: user, session, persistent\n");
    exit(1);
}

static EVP_PKEY *generate_rsa_key(int bits)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize keygen\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "Failed to set RSA key bits\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static unsigned char *key_to_pkcs8_der(EVP_PKEY *pkey, size_t *der_len)
{
    unsigned char *der = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    int len;

    /* Convert to PKCS#8 PrivateKeyInfo structure */
    p8inf = EVP_PKEY2PKCS8(pkey);
    if (p8inf == NULL) {
        fprintf(stderr, "Failed to convert key to PKCS#8 format\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Get DER encoding length */
    len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
    if (len <= 0) {
        fprintf(stderr, "Failed to get DER length\n");
        ERR_print_errors_fp(stderr);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return NULL;
    }

    /* Allocate buffer for DER encoding */
    der = malloc((size_t)len);
    if (der == NULL) {
        fprintf(stderr, "Failed to allocate memory for DER encoding\n");
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return NULL;
    }

    /* Encode to DER format */
    unsigned char *p = der;
    if (i2d_PKCS8_PRIV_KEY_INFO(p8inf, &p) <= 0) {
        fprintf(stderr, "Failed to convert key to DER format\n");
        ERR_print_errors_fp(stderr);
        free(der);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return NULL;
    }

    PKCS8_PRIV_KEY_INFO_free(p8inf);
    *der_len = (size_t)len;
    return der;
}

static int load_key_to_keyring(const unsigned char *der, size_t der_len,
                                const char *description, key_serial_t keyring)
{
    key_serial_t key_id;

    key_id = add_key("asymmetric", description, der, der_len, keyring);
    if (key_id < 0) {
        perror("Failed to add key to keyring");
        return 0;
    }

    printf("Key loaded successfully:\n");
    printf("  Description: %s\n", description);
    printf("  Serial: 0x%08x\n", key_id);

    return 1;
}

int main(int argc, char *argv[])
{
    int bits = 2048;
    const char *description = NULL;
    const char *keyring_type = "user";
    key_serial_t keyring;
    EVP_PKEY *pkey = NULL;
    unsigned char *der = NULL;
    size_t der_len = 0;
    int ret = 0;

    static struct option long_options[] = {
        {"bits",        required_argument, 0, 'b'},
        {"description", required_argument, 0, 'd'},
        {"keyring",     required_argument, 0, 'k'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "b:d:k:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'b':
            bits = atoi(optarg);
            if (bits < 1024 || bits > 16384) {
                fprintf(stderr, "Invalid key size: %d (must be 1024-16384)\n", bits);
                exit(1);
            }
            break;
        case 'd':
            description = optarg;
            break;
        case 'k':
            keyring_type = optarg;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (description == NULL) {
        fprintf(stderr, "Error: Key description is required\n\n");
        usage(argv[0]);
        exit(1);
    }

    keyring = parse_keyring_type(keyring_type);

    printf("Generating %d-bit RSA key...\n", bits);
    pkey = generate_rsa_key(bits);
    if (pkey == NULL) {
        ret = 1;
        goto cleanup;
    }
    printf("Key generated successfully\n");

    printf("Converting to PKCS#8 DER format...\n");
    der = key_to_pkcs8_der(pkey, &der_len);
    if (der == NULL) {
        ret = 1;
        goto cleanup;
    }
    printf("Converted to DER format (%zu bytes)\n", der_len);

    printf("Loading key into keyring...\n");
    if (!load_key_to_keyring(der, der_len, description, keyring)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (der != NULL) {
        /* Clear sensitive key material */
        memset(der, 0, der_len);
        free(der);
    }

    return ret;
}
