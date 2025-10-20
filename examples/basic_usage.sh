#!/bin/bash
# Basic usage example for OpenSSL Keyring Provider

set -e

PROVIDER_PATH="/data/home/jjackson/build/provider-keyring/build/lib"
WORK_DIR="/tmp/keyring_example"

echo "=========================================="
echo "OpenSSL Keyring Provider - Basic Example"
echo "=========================================="
echo

# Setup
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Step 1: Generate a new RSA key
echo "=== Step 1: Generate RSA Key ==="
openssl genrsa -out example_key.pem 2048 2>/dev/null
echo "✓ Generated 2048-bit RSA key"
echo

# Step 2: Convert to PKCS#8 DER format for keyring
echo "=== Step 2: Convert to PKCS#8 DER Format ==="
openssl pkcs8 -topk8 -inform PEM -outform DER \
  -in example_key.pem -out example_key.der -nocrypt 2>/dev/null
echo "✓ Converted to PKCS#8 DER format"
echo

# Step 3: Load into kernel keyring
echo "=== Step 3: Load Key into Kernel Keyring ==="
KEY_ID=$(keyctl padd asymmetric example_key @s < example_key.der)
echo "✓ Key loaded into session keyring"
echo "  Key ID: $KEY_ID"
echo

# Show keyring contents
echo "Current keyring contents:"
keyctl show | grep -A2 "Session Keyring" || keyctl show
echo

# Step 4: Encrypt some data
echo "=== Step 4: Encrypt Data ==="
echo "Secret message that needs encryption!" > plaintext.txt
echo "  Plaintext: $(cat plaintext.txt)"

OPENSSL_MODULES="$PROVIDER_PATH" \
openssl pkeyutl -provider keyring -provider default \
  -encrypt \
  -inkey "keyring:id=$KEY_ID;type=private" \
  -in plaintext.txt \
  -out ciphertext.bin \
  -pkeyopt rsa_padding_mode:pkcs1

echo "✓ Data encrypted"
echo "  Ciphertext size: $(stat -c%s ciphertext.bin) bytes"
echo

# Step 5: Decrypt the data
echo "=== Step 5: Decrypt Data ==="
OPENSSL_MODULES="$PROVIDER_PATH" \
openssl pkeyutl -provider keyring -provider default \
  -decrypt \
  -inkey "keyring:id=$KEY_ID;type=private" \
  -in ciphertext.bin \
  -out decrypted.txt

echo "✓ Data decrypted"
echo "  Decrypted: $(cat decrypted.txt)"

# Verify
if diff -q plaintext.txt decrypted.txt > /dev/null; then
    echo "✓ Verification: Plaintext matches decrypted text!"
else
    echo "✗ Verification failed!"
    exit 1
fi
echo

# Step 6: Sign some data
echo "=== Step 6: Sign Data ==="
echo "Important document to be signed" > document.txt

# Hash the document
openssl dgst -sha256 -binary document.txt > document.hash

# Sign the hash
OPENSSL_MODULES="$PROVIDER_PATH" \
openssl pkeyutl -provider keyring -provider default \
  -sign \
  -inkey "keyring:id=$KEY_ID;type=private" \
  -in document.hash \
  -out signature.bin \
  -pkeyopt digest:sha256

echo "✓ Document signed"
echo "  Signature size: $(stat -c%s signature.bin) bytes"
echo

# Step 7: Verify the signature
echo "=== Step 7: Verify Signature ==="
# Extract public key
openssl pkey -in example_key.pem -pubout -out pubkey.pem 2>/dev/null

# Verify
if openssl pkeyutl -verify \
  -pubin -inkey pubkey.pem \
  -in document.hash \
  -sigfile signature.bin \
  -pkeyopt digest:sha256 > /dev/null 2>&1; then
    echo "✓ Signature verified successfully!"
else
    echo "✗ Signature verification failed!"
    exit 1
fi
echo

# Cleanup
echo "=== Cleanup ==="
echo "Work directory: $WORK_DIR"
echo "(Files left in place for inspection)"
echo

echo "=========================================="
echo "✓ Example completed successfully!"
echo "=========================================="
echo
echo "Summary:"
echo "  - Generated RSA key and loaded into keyring"
echo "  - Encrypted and decrypted data using keyring key"
echo "  - Signed and verified document using keyring key"
echo "  - All operations performed in kernel space"
echo
echo "Next steps:"
echo "  - Try using different key IDs: keyring:id=$KEY_ID"
echo "  - Explore different padding modes: pkcs1, oaep, pss"
echo "  - Use key descriptions: keyring:object=example_key"
