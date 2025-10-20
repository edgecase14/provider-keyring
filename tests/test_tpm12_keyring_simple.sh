#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Simplified TPM 1.2 Key + Kernel Keyring Test
#
# This is a simplified version that demonstrates the concept without
# requiring actual TPM hardware. It shows how a TPM key would be loaded
# into the kernel keyring and used for signing.
#
# For actual TPM testing, use test_tpm12_keyring.sh

set -e

# Configuration
KEY_NAME="test-tpm12-key"
WORK_DIR="/tmp/tpm_keyring_test_$$"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

cleanup() {
    [ -n "$KEY_ID" ] && keyctl unlink "$KEY_ID" @u 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log "=== Simplified TPM Keyring Test ==="
log ""

# Check requirements
if ! command -v keyctl &>/dev/null; then
    echo "ERROR: keyctl not found. Install: sudo apt-get install keyutils"
    exit 1
fi

# Create work directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Step 1: Generate a key (simulating TPM generation)
log "Step 1: Generating RSA key (simulating TPM key generation)..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out private_key.pem

# Extract public key
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Convert public key to DER (required for kernel keyring)
openssl rsa -pubin -in public_key.pem -outform DER -out public_key.der

log "✓ Key pair generated"
log ""

# Step 2: Load public key into kernel keyring
log "Step 2: Loading key into kernel keyring..."

# For TPM keys, the description should include TPM metadata
# This tells the kernel to route operations to TPM
DESCRIPTION="asymmetric;tpm;$KEY_NAME"

# Load key into user keyring
KEY_ID=$(keyctl padd asymmetric "$DESCRIPTION" @u < public_key.der)

log "✓ Key loaded into kernel keyring"
log "  Key Serial: $KEY_ID"
log "  Description: $DESCRIPTION"
log ""

# Verify key is loaded
log "Kernel keyring contents:"
keyctl show @u | grep "$KEY_NAME" || warn "Key not visible in keyring"
log ""

# Step 3: Create test data
log "Step 3: Creating test data..."
echo -n "Hello from TPM key in kernel keyring" > data.txt

# Hash the data (kernel keyring operations work on pre-hashed data)
openssl dgst -sha256 -binary data.txt > data.hash

log "✓ Test data created and hashed"
log "  Data: $(cat data.txt)"
log "  Hash: $(hexdump -C data.hash | head -1)"
log ""

# Step 4: Sign using keyctl (would use TPM for real TPM keys)
log "Step 4: Signing with keyctl_pkey_sign()..."

warn "NOTE: This will likely FAIL because:"
warn "  1. The kernel needs the PRIVATE key for signing"
warn "  2. We only loaded the PUBLIC key into the keyring"
warn "  3. For real TPM keys, the kernel would access TPM via /dev/tpm0"
warn ""
warn "This demonstrates the INTERFACE, not actual functionality"
warn "For real TPM integration, the kernel must have TPM driver support"
log ""

# Try to sign (this will fail for software keys, but shows the interface)
if keyctl pkey_sign "$KEY_ID" enc=pkcs1 hash=sha256 \
    < data.hash > signature.bin 2>sign_error.txt; then

    log "✓ Signature created: $(stat -c%s signature.bin) bytes"
    log ""

    # Step 5: Verify signature
    log "Step 5: Verifying signature with OpenSSL..."
    if openssl dgst -sha256 -verify public_key.pem \
        -signature signature.bin data.txt 2>&1 | grep -q "Verified OK"; then
        log "✓ Signature verification: SUCCESS"
    else
        warn "Signature verification failed"
    fi
else
    warn "Signing failed (expected for software keys)"
    warn "Error: $(cat sign_error.txt)"
    log ""
    log "This is EXPECTED because:"
    log "  • The kernel keyring only has the PUBLIC key"
    log "  • Software keys cannot sign from keyring (no private material)"
    log "  • TPM keys WOULD work because kernel routes to /dev/tpm0"
fi

log ""
log "=== Understanding the Architecture ==="
log ""
log "For REAL TPM keys, the flow would be:"
log ""
log "1. Generate key IN TPM hardware:"
log "   tpm_createkey -s 2048 -e ..."
log ""
log "2. Extract public key from TPM:"
log "   tpm_getpubkey -k <handle> > pubkey.pem"
log ""
log "3. Load to kernel keyring with TPM marker:"
log "   keyctl padd asymmetric 'asymmetric;tpm;mykey' @u < pubkey.der"
log ""
log "4. Kernel detects 'tpm' in description and routes to TPM:"
log "   keyctl pkey_sign <serial> enc=pkcs1 hash=sha256"
log "   └─> Kernel sees 'tpm' marker"
log "       └─> Routes to /dev/tpm0"
log "           └─> TPM performs signing with private key"
log ""
log "5. Private key NEVER leaves TPM hardware"
log ""

log "=== Test Complete ==="
log ""
log "Files created in: $WORK_DIR"
log "  • private_key.pem - Private key (PEM)"
log "  • public_key.pem - Public key (PEM)"
log "  • public_key.der - Public key (DER - loaded to keyring)"
log "  • data.txt - Test data"
log "  • data.hash - SHA256 hash"
log ""

log "To see the key in keyring:"
log "  keyctl show @u | grep $KEY_NAME"
log ""
log "To unlink the key:"
log "  keyctl unlink $KEY_ID @u"
log ""
