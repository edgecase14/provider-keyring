#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Kernel Keyring Sign/Verify Test
#
# This script demonstrates how TPM keys WOULD work with kernel keyring.
# Since we can't actually test TPM signing without TPM hardware, this shows:
# 1. The correct format for loading keys
# 2. The keyctl interface for signing
# 3. What would happen with real TPM integration

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }

WORK_DIR="/tmp/keyring_test_$$"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

cleanup() {
    [ -n "$KEY_ID" ] && keyctl unlink "$KEY_ID" @u 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "========================================="
echo "Kernel Keyring Signing Interface Test"
echo "========================================="
echo ""

# Check requirements
if ! command -v keyctl &>/dev/null; then
    err "keyctl not found. Install: sudo apt-get install keyutils"
    exit 1
fi

log "Generating test RSA key pair..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem 2>&1 | grep -v "^\.\..*" || true
openssl rsa -in key.pem -pubout -out pubkey.pem 2>&1 | grep -v "^writing" || true

# Create test data
echo -n "Test data for signing" > data.txt
openssl dgst -sha256 -binary data.txt > data.hash

log "Test data: $(cat data.txt)"
log "SHA256: $(od -An -tx1 data.hash | tr -d ' \n' | head -c 64)"
log ""

# Try different key formats for kernel keyring
log "Attempting to load key into kernel keyring..."
log ""

warn "The Linux kernel asymmetric key type has specific requirements:"
warn "  • Must be X.509 certificate OR raw public key in specific format"
warn "  • Simple DER-encoded RSA public keys may not work"
warn "  • TPM keys use special kernel-internal format"
log ""

# Method 1: Try DER format
log "Method 1: DER-encoded public key"
openssl rsa -pubin -in pubkey.pem -outform DER -out pubkey.der 2>&1 | grep -v "^writing" || true

if KEY_ID=$(keyctl padd asymmetric "test-key-der" @u < pubkey.der 2>&1); then
    log "✓ Successfully loaded DER key with serial: $KEY_ID"
    keyctl describe "$KEY_ID"

    # Try to sign
    log ""
    log "Attempting to sign with keyctl_pkey_sign..."
    if keyctl pkey_sign "$KEY_ID" enc=pkcs1 hash=sha256 < data.hash > signature.bin 2>sign_err.txt; then
        log "✓ Signing succeeded! Size: $(stat -c%s signature.bin) bytes"

        # Verify
        if openssl dgst -sha256 -verify pubkey.pem -signature signature.bin data.txt 2>&1 | grep -q "Verified OK"; then
            log "✓ Signature verification: SUCCESS!"
        else
            warn "Signature verification failed"
        fi
    else
        warn "Signing failed (expected - no private key in keyring)"
        warn "Error: $(cat sign_err.txt 2>/dev/null || echo 'Unknown error')"
    fi

    keyctl unlink "$KEY_ID" @u 2>/dev/null || true
else
    warn "Failed to load DER key: $KEY_ID"
fi

log ""
log "Method 2: X.509 Self-signed certificate"

# Create self-signed cert (this format IS supported by kernel)
openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
    -subj "/CN=Test Key/O=Keyring Test" 2>&1 | grep -v "^\.\..*" || true

openssl x509 -in cert.pem -outform DER -out cert.der

if KEY_ID=$(keyctl padd asymmetric "test-cert" @u < cert.der 2>&1); then
    log "✓ Successfully loaded X.509 cert with serial: $KEY_ID"
    keyctl describe "$KEY_ID"

    log ""
    log "Attempting to sign with certificate key..."
    if keyctl pkey_sign "$KEY_ID" enc=pkcs1 hash=sha256 < data.hash > signature2.bin 2>sign_err2.txt; then
        log "✓ Signing succeeded! Size: $(stat -c%s signature2.bin) bytes"

        # Verify with cert
        openssl x509 -in cert.pem -pubkey -noout > cert_pubkey.pem
        if openssl dgst -sha256 -verify cert_pubkey.pem -signature signature2.bin data.txt 2>&1 | grep -q "Verified OK"; then
            log "✓ Signature verification: SUCCESS!"
        else
            warn "Signature verification failed"
        fi
    else
        warn "Signing failed (expected - no private key in keyring)"
        warn "Error: $(cat sign_err2.txt 2>/dev/null || echo 'Unknown error')"
    fi

    keyctl unlink "$KEY_ID" @u 2>/dev/null || true
else
    warn "Failed to load cert: $KEY_ID"
fi

log ""
log "========================================="
log "Understanding TPM + Kernel Keyring"
log "========================================="
log ""
log "Why signing fails in these tests:"
log "  1. We only loaded PUBLIC keys into the keyring"
log "  2. Private key material is needed for signing"
log "  3. Software keys don't store private material in keyring"
log ""
log "How TPM keys are DIFFERENT:"
log "  1. Private key lives in TPM hardware (never exported)"
log "  2. Kernel loads TPM key handle (not the key itself)"
log "  3. When you call keyctl_pkey_sign():"
log "     • Kernel sees this is a TPM key"
log "     • Kernel sends sign request to /dev/tpm0"
log "     • TPM performs signing with its internal private key"
log "     • Kernel returns signature to userspace"
log ""
log "Real TPM workflow:"
log "  1. tpm_createkey → generates key IN TPM"
log "  2. tpm_loadkey → loads TPM key, returns handle"
log "  3. tpm_getpubkey → extracts public key"
log "  4. keyctl padd asymmetric 'tpm;mykey' → load to kernel"
log "     (Kernel stores TPM handle internally)"
log "  5. keyctl pkey_sign → kernel routes to TPM"
log "  6. Signature returned (private key never left TPM)"
log ""
log "Key differences from software keys:"
log ""
log "Software Key:"
log "  keyring ──> [public key only]"
log "  file ──> [private key PEM]"
log "  signing ──> use private key file with OpenSSL"
log ""
log "TPM Key:"
log "  keyring ──> [public key + TPM handle]"
log "  TPM ──> [private key sealed in hardware]"
log "  signing ──> keyctl_pkey_sign → kernel → TPM → signature"
log ""
log "This provider uses the TPM approach for all keyring keys!"
log ""

log "For actual TPM testing, you need:"
log "  • TPM 1.2 or 2.0 hardware (or swtpm)"
log "  • Kernel built with CONFIG_TCG_TPM=y"
log "  • trousers (TPM 1.2) or tpm2-tools (TPM 2.0)"
log "  • Root/CAP_SYS_ADMIN privileges"
log ""
log "Run test_tpm12_keyring.sh for full TPM integration test"
log ""
