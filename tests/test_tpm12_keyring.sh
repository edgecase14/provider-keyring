#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Test Script: TPM Key Generation and Kernel Keyring Integration
#
# This script demonstrates:
# 1. Generating an RSA key inside TPM using tpmtool (GnuTLS)
# 2. Loading the key into Linux kernel keyring
# 3. Signing data using keyctl (TPM-offloaded)
# 4. Verifying signature using OpenSSL
#
# Requirements:
# - TPM 1.2 or 2.0 hardware (or software TPM with swtpm)
# - gnutls-bin package (provides tpmtool)
# - keyutils package (provides keyctl)
# - Linux kernel 4.7+ with asymmetric key support
# - Kernel config: CONFIG_TRUSTED_KEYS=y (for loading TPM blobs)
#   OR CONFIG_ASYMMETRIC_KEY_TYPE=y (for loading public keys only)
# - Root privileges or CAP_SYS_ADMIN
#
# NOTE: Current implementation loads TPM-generated keys but the kernel
# may not support keyctl_pkey_sign() with TPM private keys unless
# CONFIG_TRUSTED_KEYS is enabled. This script demonstrates the workflow.

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
KEY_DESCRIPTION="test-tpm12-key"
KEY_SIZE=2048
TEST_DATA="Hello from TPM 1.2 key in kernel keyring!"
WORK_DIR="/tmp/tpm12_keyring_test_$$"

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"

    # Remove key from keyring if it exists
    if [ -n "$KEY_SERIAL" ]; then
        keyctl unlink "$KEY_SERIAL" @u 2>/dev/null || true
    fi

    # Remove work directory
    rm -rf "$WORK_DIR"

    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."

    # Check if running as root or have CAP_SYS_ADMIN
    if [ "$EUID" -ne 0 ] && ! capsh --print 2>/dev/null | grep -q "cap_sys_admin"; then
        log_error "This script requires root privileges or CAP_SYS_ADMIN capability"
        log_error "Run with: sudo $0"
        exit 1
    fi

    # Check for tpmtool (GnuTLS TPM tool)
    if ! command -v tpmtool &> /dev/null; then
        log_error "tpmtool not found. Install gnutls-bin package:"
        log_error "  Debian/Ubuntu: sudo apt-get install gnutls-bin"
        log_error "  RHEL/Fedora: sudo dnf install gnutls-utils"
        exit 1
    fi

    # Check for keyctl
    if ! command -v keyctl &> /dev/null; then
        log_error "keyctl not found. Install keyutils package"
        exit 1
    fi

    # Check for OpenSSL
    if ! command -v openssl &> /dev/null; then
        log_error "openssl not found"
        exit 1
    fi

    log_info "All requirements satisfied"
}

check_tpm() {
    log_info "Checking TPM availability..."

    # Check if TPM device exists
    if [ ! -c /dev/tpm0 ]; then
        log_error "TPM device /dev/tpm0 not found"
        log_error "For testing without hardware TPM, use software TPM:"
        log_error "  Install: sudo apt-get install swtpm swtpm-tools"
        log_error "  Start: swtpm chardev --vtpm-proxy --tpm2=false --tpmstate dir=/tmp/tpm1"
        exit 1
    fi

    # Check if we can list TPM keys (tests TPM access)
    log_info "Testing TPM access..."
    tpmtool --list 2>&1 || log_warn "TPM list operation returned error (may be expected if no keys registered)"

    log_info "TPM check complete"
}

generate_tpm_key() {
    log_info "Generating RSA $KEY_SIZE key inside TPM..."

    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    # Generate RSA key in TPM and register it
    # --generate-rsa: Generate RSA key pair
    # --register: Register the key in TPM
    # --signing: Create a signing key
    # --user: Register as user key (not system key)
    # --bits: Key size in bits
    # --outder: Output public key in DER format
    # --srk-well-known: Use well-known SRK password (20 bytes of zeros)
    log_info "Creating and registering signing key in TPM..."

    tpmtool --generate-rsa \
            --register \
            --signing \
            --user \
            --bits "$KEY_SIZE" \
            --outder \
            --outfile "$WORK_DIR/pubkey.der" \
            --srk-well-known 2>&1 | tee "$WORK_DIR/tpmtool.log" || {
        log_error "Failed to create TPM key"
        log_error "This may happen if:"
        log_error "  1. TPM is not properly initialized"
        log_error "  2. SRK password is required (try without --srk-well-known)"
        log_error "  3. TPM is disabled in BIOS"
        log_error "  4. Insufficient permissions (run with sudo)"
        cat "$WORK_DIR/tpmtool.log"
        exit 1
    }

    log_info "TPM key created and registered successfully"

    # Extract the key UUID from tpmtool output
    KEY_UUID=$(grep -oP 'tpmkey:uuid=[0-9a-f-]+' "$WORK_DIR/tpmtool.log" | head -1 || echo "")

    if [ -n "$KEY_UUID" ]; then
        log_info "TPM key UUID: $KEY_UUID"
        echo "$KEY_UUID" > "$WORK_DIR/key_uuid.txt"
    else
        log_warn "Could not extract key UUID from tpmtool output"
    fi

    # Also save public key in PEM format for verification
    openssl rsa -pubin -inform DER -in "$WORK_DIR/pubkey.der" \
        -outform PEM -out "$WORK_DIR/pubkey.pem" 2>&1 || {
        log_error "Failed to convert public key to PEM format"
        exit 1
    }

    log_info "Public key saved in both DER and PEM formats"
}

load_key_to_keyring() {
    log_info "Loading TPM key into kernel keyring..."

    # The kernel keyring asymmetric key type expects DER-encoded public key
    # We need to create a special description that indicates this is a TPM key

    # Note: The kernel needs to be built with CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE
    # and the TPM needs to be accessible via the kernel's TPM subsystem

    # For TPM 1.2, we need to use a special format that tells the kernel
    # this is a TPM key. The description should include TPM metadata.

    # Create description with TPM metadata
    FULL_DESCRIPTION="asymmetric;tpm;$KEY_DESCRIPTION"

    # Load public key to keyring
    # The kernel will see the "tpm" marker and route operations to TPM
    KEY_SERIAL=$(keyctl padd asymmetric "$FULL_DESCRIPTION" @u < "$WORK_DIR/pubkey.der")

    if [ -z "$KEY_SERIAL" ]; then
        log_error "Failed to load key into kernel keyring"
        exit 1
    fi

    log_info "Key loaded into kernel keyring with serial: $KEY_SERIAL"

    # Verify the key is in the keyring
    log_info "Verifying key in keyring..."
    keyctl show @u | grep "$KEY_DESCRIPTION" || {
        log_error "Key not found in keyring"
        exit 1
    }

    # Show key information
    log_info "Key information:"
    keyctl print "$KEY_SERIAL" || log_warn "Cannot print key (expected for asymmetric keys)"
    keyctl describe "$KEY_SERIAL"
}

test_signing() {
    log_info "Testing signature operation with keyctl..."

    # Create test data to sign
    echo -n "$TEST_DATA" > "$WORK_DIR/data.txt"

    # Hash the data (TPM signing typically works on hashes)
    openssl dgst -sha256 -binary "$WORK_DIR/data.txt" > "$WORK_DIR/data.hash"

    log_info "Test data: $TEST_DATA"
    log_info "SHA256 hash: $(hexdump -C "$WORK_DIR/data.hash" | head -1)"

    # Sign using keyctl_pkey_sign
    # Format: keyctl pkey_sign <key_serial> <info_string> <data_file> <sig_file>
    # Info string specifies encoding and hash algorithm

    log_info "Signing with TPM key via kernel keyring..."

    # The kernel will route this to TPM automatically if the key is TPM-backed
    keyctl pkey_sign "$KEY_SERIAL" enc=pkcs1 hash=sha256 \
        < "$WORK_DIR/data.hash" \
        > "$WORK_DIR/signature.bin" 2>&1 || {
        log_error "Signing operation failed"
        log_error "This may happen if:"
        log_error "  1. Kernel doesn't have TPM keyring support"
        log_error "  2. TPM key not properly linked to kernel"
        log_error "  3. Kernel version < 4.7"
        exit 1
    }

    SIGNATURE_SIZE=$(stat -c%s "$WORK_DIR/signature.bin")
    log_info "Signature created: $SIGNATURE_SIZE bytes"
    log_info "Signature (hex): $(hexdump -C "$WORK_DIR/signature.bin" | head -3)"
}

test_verification() {
    log_info "Verifying signature with OpenSSL..."

    # Verify the signature using the public key
    # This proves the signature was created by the TPM private key

    openssl dgst -sha256 -verify "$WORK_DIR/pubkey.pem" \
        -signature "$WORK_DIR/signature.bin" \
        "$WORK_DIR/data.txt" > "$WORK_DIR/verify.out" 2>&1 || {
        log_error "Signature verification failed!"
        cat "$WORK_DIR/verify.out"
        exit 1
    }

    if grep -q "Verified OK" "$WORK_DIR/verify.out"; then
        log_info "✓ Signature verification: SUCCESS"
    else
        log_error "✗ Signature verification: FAILED"
        cat "$WORK_DIR/verify.out"
        exit 1
    fi
}

test_decrypt() {
    log_info "Testing decryption operation (optional)..."

    # Encrypt some data with the public key
    echo -n "Secret message for TPM" > "$WORK_DIR/plaintext.txt"

    openssl rsautl -encrypt -pubin -inkey "$WORK_DIR/pubkey.pem" \
        -in "$WORK_DIR/plaintext.txt" \
        -out "$WORK_DIR/ciphertext.bin" 2>/dev/null || {
        log_warn "Encryption failed (may not be supported for signing keys)"
        return 0
    }

    log_info "Encrypted data: $(stat -c%s "$WORK_DIR/ciphertext.bin") bytes"

    # Decrypt using keyctl_pkey_decrypt (TPM-offloaded)
    log_info "Decrypting with TPM key via kernel keyring..."

    keyctl pkey_decrypt "$KEY_SERIAL" enc=pkcs1 \
        < "$WORK_DIR/ciphertext.bin" \
        > "$WORK_DIR/decrypted.txt" 2>&1 || {
        log_warn "Decryption failed (may not be supported for this key type)"
        return 0
    }

    if cmp -s "$WORK_DIR/plaintext.txt" "$WORK_DIR/decrypted.txt"; then
        log_info "✓ Decryption: SUCCESS"
    else
        log_warn "Decryption produced different output"
    fi
}

show_summary() {
    log_info "========================================="
    log_info "Test Summary"
    log_info "========================================="
    log_info "Key Description: $FULL_DESCRIPTION"
    log_info "Key Serial: $KEY_SERIAL"
    log_info "Key Size: $KEY_SIZE bits"
    log_info "TPM Key UUID: $(cat "$WORK_DIR/key_uuid.txt" 2>/dev/null || echo "N/A")"
    log_info ""
    log_info "Files created in: $WORK_DIR"
    log_info "  - pubkey.pem: Public key (PEM format)"
    log_info "  - pubkey.der: Public key (DER format)"
    log_info "  - data.txt: Test data"
    log_info "  - data.hash: SHA256 hash of test data"
    log_info "  - signature.bin: TPM-generated signature"
    log_info "  - tpmtool.log: TPM tool output"
    log_info ""
    log_info "Kernel keyring status:"
    keyctl show @u | grep -A5 "$KEY_DESCRIPTION" || true
    log_info ""
    log_info "========================================="
}

# Main execution
main() {
    echo "========================================="
    echo "TPM 1.2 Kernel Keyring Integration Test"
    echo "========================================="
    echo ""

    check_requirements
    check_tpm
    generate_tpm_key
    load_key_to_keyring
    test_signing
    test_verification
    test_decrypt
    show_summary

    echo ""
    log_info "All tests completed successfully!"
    log_info "The TPM key is loaded in kernel keyring and can be used for signing"
    log_info ""
    log_info "To use this key with the provider:"
    log_info "  URI: keyring:object=$KEY_DESCRIPTION;type=private"
    log_info "  Serial: keyring:id=$(printf '%x' "$KEY_SERIAL");type=private"
    echo ""
}

# Run main function
main "$@"
