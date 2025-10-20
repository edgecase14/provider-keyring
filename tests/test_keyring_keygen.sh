#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Test script for keyring-keygen utility
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
KEYGEN="${KEYGEN:-./build/bin/keyring-keygen}"
TEST_KEY_PREFIX="test-keygen-$$"
OPENSSL_MODULES="${OPENSSL_MODULES:-./build/lib}"

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    echo "Cleaning up test keys..."
    keyctl list @u | grep "$TEST_KEY_PREFIX" | while read -r line; do
        key_id=$(echo "$line" | awk -F: '{print $1}')
        keyctl unlink "$key_id" @u 2>/dev/null || true
    done
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Test function
test_case() {
    local test_name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "${YELLOW}[TEST $TESTS_RUN]${NC} $test_name"
}

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}[FAIL]${NC} $1"
    return 1
}

# Check prerequisites
if [ ! -f "$KEYGEN" ]; then
    echo -e "${RED}ERROR:${NC} keyring-keygen not found at $KEYGEN"
    echo "Run 'make utils' to build it"
    exit 1
fi

if ! command -v keyctl >/dev/null 2>&1; then
    echo -e "${RED}ERROR:${NC} keyctl command not found"
    echo "Install keyutils package"
    exit 1
fi

echo "========================================"
echo "Testing keyring-keygen utility"
echo "========================================"
echo ""

# Test 1: Generate 2048-bit key with default options
test_case "Generate 2048-bit RSA key with default options"
KEY_NAME="${TEST_KEY_PREFIX}-default"
if $KEYGEN -b 2048 -d "$KEY_NAME" >/dev/null 2>&1; then
    if keyctl list @u | grep -q "$KEY_NAME"; then
        pass "Key generated and loaded into keyring"
    else
        fail "Key not found in keyring"
    fi
else
    fail "Key generation failed"
fi
echo ""

# Test 2: Generate 4096-bit key
test_case "Generate 4096-bit RSA key"
KEY_NAME="${TEST_KEY_PREFIX}-4096"
if $KEYGEN -b 4096 -d "$KEY_NAME" >/dev/null 2>&1; then
    if keyctl list @u | grep -q "$KEY_NAME"; then
        pass "4096-bit key generated successfully"
    else
        fail "4096-bit key not found in keyring"
    fi
else
    fail "4096-bit key generation failed"
fi
echo ""

# Test 3: Test with session keyring
test_case "Generate key in session keyring"
KEY_NAME="${TEST_KEY_PREFIX}-session"
# Run in a keyctl session to ensure we have a valid session keyring
if keyctl session test-session bash -c "$KEYGEN -b 2048 -d $KEY_NAME -k @s && keyctl list @s | grep -q $KEY_NAME" >/dev/null 2>&1; then
    pass "Key loaded into session keyring"
else
    fail "Key generation to session keyring failed"
fi
echo ""

# Test 4: Verify key is stored with correct attributes
test_case "Verify key stored with correct attributes"
KEY_NAME="${TEST_KEY_PREFIX}-verify"
if $KEYGEN -b 2048 -d "$KEY_NAME" >/dev/null 2>&1; then
    # Check if key exists in keyring with correct description
    if keyctl list @u | grep -q "$KEY_NAME"; then
        # Check if it's marked as asymmetric type
        if keyctl list @u | grep "$KEY_NAME" | grep -q "asymmetric"; then
            pass "Key stored with correct type and description"
        else
            fail "Key not stored as asymmetric type"
        fi
    else
        fail "Key not found in keyring"
    fi
else
    fail "Key generation failed"
fi
echo ""

# Test 5: Error handling - missing description
test_case "Error handling - missing description"
if $KEYGEN -b 2048 2>/dev/null; then
    fail "Should fail without description"
else
    pass "Correctly rejected missing description"
fi
echo ""

# Test 6: Error handling - invalid key size
test_case "Error handling - invalid key size"
KEY_NAME="${TEST_KEY_PREFIX}-invalid"
if $KEYGEN -b 512 -d "$KEY_NAME" 2>/dev/null; then
    fail "Should reject key size < 1024"
else
    pass "Correctly rejected invalid key size"
fi
echo ""

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Tests run:    $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
else
    echo -e "Tests failed: $TESTS_FAILED"
fi
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
