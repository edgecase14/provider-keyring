# TPM + Kernel Keyring Testing Guide

This directory contains test scripts for TPM integration with the Linux kernel keyring.

## Test Scripts

### 1. `test_keyring_sign_verify.sh` - Educational Demo ✓ Ready to Run

**Purpose:** Demonstrates the kernel keyring signing interface without requiring TPM hardware.

**What it does:**
- Generates test RSA keys
- Loads keys into kernel keyring (various formats)
- Attempts signing with `keyctl_pkey_sign()`
- Explains why software keys can't sign from keyring
- Shows how TPM keys would work differently

**Requirements:**
- `keyutils` package
- `openssl`
- No special privileges needed

**Run:**
```bash
./tests/test_keyring_sign_verify.sh
```

**Expected result:** Educational output explaining TPM vs software key architecture.

---

### 2. `test_tpm12_keyring.sh` - Full TPM 1.2 Integration Test

**Purpose:** Complete end-to-end test of TPM 1.2 key generation and kernel keyring integration.

**What it does:**
1. Generates RSA key inside TPM 1.2 hardware
2. Extracts public key from TPM
3. Loads key into kernel keyring with TPM metadata
4. Signs data using `keyctl_pkey_sign()` (TPM-offloaded)
5. Verifies signature with OpenSSL
6. Tests decryption if supported

**Requirements:**
- TPM 1.2 hardware OR software TPM (swtpm)
- `trousers` package (tcsd daemon)
- `tpm-tools` package
- Linux kernel 4.7+ with CONFIG_TCG_TPM=y
- Root privileges or CAP_SYS_ADMIN

**Setup:**

#### For Hardware TPM:
```bash
# Install packages (Debian/Ubuntu)
sudo apt-get install trousers tpm-tools keyutils

# Start TPM daemon
sudo systemctl start tcsd

# Take ownership of TPM (if not already done)
sudo tpm_takeownership -z
```

#### For Software TPM (Testing):
```bash
# Install software TPM
sudo apt-get install swtpm swtpm-tools

# Start software TPM 1.2
mkdir -p /tmp/tpm1
swtpm chardev --vtpm-proxy --tpm2=false \
    --tpmstate dir=/tmp/tpm1 --ctrl type=unixio,path=/tmp/tpm1/ctrl &

# Start tcsd
sudo systemctl start tcsd
```

**Run:**
```bash
sudo ./tests/test_tpm12_keyring.sh
```

**Expected result:**
```
========================================
TPM 1.2 Kernel Keyring Integration Test
========================================

[INFO] Checking requirements...
[INFO] All requirements satisfied
[INFO] Checking TPM 1.2 availability...
[INFO] TPM check complete
[INFO] Generating RSA 2048 key inside TPM 1.2...
[INFO] TPM key created successfully
[INFO] TPM key handle: 12345678
[INFO] Public key extracted and converted to DER format
[INFO] Loading TPM key into kernel keyring...
[INFO] Key loaded into kernel keyring with serial: 987654321
[INFO] Testing signature operation with keyctl...
[INFO] Signing with TPM key via kernel keyring...
[INFO] Signature created: 256 bytes
[INFO] Verifying signature with OpenSSL...
[INFO] ✓ Signature verification: SUCCESS
[INFO] ✓ Decryption: SUCCESS
[INFO] All tests completed successfully!
```

---

### 3. `test_tpm12_keyring_simple.sh` - Simplified Demo

**Purpose:** Simplified version showing the concept without full TPM setup.

**Run:**
```bash
./tests/test_tpm12_keyring_simple.sh
```

**Note:** This will fail at the signing step (expected), but demonstrates the workflow.

---

## Understanding the Architecture

### Software Keys vs TPM Keys

#### Software Keys (Current `keygen` tool):
```
┌─────────────┐
│  OpenSSL    │ Generate key pair
│  EVP API    │
└──────┬──────┘
       │
       ├──> private_key.pem (on disk)
       │
       └──> public_key.der ──> add_key() ──> Kernel Keyring
                                              • Only public key stored
                                              • Can't sign from keyring
                                              • Need private key file for signing
```

#### TPM Keys (Future `keygen -t`):
```
┌─────────────┐
│     TPM     │ Generate key pair
│  Hardware   │
└──────┬──────┘
       │
       ├──> Private key STAYS in TPM (never exported)
       │
       └──> public_key.der ──> add_key("...;tpm;...") ──> Kernel Keyring
                                                           • Public key + TPM handle
                                                           • Kernel routes to /dev/tpm0
                                                           • CAN sign via keyctl_pkey_sign()
```

### Kernel Keyring Signing Flow

For TPM keys:
```
Application
    │
    ├─> keyctl_pkey_sign(key_serial, "enc=pkcs1 hash=sha256", data)
    │
    v
Kernel Keyring
    │
    ├─> Checks key type: "asymmetric;tpm;mykey"
    │   Sees "tpm" marker
    │
    v
TPM Subsystem (/dev/tpm0)
    │
    ├─> TPM performs RSA-SHA256-PKCS1 signing
    │   with internal private key
    │
    v
Signature returned to application
```

### Key Storage Locations

| Key Type | Private Key Location | Public Key Location | Signing Method |
|----------|---------------------|---------------------|----------------|
| Software | `/path/to/key.pem` | Kernel keyring | OpenSSL with file |
| TPM | TPM hardware (sealed) | Kernel keyring | `keyctl_pkey_sign()` |

---

## TPM Key Lifecycle

### 1. Generation (NOT YET IMPLEMENTED)
```bash
# Future implementation:
./build/bin/keygen -k mykey -t -b 2048 -r user

# Under the hood:
# 1. Call tpm_createkey() via trousers/tpm2-tss
# 2. Extract public key from TPM
# 3. Load to kernel: add_key("asymmetric", "asymmetric;tpm;mykey", pubkey_der)
# 4. Store TPM blob to disk (optional, for persistence)
```

### 2. Loading (Manual with tpm-tools)
```bash
# Generate key in TPM
tpm_createkey -s 2048 -e -w -l /tmp/mykey -z

# Load key to get handle
tpm_loadkey -p /tmp/mykey.blob -z
# Output: Key handle: 0x01000000

# Extract public key
tpm_getpubkey -k 0x01000000 -z > pubkey.pem

# Convert to DER
openssl rsa -pubin -in pubkey.pem -outform DER -out pubkey.der

# Load to kernel keyring with TPM marker
keyctl padd asymmetric "asymmetric;tpm;mykey" @u < pubkey.der
# Output: 123456789 (key serial)
```

### 3. Using for Signing
```bash
# Hash data
echo -n "Test data" | openssl dgst -sha256 -binary > data.hash

# Sign with TPM via kernel keyring
keyctl pkey_sign 123456789 enc=pkcs1 hash=sha256 < data.hash > signature.bin

# The kernel automatically:
# 1. Sees "tpm" in key description
# 2. Routes to /dev/tpm0
# 3. TPM signs with private key
# 4. Returns signature
```

### 4. Verification
```bash
# Extract public key from keyring
keyctl read 123456789 > keyring_pubkey.der

# Convert to PEM
openssl rsa -pubin -inform DER -in keyring_pubkey.der -out verify.pem

# Verify signature
echo -n "Test data" > original.txt
openssl dgst -sha256 -verify verify.pem -signature signature.bin original.txt
# Output: Verified OK
```

---

## Integration with OpenSSL Provider

Once TPM key generation is implemented, the provider will use it like this:

```c
// Load key via URI
OSSL_STORE_open("keyring:object=mykey;type=private");

// Provider loads key from kernel keyring:
key_serial_t key = keyctl_search(KEY_SPEC_USER_KEYRING, "asymmetric", "mykey", 0);

// Application signs data
EVP_PKEY_sign(...);

// Provider routes to kernel keyring:
keyring_pkey_sign(key_serial, data, data_len, sig, sig_len, "sha256", "pkcs1");

// Inside keyring_pkey_sign():
char info[128];
snprintf(info, sizeof(info), "enc=pkcs1 hash=%s", hash_algo);
keyctl_pkey_sign(key_serial, info, data, data_len, sig, sig_len);

// Kernel sees "tpm" in key description → routes to TPM → signature
```

---

## Troubleshooting

### "add_key: Bad message"
- The kernel doesn't recognize the key format
- Try X.509 certificate format instead of raw DER
- Check kernel has `CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y`

### "keyctl_pkey_sign: Operation not supported"
- Kernel doesn't have TPM keyring integration
- Check kernel version >= 4.7
- Verify `CONFIG_TCG_TPM=y` in kernel config

### "Key not found in keyring"
- Key may be in different keyring (session vs user vs persistent)
- Use `keyctl show` to list all keys
- Try `@s` (session) instead of `@u` (user)

### "TPM communication failed"
- Check /dev/tpm0 exists and is accessible
- Verify tcsd is running: `systemctl status tcsd`
- Check TPM is enabled in BIOS
- For swtpm, verify it's running: `ps aux | grep swtpm`

---

## Future Work

### To Implement TPM Key Generation in `keygen`:

1. **Add tpm2-tss or trousers library dependency**
   ```makefile
   TPM_LIBS = -ltspi  # For TPM 1.2
   # or
   TPM_LIBS = -ltss2-esys  # For TPM 2.0
   ```

2. **Implement generation in `tools/keygen.c`:**
   ```c
   if (use_tpm) {
       // Call TPM library to generate key
       tpm_key_handle = generate_tpm_key(key_bits);

       // Extract public key from TPM
       pubkey_der = extract_tpm_public_key(tpm_key_handle);

       // Load to kernel with TPM marker
       snprintf(description, sizeof(description), "asymmetric;tpm;%s", key_name);
       key_id = add_key("asymmetric", description, pubkey_der, pubkey_len, keyring_id);

       // Optionally save TPM blob for persistence
       save_tpm_blob(key_name, tpm_key_handle);
   }
   ```

3. **Add TPM blob persistence** (optional)
   - Save wrapped key blobs to `/var/lib/keyring-provider/tpm/`
   - Implement loader to re-import on boot
   - Create systemd service for automatic loading

---

## References

- [Linux Kernel Keyring Documentation](https://www.kernel.org/doc/html/latest/security/keys/core.html)
- [TrouSerS TPM 1.2 User Guide](https://trousers.sourceforge.net/)
- [TPM2-Tools Documentation](https://github.com/tpm2-software/tpm2-tools)
- [keyctl man page](https://man7.org/linux/man-pages/man1/keyctl.1.html)
