# Test Suite for Kernel Keyring OpenSSL Provider

This directory contains test scripts and documentation for the Linux kernel keyring OpenSSL provider.

## Quick Start

For first-time users, start here:

```bash
# Educational demo (no TPM required)
./tests/test_keyring_sign_verify.sh
```

Then read:
- **[QUICK_START.md](QUICK_START.md)** - Step-by-step guide for TPM testing
- **[TPM_TESTING.md](TPM_TESTING.md)** - Comprehensive architecture documentation

## Test Scripts

### Educational Demos

#### `test_keyring_sign_verify.sh` ✅ No TPM Required
Demonstrates kernel keyring signing interface with software keys.

**Purpose:**
- Shows how to load keys into kernel keyring
- Explains why software keys can't sign from keyring
- Demonstrates the difference between software and TPM keys

**Run:**
```bash
./tests/test_keyring_sign_verify.sh
```

**Expected:** Educational output explaining TPM vs software key architecture.

---

### TPM Integration Tests

#### `test_tpm12_keyring.sh` 🔐 Requires TPM 1.2
Complete end-to-end test of TPM 1.2 key generation and kernel keyring integration.

**What it does:**
1. Generates RSA key inside TPM 1.2 hardware
2. Extracts public key from TPM
3. Loads key into kernel keyring with TPM metadata
4. Signs data using `keyctl_pkey_sign()` (TPM-offloaded)
5. Verifies signature with OpenSSL
6. Tests decryption if supported

**Requirements:**
- TPM 1.2 hardware OR software TPM (swtpm)
- trousers package (tcsd daemon)
- tpm-tools package
- Linux kernel 4.7+ with CONFIG_TCG_TPM=y
- Root privileges or CAP_SYS_ADMIN

**Setup:**
```bash
# Install packages
sudo apt-get install trousers tpm-tools keyutils

# Start TPM daemon
sudo systemctl start tcsd

# Run test
sudo ./tests/test_tpm12_keyring.sh
```

**Expected:** All tests pass with signature verification success.

---

#### `test_tpm12_keyring_simple.sh` 🔐 Simplified Demo
Simplified version showing the concept without full TPM setup.

**Run:**
```bash
./tests/test_tpm12_keyring_simple.sh
```

**Note:** This will fail at the signing step (expected), but demonstrates the workflow.

---

## Unit Tests

### `test_basic.c`
Basic functionality tests for the provider.

**Compile and run:**
```bash
make test
./build/bin/test_basic
```

**Tests:**
- Key loading from kernel keyring
- URI parsing
- Memory management

---

### `test_uri_parser.c`
URI parsing tests.

**Compile and run:**
```bash
make test
./build/bin/test_uri_parser
```

**Tests:**
- Valid URI formats
- Parameter parsing
- Error handling
- Backward compatibility (deprecated backend parameter)

---

### `test_provider_load.c`
Provider loading tests.

**Compile and run:**
```bash
make test
OPENSSL_MODULES=./build/lib ./build/bin/test_provider_load
```

**Tests:**
- Provider registration
- Algorithm availability
- Basic crypto operations

---

## Documentation

### [QUICK_START.md](QUICK_START.md)
**For:** First-time users, quick testing

**Contains:**
- Educational demo walkthrough
- TPM 1.2 prerequisites and setup
- Manual TPM key creation steps
- Software TPM (swtpm) setup
- Troubleshooting common issues
- Kernel requirements

**Start here if:** You want to quickly test TPM integration.

---

### [TPM_TESTING.md](TPM_TESTING.md)
**For:** Developers, architects, deep understanding

**Contains:**
- Complete architecture explanation
- Software keys vs TPM keys comparison
- Kernel keyring signing flow diagrams
- Key lifecycle documentation
- Integration with OpenSSL provider
- Future work and implementation notes
- Troubleshooting guide

**Start here if:** You want to understand how everything works internally.

---

## Architecture Overview

### Kernel Keyring + TPM Integration

```
Application (OpenSSL)
    │
    ├─> openssl dgst -sign "keyring:object=mykey" data.txt
    │
    v
Provider (keyring-provider.so)
    │
    ├─> keyring_pkey_sign(key_serial, data, ...)
    │
    v
Kernel Keyring Subsystem
    │
    ├─> keyctl_pkey_sign(key_serial, "enc=pkcs1 hash=sha256", ...)
    │
    ├─> Kernel sees "tpm" in key description
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

### Key Differences from Traditional TPM Usage

| Aspect | Traditional TPM | This Provider |
|--------|----------------|---------------|
| Private Key | TPM blob on disk | Stays in TPM hardware |
| Public Key | Extracted on demand | Stored in kernel keyring |
| Signing | tpm_sign() userspace | keyctl_pkey_sign() kernel |
| Libraries | TrouSerS/tpm2-tss | Kernel keyring API |
| Persistence | File-based blobs | Kernel keyring (optional) |

---

## Testing Workflow

### For Development (No TPM)

```bash
# 1. Build provider
make clean
make

# 2. Run unit tests
./build/bin/test_basic
./build/bin/test_uri_parser
OPENSSL_MODULES=./build/lib ./build/bin/test_provider_load

# 3. Run educational demo
./tests/test_keyring_sign_verify.sh

# 4. Read documentation
less tests/QUICK_START.md
less tests/TPM_TESTING.md
```

---

### For Production (With TPM)

```bash
# 1. Setup TPM
sudo apt-get install trousers tpm-tools keyutils
sudo systemctl start tcsd
sudo tpm_takeownership -z

# 2. Run full integration test
sudo ./tests/test_tpm12_keyring.sh

# 3. Manual key creation (if needed)
# Follow QUICK_START.md "Manual TPM Key Setup" section

# 4. Use with OpenSSL
export OPENSSL_MODULES=/path/to/provider-keyring/build/lib
openssl dgst -sha256 -sign "keyring:object=mykey;type=private" -out sig.bin data.txt
```

---

## Troubleshooting

### Common Issues

**"keyctl: command not found"**
```bash
sudo apt-get install keyutils
```

**"tcsd: not found"**
```bash
sudo apt-get install trousers tpm-tools
sudo systemctl start tcsd
```

**"/dev/tpm0: No such file or directory"**
- Enable TPM in BIOS, or
- Use software TPM (swtpm) for testing
- Check kernel modules: `lsmod | grep tpm`

**"add_key: Permission denied"**
```bash
# Need root or CAP_SYS_ADMIN for keyring operations
sudo -E bash
```

**"keyctl_pkey_sign: Operation not supported"**
- Kernel version < 4.7, or
- Missing CONFIG_ASYMMETRIC_KEY_TYPE=y in kernel config

For more troubleshooting, see **QUICK_START.md** and **TPM_TESTING.md**.

---

## Future Work

### TPM Key Generation in `keygen` Tool

Currently, the `keygen` tool only generates software keys. To implement TPM key generation:

1. Add tpm2-tss or trousers library dependency
2. Implement TPM key creation in `tools/keygen.c`
3. Extract public key from TPM
4. Load to kernel with TPM marker
5. Optionally save TPM blob for persistence

See **TPM_TESTING.md** section "Future Work" for detailed implementation notes.

---

## References

- [Linux Kernel Keyring Documentation](https://www.kernel.org/doc/html/latest/security/keys/core.html)
- [TrouSerS TPM 1.2 User Guide](https://trousers.sourceforge.net/)
- [TPM2-Tools Documentation](https://github.com/tpm2-software/tpm2-tools)
- [keyctl man page](https://man7.org/linux/man-pages/man1/keyctl.1.html)
- [OpenSSL Provider Documentation](https://www.openssl.org/docs/man3.0/man7/provider.html)

---

## Contributing

When adding new tests:

1. Follow the existing naming convention (`test_*.sh` for shell scripts)
2. Make scripts executable: `chmod +x tests/test_*.sh`
3. Add error handling and cleanup functions
4. Document requirements and expected output
5. Update this README with the new test description

---

## License

All test scripts and documentation are licensed under Apache-2.0.
See LICENSE file in the project root.
