# OpenSSL Keyring Provider

An OpenSSL 3.x provider that enables RSA cryptographic operations using Linux kernel keyring asymmetric keys with TPM 1.2 hardware offload support.

## Features

- **RFC 7512-compatible URI scheme** for key identification
- **Linux kernel keyring integration** for asymmetric key storage
- **TPM 1.2 hardware offload** for sign/decrypt operations
- **Auto-detection** of TPM-backed vs software keys
- **Multiple keyring support** (session, user, persistent)
- **Full RSA operation support** (sign, verify, encrypt, decrypt)
- **Padding schemes**: PKCS#1 v1.5, PSS, OAEP
- **Future TPM2 support** architecture

## System Requirements

- Linux kernel 4.7+ (asymmetric key type support)
- OpenSSL 3.x (libcrypto)
- keyutils library
- trousers library (TPM 1.2 support)
- GCC compiler and make

## URI Scheme

Following RFC 7512 PKCS#11 URI format:

```
keyring:path-attributes[?query-attributes]
```

### Path Attributes (semicolon-separated)

- `id=<hex-serial>` - Keyring serial ID (e.g., `id=12345678`)
- `object=<description>` - Key description/label (e.g., `object=my-rsa-key`)
- `type=<key-type>` - Key type: `private`, `public`, `cert`
- `keyring=<name>` - Target keyring: `session`, `user`, `persistent` (default: search all)
- `backend=<tpm-version>` - TPM backend: `tpm1.2`, `tpm2`, `software`, `auto` (default: `auto`)

### Query Attributes (ampersand-separated)

- `pin-source=<uri>` - PIN/passphrase source for keyring operations
- `module-path=<path>` - Explicit path to TPM library

### Example URIs

```
keyring:id=3f2a9c01;type=private
keyring:object=server-key;type=private;backend=tpm1.2
keyring:object=test-key;keyring=user?pin-source=file:/etc/keyring.pin
keyring:id=12ab34cd;type=public;backend=auto
keyring:object=my-key
keyring:
```

## Building

```bash
make                    # Build provider, tools, and tests
make tools              # Build only key management tools
make tests              # Build only test suite
make test               # Run test suite
make install            # Install provider and tools
make clean              # Clean build artifacts
```

## Installation

```bash
sudo make install
```

This installs:
- Provider library to OpenSSL modules directory
- Key management tools to `/usr/local/bin/`

## Configuration

Add to your `openssl.cnf`:

```ini
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
keyring = keyring_sect

[default_sect]
activate = 1

[keyring_sect]
activate = 1
```

Or use environment variable:

```bash
export OPENSSL_MODULES=/path/to/provider/lib
```

## Key Management Tools

### keygen - Generate RSA keys in keyring

```bash
keygen -k <description> -b <bits> [-t] [-r <keyring>]

Options:
  -k <description>  Key description/label
  -b <bits>         Key size (2048, 3072, 4096)
  -t                Use TPM for key generation
  -r <keyring>      Target keyring (session, user, persistent)
```

Example:
```bash
keygen -k "my-server-key" -b 2048 -t
```

### keyimport - Import existing keys to keyring

```bash
keyimport -i <file> -k <description> [-r <keyring>]

Options:
  -i <file>         Input key file (PEM/DER)
  -k <description>  Key description in keyring
  -r <keyring>      Target keyring
```

Example:
```bash
keyimport -i server.key -k "imported-key"
```

### keyinfo - Display key information

```bash
keyinfo <uri>

Examples:
  keyinfo "keyring:object=my-key"
  keyinfo "keyring:id=12345678"
```

### keyattest - TPM key attestation

```bash
keyattest <uri> [-o <output-file>]

Options:
  -o <output-file>  Write attestation data to file

Example:
  keyattest "keyring:object=my-tpm-key;backend=tpm1.2" -o attestation.bin
```

## Usage Examples

### Sign data with keyring key

```bash
# Generate or import a key first
keygen -k "signing-key" -b 2048 -t

# Sign data
echo "data to sign" | openssl dgst -sha256 -sign "keyring:object=signing-key" \
  -out signature.bin

# Verify signature
echo "data to sign" | openssl dgst -sha256 -verify <(openssl pkey -pubin \
  -in <(keyinfo "keyring:object=signing-key" --export-public)) \
  -signature signature.bin
```

### Encrypt/Decrypt with keyring key

```bash
# Encrypt data
echo "secret data" | openssl pkeyutl -encrypt \
  -pubin -in <(keyinfo "keyring:object=my-key" --export-public) \
  -out encrypted.bin

# Decrypt data
openssl pkeyutl -decrypt -in encrypted.bin \
  -inkey "keyring:object=my-key"
```

### TLS with keyring keys

```bash
# Use keyring key in TLS server
openssl s_server -cert server.crt \
  -key "keyring:object=server-key;backend=tpm1.2" \
  -accept 4433
```

## Architecture

```
provider-keyring/
├── src/
│   ├── provider.c           # Provider entry point
│   ├── keyring_uri.c        # RFC 7512 URI parser
│   ├── keyring_loader.c     # Key loading logic
│   ├── keyring_rsa.c        # RSA keymgmt operations
│   ├── keyring_signature.c  # Sign/verify operations
│   ├── keyring_asym_cipher.c # Encrypt/decrypt operations
│   ├── keyring_tpm.c        # TPM 1.2 detection & offload
│   └── util.c               # Utility functions
├── include/
│   └── keyring_provider.h   # Internal headers
├── tools/
│   ├── keygen.c             # Key generation tool
│   ├── keyimport.c          # Key import tool
│   ├── keyinfo.c            # Key information tool
│   └── keyattest.c          # TPM attestation tool
└── tests/
    ├── test_provider.c      # Provider tests
    ├── test_uri.c           # URI parsing tests
    ├── test_keygen.c        # Key generation tests
    ├── test_sign.c          # Signature tests
    ├── test_encrypt.c       # Encryption tests
    └── test_tpm.c           # TPM tests
```

## TPM Support

### TPM 1.2

The provider automatically detects TPM-backed keys by examining the keyring key description. When a TPM-backed key is detected, cryptographic operations are offloaded to the TPM hardware using the kernel's `keyctl_pkey_*` functions.

Key operations:
- Sign: `keyctl_pkey_sign()`
- Decrypt: `keyctl_pkey_decrypt()`

### TPM2 (Future)

Architecture in place for TPM2 support via:
- `backend=tpm2` URI attribute
- tpm2-tss library integration
- Extended keyring metadata parsing

## Development

### Adding New Algorithms

1. Implement keymgmt dispatch table in `src/keyring_<algo>.c`
2. Implement signature/cipher operations
3. Register in `src/provider.c` query_operation
4. Add tests in `tests/test_<algo>.c`

### Debugging

Enable debug output:

```bash
export KEYRING_DEBUG=1
```

View keyring contents:

```bash
keyctl show
```

## License

Apache-2.0

## Contributing

Contributions welcome! Please ensure:
- Code follows existing style
- Tests pass: `make test`
- Documentation updated

## Security Considerations

- Keys in kernel keyring are protected by kernel security
- TPM-backed keys provide hardware-level security
- Private keys never leave the kernel/TPM
- Proper permissions required for keyring access

## Troubleshooting

### Provider not loading

```bash
# Check OpenSSL modules directory
pkg-config --variable=modulesdir libcrypto

# Verify provider installation
ls -l /usr/lib/x86_64-linux-gnu/ossl-modules/keyring.so

# Test provider load
openssl list -providers
```

### Key not found

```bash
# List keyring contents
keyctl show

# Search for key
keyctl search @u asymmetric "my-key-description"
```

### TPM not detected

```bash
# Check TPM availability
ls /dev/tpm*

# Check trousers daemon
systemctl status tcsd
```

## References

- [RFC 7512 - PKCS#11 URI Scheme](https://datatracker.ietf.org/doc/html/rfc7512)
- [OpenSSL Provider API](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [Linux Keyutils](https://man7.org/linux/man-pages/man7/keyutils.7.html)
- [TPM 1.2 Specification](https://trustedcomputinggroup.org/resource/tpm-main-specification/)
