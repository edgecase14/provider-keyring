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
make                    # Build provider and tests
make tests              # Build only test suite
make test               # Run test suite
make install            # Install provider
make clean              # Clean build artifacts
```

## Installation

```bash
sudo make install
```

This installs the provider library to the OpenSSL modules directory.

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

## Key Management with keyctl

The provider uses keys stored in the Linux kernel keyring. Use standard `keyctl` and `openssl` commands to manage keys.

### Generate and Add Keys to Keyring

```bash
# Generate an RSA key pair
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem

# Extract public key in DER format
openssl pkey -in private.pem -pubout -outform DER -out public.der

# Add public key to user keyring
keyctl padd asymmetric my-key-name @u < public.der

# The key is now available via URI
# keyring:object=my-key-name;type=private
```

### View Keys in Keyring

```bash
# List all keyrings
keyctl show

# List user keyring contents
keyctl show @u

# Search for a specific key
keyctl search @u asymmetric my-key-name

# Display key details
keyctl describe <key-id>

# Read key data (public key)
keyctl read <key-id>
```

### Remove Keys from Keyring

```bash
# Find key ID
KEY_ID=$(keyctl search @u asymmetric my-key-name)

# Revoke and unlink key
keyctl revoke $KEY_ID
keyctl unlink $KEY_ID @u
```

## Usage Examples

### Sign data with keyring key

```bash
# Generate and add a key first (see above)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl pkey -in private.pem -pubout -outform DER | keyctl padd asymmetric signing-key @u

# Sign data using the provider
echo "data to sign" > data.txt
openssl dgst -sha256 -sign "keyring:object=signing-key;type=private" \
  -out signature.bin data.txt

# Extract public key for verification
openssl pkey -in private.pem -pubout -out public.pem

# Verify signature
openssl dgst -sha256 -verify public.pem -signature signature.bin data.txt
```

### Decrypt data with keyring key

```bash
# Encrypt data with public key
openssl pkey -in private.pem -pubout -out public.pem
echo "secret data" > plaintext.txt
openssl pkeyutl -encrypt -pubin -inkey public.pem \
  -in plaintext.txt -out encrypted.bin

# Decrypt using keyring key via provider
openssl pkeyutl -decrypt -inkey "keyring:object=signing-key;type=private" \
  -in encrypted.bin -out decrypted.txt
```

### TLS with keyring keys

```bash
# Use keyring key in TLS server
openssl s_server -cert server.crt \
  -key "keyring:object=server-key;type=private" \
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
│   ├── keyring_pkey.c       # Kernel pkey operations
│   └── util.c               # Utility functions
├── include/
│   └── keyring_provider.h   # Internal headers
└── tests/
    ├── test_basic.c          # Basic functionality tests
    ├── test_uri_parser.c     # URI parsing tests
    └── test_provider_load.c  # Provider loading tests
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
