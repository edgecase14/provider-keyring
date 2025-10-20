# TPM Key Blob Loading Investigation

## Goal
Load a TPM-generated private key blob into the Linux kernel keyring for use with `keyctl_pkey_sign()`.

## TPM Key Generation (Successful)

### Using tpmtool (GnuTLS)

```bash
# Generate TPM key and save blob
echo "" | tpmtool --generate-rsa --signing --bits 2048 \
    --outfile /tmp/tpm_key.blob --srk-well-known

# Output: TSS KEY BLOB in base64 PEM format
# File size: 821 bytes (ASCII text)
```

### Convert to Binary

```bash
# Extract base64 content and decode
sed -n '/-----BEGIN TSS KEY BLOB-----/,/-----END TSS KEY BLOB-----/p' /tmp/tpm_key.blob \
    | grep -v "BEGIN\|END" \
    | tr -d '\n' \
    | base64 -d > /tmp/tpm_key_binary.blob

# Result: 563 bytes binary blob
# Hex header: 04 82 02 2f 01 01 00 00 00 10 00 00 00 04...
```

## Kernel Keyring Loading Attempts

### Attempt 1: Load as "asymmetric" key type

```bash
cat /tmp/tpm_key_binary.blob | keyctl padd asymmetric "my-tpm-key" @u
# Result: add_key: Bad message
```

**Analysis**: Kernel's asymmetric key type expects X.509 certificates or specific public key formats (SubjectPublicKeyInfo), not TSS blobs.

### Attempt 2: Load as "trusted" key type

```bash
cat /tmp/tpm_key_binary.blob | keyctl padd trusted "my-tpm-key" @u
# Result: add_key: No such device
```

**Analysis**: Kernel doesn't have trusted keys support compiled in.

### Attempt 3: Load as "user" key type (successful but not useful)

```bash
cat /tmp/tpm_key_binary.blob | keyctl padd user "test-user-key" @u
# Result: 688038181 (success)
```

**Analysis**: Successfully loaded as generic user key, but `keyctl_pkey_sign()` won't work with "user" type keys.

## Kernel Configuration Analysis

### Current Kernel: 6.12.48+deb13-amd64

```bash
grep "ASYMMETRIC\|TPM_KEY\|TRUSTED_KEY" /boot/config-6.12.48+deb13-amd64
```

**Results**:
```
# CONFIG_TRUSTED_KEYS is not set                    ← Missing!
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
# CONFIG_INTEGRITY_TRUSTED_KEYRING is not set
CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y                        ← Present
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y              ← Present
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SECONDARY_TRUSTED_KEYRING=y
```

**Problem**: `CONFIG_TRUSTED_KEYS` is NOT enabled, which is required for loading TPM private key blobs.

## Key Types Overview

| Key Type | Purpose | Can Load TPM Blob? | Can Use keyctl_pkey_sign()? |
|----------|---------|-------------------|----------------------------|
| asymmetric | X.509 certs, public keys | ❌ No | ✅ Yes (with public keys only) |
| trusted | TPM-sealed keys | ❌ Not compiled | ✅ Yes (if enabled) |
| user | Generic binary data | ✅ Yes | ❌ No |
| keyring | Container for other keys | N/A | N/A |

## TPM Blob Format

The `tpmtool` generated blob is in TSS (TCG Software Stack) format:

```
Offset  Bytes   Description
------  ------  -----------
0x00    04 82   TPM structure tag
0x02    02 2f   Structure length (559 bytes)
0x04    ...     TPM_KEY structure (TSS 1.2 format)
```

This is NOT compatible with kernel's asymmetric key parser, which expects:
- X.509 certificates (DER encoded)
- SubjectPublicKeyInfo structures (DER encoded)

## Alternative Approaches

### Approach 1: Extract Public Key and Use Software Signing

1. Extract public key from TPM
2. Load public key into kernel keyring as asymmetric type
3. Use software (OpenSSL/GnuTLS) for signing operations
4. ❌ Defeats purpose - private key operations not in TPM

### Approach 2: Use PKCS#11 with TPM

1. Use p11tool or OpenSC for TPM access
2. OpenSSL can use PKCS#11 engine
3. ❌ Doesn't use kernel keyring

### Approach 3: Enable CONFIG_TRUSTED_KEYS

1. Recompile kernel with `CONFIG_TRUSTED_KEYS=y`
2. Load TPM blob as "trusted" key type
3. ✅ Should work for TPM 2.0
4. ⚠️  TPM 1.2 support may be limited

### Approach 4: Use IMA/EVM Keyring

1. Use `.ima` or `.evm` keyrings (integrity subsystem)
2. These may have different TPM integration
3. ❓ Requires investigation

## Questions for Further Investigation

1. **Does CONFIG_TRUSTED_KEYS support TPM 1.2 blobs from tpmtool?**
   - The trusted keys subsystem was designed primarily for TPM 2.0
   - TPM 1.2 support via TrouSerS may or may not be compatible

2. **Is there a kernel interface for loading TSS blobs?**
   - Check `/sys/kernel/security/` interfaces
   - Look for TPM-specific character devices beyond `/dev/tpm0`

3. **Can we convert TSS blob to a kernel-compatible format?**
   - Parse TSS blob structure
   - Extract relevant key material
   - Reconstruct in kernel-expected format
   - ❓ Complex and error-prone

4. **Does the kernel need the blob at all?**
   - Maybe kernel just needs public key + TPM handle reference
   - Kernel routes to `/dev/tpm0` for actual signing
   - Private key never leaves TPM anyway
   - ❓ Need to research kernel TPM subsystem architecture

## Current Status

### What Works ✅
- TPM key generation with `tpmtool`
- Extracting public key from TPM
- Loading public keys into kernel keyring (asymmetric type)
- `keyctl_pkey_*()` operations with software keys

### What Doesn't Work ❌
- Loading TPM private key blobs into kernel keyring
- `keyctl_pkey_sign()` with TPM-backed keys
- TPM-offloaded signing via kernel keyring

### Blocker 🚧
- Kernel config: `CONFIG_TRUSTED_KEYS` not enabled
- Need to either:
  1. Rebuild kernel with trusted keys support, OR
  2. Find alternative method for TPM + kernel keyring integration

## References

- [Linux Kernel Keyring Documentation](https://www.kernel.org/doc/html/latest/security/keys/core.html)
- [Trusted and Encrypted Keys](https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html)
- [GnuTLS TPM Support](https://gnutls.org/manual/html_node/Cryptographic-Message-Syntax-_002d-CMS.html)
- [TrouSerS TPM Software Stack](https://trousers.sourceforge.net/)

## Next Steps

1. ✅ Document findings (this file)
2. ⏳ Update test scripts to work with available kernel features
3. ⏳ Create documentation for kernel reconfiguration
4. ⏳ Investigate if TPM handle can be passed separately from blob
5. ⏳ Research kernel TPM subsystem internals

---

*Last Updated: 2025-10-19*
*Kernel Version: 6.12.48+deb13-amd64*
