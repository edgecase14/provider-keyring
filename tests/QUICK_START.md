# Quick Start: Testing Kernel Keyring Integration

## Educational Demo (No TPM Required)

Run this first to understand the architecture:

```bash
cd /path/to/provider-keyring
./tests/test_keyring_sign_verify.sh
```

**What you'll learn:**
- How kernel keyring asymmetric keys work
- Why software keys can't sign from keyring
- How TPM keys are different
- The `keyctl_pkey_sign()` interface

---

## Testing with Real TPM 1.2

### Prerequisites

```bash
# Install required packages
sudo apt-get install trousers tpm-tools keyutils openssl

# Start TPM daemon
sudo systemctl start tcsd
sudo systemctl enable tcsd

# Take TPM ownership (first time only)
sudo tpm_takeownership -z
```

### Run Full Test

```bash
sudo ./tests/test_tpm12_keyring.sh
```

**This test will:**
1. ✓ Generate 2048-bit RSA key inside TPM
2. ✓ Extract public key from TPM
3. ✓ Load key into kernel keyring with TPM marker
4. ✓ Sign test data using `keyctl_pkey_sign()` (TPM-offloaded)
5. ✓ Verify signature with OpenSSL
6. ✓ Test decryption (if key type supports it)

---

## Manual TPM Key Setup

If you want to manually create and test a TPM key:

### Step 1: Generate Key in TPM
```bash
# Create TPM key (2048-bit RSA)
tpm_createkey -s 2048 -e -w -l /tmp/mykey -z

# Load key to get handle
KEY_HANDLE=$(tpm_loadkey -p /tmp/mykey.blob -z 2>&1 | grep "Key handle" | awk '{print $3}')
echo "TPM Key Handle: $KEY_HANDLE"
```

### Step 2: Extract Public Key
```bash
# Get public key from TPM
tpm_getpubkey -k $KEY_HANDLE -z > /tmp/pubkey.pem

# Convert to DER format (required for kernel keyring)
openssl rsa -pubin -in /tmp/pubkey.pem -outform DER -out /tmp/pubkey.der
```

### Step 3: Load to Kernel Keyring
```bash
# Load with TPM marker in description (IMPORTANT!)
KEY_SERIAL=$(keyctl padd asymmetric "asymmetric;tpm;mykey" @u < /tmp/pubkey.der)
echo "Kernel Keyring Serial: $KEY_SERIAL"

# Verify it's loaded
keyctl show @u | grep mykey
```

### Step 4: Sign Data
```bash
# Create test data
echo -n "Hello from TPM!" > /tmp/data.txt

# Hash the data
openssl dgst -sha256 -binary /tmp/data.txt > /tmp/data.hash

# Sign with TPM via kernel keyring
keyctl pkey_sign $KEY_SERIAL enc=pkcs1 hash=sha256 \
    < /tmp/data.hash \
    > /tmp/signature.bin

echo "Signature size: $(stat -c%s /tmp/signature.bin) bytes"
```

### Step 5: Verify Signature
```bash
# Verify with OpenSSL
openssl dgst -sha256 -verify /tmp/pubkey.pem \
    -signature /tmp/signature.bin \
    /tmp/data.txt

# Should output: Verified OK
```

---

## Using with OpenSSL Provider

Once the key is in the kernel keyring:

```bash
# Set environment to use the provider
export OPENSSL_MODULES=/path/to/provider-keyring/build/lib

# Sign with OpenSSL using the provider
openssl dgst -sha256 -sign "keyring:object=mykey;type=private" \
    -out signature.bin data.txt

# The provider will:
# 1. Search kernel keyring for "mykey"
# 2. Call keyctl_pkey_sign() with the key serial
# 3. Kernel routes to TPM automatically
# 4. Signature returned
```

---

## Kernel Requirements

### Minimum Kernel Version
- Linux **4.7+** for `keyctl_pkey_*()` functions

### Required Kernel Config
```
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_TCG_TPM=y                    # TPM support
CONFIG_TCG_TIS=m or y               # TPM Interface (hardware)
# or
CONFIG_TCG_VTPM_PROXY=m or y        # Virtual TPM (for swtpm)
```

### Check Your Kernel
```bash
# Check kernel version
uname -r  # Should be >= 4.7

# Check if TPM is available
ls -l /dev/tpm*

# Check if keyctl supports pkey operations
keyctl --help | grep pkey

# Check loaded kernel modules
lsmod | grep tpm
```

---

## Software TPM for Testing

If you don't have hardware TPM:

### Install swtpm
```bash
sudo apt-get install swtpm swtpm-tools
```

### Start Software TPM 1.2
```bash
# Create TPM state directory
mkdir -p /tmp/mytpm

# Start TPM emulator
swtpm chardev --vtpm-proxy --tpm2=false \
    --tpmstate dir=/tmp/mytpm \
    --ctrl type=unixio,path=/tmp/mytpm/ctrl &

# Wait for /dev/tpm0 to appear
sleep 2
ls -l /dev/tpm0

# Start tcsd daemon
sudo systemctl restart tcsd
```

### Verify swtpm is Working
```bash
# Query TPM version
tpm_version

# Should show: TPM 1.2 Version Info
```

---

## Troubleshooting

### Common Issues

**"tcsd: error while loading shared libraries"**
```bash
sudo apt-get install trousers tpm-tools
sudo systemctl restart tcsd
```

**"add_key: Permission denied"**
```bash
# Need root or CAP_SYS_ADMIN for keyring operations
sudo -E bash  # Run commands as root
```

**"keyctl: Package not found"**
```bash
sudo apt-get install keyutils
```

**"/dev/tpm0: No such file or directory"**
```bash
# Enable TPM in BIOS, or use swtpm for testing
# Check kernel modules:
sudo modprobe tpm_tis  # Hardware TPM
# or
sudo modprobe tpm_vtpm_proxy  # Virtual TPM
```

**"Bad message" when loading key**
```bash
# Kernel doesn't recognize key format
# Make sure you're loading DER format, not PEM
openssl rsa -pubin -in pubkey.pem -outform DER -out pubkey.der
keyctl padd asymmetric "mykey" @u < pubkey.der
```

**"Operation not supported" on pkey_sign**
```bash
# Kernel might not have asymmetric key support
grep ASYMMETRIC /boot/config-$(uname -r)
# Should show:
# CONFIG_ASYMMETRIC_KEY_TYPE=y
# CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
```

---

## Next Steps

1. **Run educational demo**: `./tests/test_keyring_sign_verify.sh`
2. **Read TPM_TESTING.md**: Full documentation on architecture
3. **Try manual setup**: Follow "Manual TPM Key Setup" above
4. **Run full test**: `sudo ./tests/test_tpm12_keyring.sh`
5. **Integrate with provider**: Use `keyring:object=...` URIs

---

## Key Takeaways

✅ **Kernel keyring stores PUBLIC keys** (+ TPM handle for TPM keys)

✅ **Private keys stay in TPM** (never exported)

✅ **`keyctl_pkey_sign()` routes to TPM** automatically

✅ **This provider uses kernel keyring** for all crypto operations

✅ **No userspace TPM libraries needed** for signing (kernel handles it)

❌ **Software keys CAN'T sign from keyring** (no private material stored)

❌ **TPM key generation NOT YET implemented** in keygen tool (coming soon)
