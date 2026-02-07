#!/bin/bash
# Provision swtpm with GCP-style NV indices for testing
#
# This script sets up a software TPM with the NV indices that vaportpm
# expects for GCP-style attestation, enabling local QEMU testing.
#
# Usage: provision-test-tpm.sh [socket_path]
#   socket_path: Path to swtpm control socket (default: /tmp/swtpm-sock)

set -euox pipefail

TPM_STATE_DIR="${1:-/tmp/tpm-state}"
SOCKET="/tmp/swtpm-provision-sock"
export TPM2TOOLS_TCTI="swtpm:path=$SOCKET"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
cd $TMPDIR

# NV indices (GCP standard)
NV_RSA_TEMPLATE=0x01c10001
NV_ECC_CERT=0x01c10002
NV_ECC_TEMPLATE=0x01c10003

# Start swtpm with both server+ctrl sockets (required for tpm2-tools TCTI)
swtpm socket --tpmstate dir=$TPM_STATE_DIR \
    --server type=unixio,path=$SOCKET \
    --ctrl type=unixio,path=${SOCKET}.ctrl \
    --tpm2 \
    --daemon

sleep 1

# Initialize and startup TPM
swtpm_ioctl --unix ${SOCKET}.ctrl -i
tpm2_startup -c

# Check if already provisioned (idempotent)
if tpm2_nvreadpublic $NV_ECC_TEMPLATE 2>/dev/null; then
    echo "TPM already provisioned, skipping"
    exit 0
fi

echo "Provisioning TPM for GCP-style attestation..."

# 1. Create hardcoded TPMT_PUBLIC template (empty unique)
# Based on vaportpm's template but WITHOUT restricted attribute for tpm2-tools compatibility:
#   type=ECC(0x0023), nameAlg=SHA256(0x000b), attrs=0x00040072 (no restricted)
#   symmetric=Null, scheme=ECDSA-SHA256, curve=P256, kdf=Null
#   unique x_size=0, y_size=0
# Note: tpm2_createprimary can't create restricted ECC signing keys (symmetric bug)
echo -n "0023000b00040072000000100018000b0003001000000000" | xxd -r -p > template.bin

# 2. Write template to NV FIRST (before creating key)
tpm2_nvdefine $NV_ECC_TEMPLATE -s 24 -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite $NV_ECC_TEMPLATE -i template.bin

# 3. Create key (non-restricted to work around tpm2-tools symmetric bug)
tpm2_createprimary -C e -G ecc:ecdsa-sha256 \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' \
    -c ak.ctx

# 4. Extract public key as PEM for certificate
tpm2_readpublic -c ak.ctx -f pem -o ak.pub.pem

# 5. Create test CA
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 \
    -subj "/CN=LockBoot Test CA" -batch

# 6. Create AK cert with TPM's public key (using -force_pubkey)
openssl req -new -key ca.key -subj "/CN=Test AK" -out ak.csr -batch
openssl x509 -req -in ak.csr -CA ca.crt -CAkey ca.key \
    -force_pubkey ak.pub.pem -out ak.crt -days 3650 \
    -extfile <(echo "keyUsage=critical,digitalSignature") \
    -CAcreateserial

# 7. Convert cert to DER and write to NV
openssl x509 -in ak.crt -outform DER -out ak.crt.der
tpm2_nvdefine $NV_ECC_CERT -s $(stat -c%s ak.crt.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite $NV_ECC_CERT -i ak.crt.der

# 8. Write dummy RSA template (for detection)
tpm2_nvdefine $NV_RSA_TEMPLATE -s 32 -a "ownerread|ownerwrite|authread|authwrite"
dd if=/dev/zero bs=32 count=1 2>/dev/null | tpm2_nvwrite $NV_RSA_TEMPLATE -i -

# 9. Cleanup TPM transient objects
tpm2_flushcontext -t

# 10. Clean shutdown to save state (boot.sh will restart swtpm)
tpm2_shutdown
swtpm_ioctl --unix ${SOCKET}.ctrl -s

echo "TPM provisioned successfully for GCP-style attestation"
