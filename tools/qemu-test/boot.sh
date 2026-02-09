#!/bin/bash
set -euox pipefail

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Repository root (computed from script location: tools/qemu-test -> ../..)
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ "$YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES" != 1 ]; then
    echo "Error: not inside docker, refusing to do dangerous stuff!!"
    exit 1
fi

# Get architecture from environment (default to x86_64)
ARCH=${ARCH:-x86_64}

# Default user-data file
KEYDIR="${REPO_ROOT}/tools/build-uki/keys"
USER_DATA="${REPO_ROOT}/user-data.json"
TMP=/tmp

echo "=== Booting UKI with Secure Boot + TPM 2.0 (${ARCH}) ==="
echo "User-data file: ${USER_DATA}"

AMMM=${SCRIPT_DIR}/ec2-metadata-mock-linux-amd64

# Check dependencies
if [ ! -f ${AMMM} ]; then
    echo "Error: ${AMMM} not found. Run 'make ec2-metadata-mock-linux-amd64' first."
    exit 1
fi

if [ ! -f "${USER_DATA}" ]; then
    echo "Error: User-data file '${USER_DATA}' not found."
    exit 1
fi

# Boot disk location (in tools/build-uki)
BOOT_DISK="${REPO_ROOT}/tools/build-uki/${ARCH}/boot.disk"
if [ ! -f "${BOOT_DISK}" ]; then
    echo "Error: ${BOOT_DISK} not found. Run 'make ${ARCH}' first."
    exit 1
fi

# OVMF firmware paths (architecture-specific)
if [ "${ARCH}" = "x86_64" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
    QEMU_CMD="qemu-system-x86_64"
    QEMU_MACHINE="-machine q35,smm=on"
    QEMU_CPU=""
    QEMU_EXTRA="-enable-kvm"
    # ISA serial at 0x3f8 = ttyS0, matches how GRUB/Fedora expects serial on x86_64
    QEMU_SERIAL="-serial none"
    QEMU_SERIAL_DEVICE="-device isa-serial,chardev=char0"
    TPM_DEVICE="tpm-tis"
elif [ "${ARCH}" = "aarch64" ]; then
    OVMF_CODE="/usr/share/AAVMF/AAVMF_CODE.fd"
    QEMU_CMD="qemu-system-aarch64"
    # GIC version 3 is more modern, try gic-version=2 if it doesn't work
    QEMU_MACHINE="-machine virt"
    #QEMU_MACHINE="-machine virt,gic-version=2"
    #QEMU_MACHINE="-machine sbsa-ref"
    # Try different CPU models if one doesn't work:
    # -cpu cortex-a57 (older, well-supported)
    # -cpu cortex-a72 (similar to a57)
    # -cpu max (all features, but may cause issues)
    QEMU_CPU="-cpu cortex-a72"
    #QEMU_CPU=""
    QEMU_EXTRA=""
    # -serial none: PL011 exists but with no backend, PCI serial is ttyS0
    QEMU_SERIAL="-serial none"
    QEMU_SERIAL_DEVICE="-device pci-serial,id=serial0,chardev=char0"
    TPM_DEVICE="tpm-tis-device"
else
    echo "Error: Unsupported architecture: ${ARCH}"
    exit 1
fi

OVMF_VARS_ORIG="${REPO_ROOT}/tools/build-uki/${ARCH}/efi-vars.ovmf"
OVMF_VARS="/tmp/efi-vars.ovmf"

if [ ! -f "${OVMF_CODE}" ]; then
    echo "Error: ${OVMF_CODE} not found. Install ovmf package."
    exit 1
fi

cp "${OVMF_VARS_ORIG}" "${OVMF_VARS}"

# Setup TPM state directory
mkdir -p $TMP/tpm-state

# Provision NV indices for GCP-style attestation (idempotent)
# This starts its own swtpm instance with tpm2-tools-compatible sockets, then shuts it down
${SCRIPT_DIR}/provision-test-tpm.sh $TMP/tpm-state

# Start swtpm for QEMU (original way - just ctrl socket)
swtpm socket --tpmstate dir=$TMP/tpm-state \
    --ctrl type=unixio,path=$TMP/swtpm-sock \
    --tpm2 \
    --pid file=$TMP/swtpm.pid \
    --daemon
sleep 1

# Cleanup function
cleanup() {
    kill $(cat $TMP/swtpm.pid 2>/dev/null) 2>/dev/null || true
    kill $(cat $TMP/ec2-mock.pid 2>/dev/null) 2>/dev/null || true
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

# Boot the UKI
echo "Press Ctrl-A, then X to exit QEMU"

#-netdev "user,id=net0,net=169.254.169.0/24,guestfwd=tcp:169.254.169.254:80-cmd:/usr/bin/nc 192.168.3.5 1338" \

ip tuntap add dev tap0 mode tap
ip link set tap0 up
ip addr add 10.0.2.1/24 dev tap0
ip addr add 169.254.169.254/24 dev tap0

# Create AEMM config with user-data
echo "Starting EC2 metadata mock..."
echo '{"userdata":{"values":{"userdata":"'$(base64 -w0 "${USER_DATA}")'"}}}' > $TMP/aemm-config.json

# Start EC2 metadata mock
${AMMM} \
    --imdsv2 \
    -n 169.254.169.254 \
    --port 80 \
    --config-file $TMP/aemm-config.json &
echo $! > $TMP/ec2-mock.pid

# Give services time to start
sleep 1

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Create dnsmasq hosts file with EC2-style hostnames
echo "Generating /tmp/dnsmasq-hosts..."
cat > /tmp/dnsmasq-hosts <<EOF
10.0.2.10 ip-10-0-2-10
10.0.2.11 ip-10-0-2-11
10.0.2.12 ip-10-0-2-12
10.0.2.13 ip-10-0-2-13
10.0.2.14 ip-10-0-2-14
10.0.2.15 ip-10-0-2-15
10.0.2.16 ip-10-0-2-16
10.0.2.17 ip-10-0-2-17
10.0.2.18 ip-10-0-2-18
10.0.2.19 ip-10-0-2-19
10.0.2.20 ip-10-0-2-20
EOF

# Start DHCP with EC2-like configuration
# Option 3: Default gateway (10.0.2.1)
# Option 6: DNS server (10.0.2.1 for local DNS, also 8.8.8.8)
# Option 15: Domain name (ec2.internal)
# Option 121: Classless Static Routes - route 169.254.169.254/32 via 10.0.2.1
# Option 119: Domain search list (.ec2.internal, .local.compute.internal)
dnsmasq --interface=tap0 --bind-interfaces \
    --dhcp-range=10.0.2.10,10.0.2.20,12h \
    --dhcp-option=3,10.0.2.1 \
    --dhcp-option=6,10.0.2.1,8.8.8.8 \
    --dhcp-option=15,ec2.internal \
    --dhcp-option=option:classless-static-route,169.254.169.254/32,10.0.2.1 \
    --dhcp-option=119,ec2.internal,local.compute.internal \
    --domain=ec2.internal \
    --expand-hosts \
    --addn-hosts=/tmp/dnsmasq-hosts \
    --log-queries

# Set pflash secure option only for x86_64
if [ "${ARCH}" = "x86_64" ]; then
    PFLASH_SECURE="-global driver=cfi.pflash01,property=secure,value=on"
else
    PFLASH_SECURE=""
fi

${QEMU_CMD} \
    ${QEMU_CPU} \
    ${QEMU_EXTRA} \
    ${QEMU_MACHINE} \
    ${PFLASH_SECURE} \
    -smp cores=2,threads=1 -m 512 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -chardev socket,id=chrtpm,path=$TMP/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device ${TPM_DEVICE},tpmdev=tpm0 \
    -drive file=${BOOT_DISK},format=raw,if=none,id=boot \
    -device nvme,serial=boot,drive=boot,bootindex=0 \
    -netdev tap,id=net0,ifname=tap0,script=no \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    ${QEMU_SERIAL} \
    -chardev stdio,mux=on,id=char0 \
    ${QEMU_SERIAL_DEVICE} \
    -drive if=pflash,format=raw,unit=0,file="${OVMF_CODE}",readonly=on \
    -drive if=pflash,format=raw,unit=1,file="${OVMF_VARS}" || true
