#!/bin/bash
# Script to launch a Confidential VM instance with all required security settings
# Usage: ./launch-instance.sh <instance-name> <zone> <machine-type> <image> <user-data-file> [additional-gcloud-options...]
# Uses default gcloud project from active configuration

set -euo pipefail

# Find gcloud: check local installation first, then system
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "${SCRIPT_DIR}/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/gcloud"
elif [ -x "${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud"
elif command -v gcloud &> /dev/null; then
    GCLOUD="gcloud"
else
    echo "Error: gcloud not found. Install it with:"
    echo "  ./install-gcloud.sh"
    exit 1
fi

if [ $# -lt 5 ]; then
    echo "Usage: $0 <instance-name> <zone> <machine-type> <image> <user-data-file> [additional-options...]"
    echo ""
    echo "Examples:"
    echo "  # Launch x86_64 instance"
    echo "  $0 my-vm us-central1-a n2d-standard-2 lockboot-x86_64 config.json"
    echo ""
    echo "  # Launch aarch64 instance with extra network settings"
    echo "  $0 my-vm us-central1-a t2a-standard-1 lockboot-aarch64 config.json --network=my-vpc"
    echo ""
    echo "Recommended machine types:"
    echo "  x86_64 SEV-SNP: n2d-standard-2, n2d-standard-4, c2d-standard-*"
    echo "  x86_64 TDX:     c3-standard-*"
    echo "  aarch64:        t2a-standard-1, t2a-standard-2, t2a-standard-4"
    echo ""
    echo "Common zones: us-central1-a, us-east1-b, europe-west1-b"
    echo ""
    echo "REQUIRED: user-data-file must contain lockboot configuration (JSON)"
    echo ""
    echo "Documentation:"
    echo "  Confidential VMs: https://cloud.google.com/confidential-computing/confidential-vm/docs"
    echo "  Machine types:    https://cloud.google.com/compute/docs/machine-resource"
    echo "  Zones/Regions:    https://cloud.google.com/compute/docs/regions-zones"
    echo "  Shielded VMs:     https://cloud.google.com/security/shielded-cloud/shielded-vm"
    echo "  Metadata:         https://cloud.google.com/compute/docs/metadata/setting-custom-metadata"
    exit 1
fi

INSTANCE_NAME="$1"
ZONE="$2"
MACHINE_TYPE="$3"
IMAGE="$4"
USER_DATA_FILE="$5"
shift 5  # Remove first 5 args, remaining are passed through

# Validate user-data file exists
if [ ! -f "${USER_DATA_FILE}" ]; then
    echo "Error: User data file '${USER_DATA_FILE}' not found"
    echo "Lockboot requires a configuration file for stage2 download and verification"
    exit 1
fi

# Get current project from gcloud config
PROJECT=$(${GCLOUD} config get-value project 2>/dev/null || echo "")
if [ -z "${PROJECT}" ]; then
    echo "Error: No default project set. Run: ${GCLOUD} config set project <project-id>"
    exit 1
fi

echo "=== Launching Confidential VM Instance ==="
echo "Instance:  ${INSTANCE_NAME}"
echo "Project:   ${PROJECT}"
echo "Zone:      ${ZONE}"
echo "Machine:   ${MACHINE_TYPE}"
echo "Image:     ${IMAGE}"
echo "User-data: ${USER_DATA_FILE}"
echo ""

# Validate machine type supports Confidential Compute
if [[ "${MACHINE_TYPE}" =~ ^n2d- ]] || [[ "${MACHINE_TYPE}" =~ ^c2d- ]]; then
    TECH="AMD SEV-SNP"
elif [[ "${MACHINE_TYPE}" =~ ^c3- ]]; then
    TECH="Intel TDX"
elif [[ "${MACHINE_TYPE}" =~ ^t2a- ]]; then
    TECH="ARM TrustZone"
else
    echo "Warning: Machine type '${MACHINE_TYPE}' may not support Confidential Computing"
    echo "Recommended: n2d-*, c2d-*, c3-*, or t2a-*"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    TECH="Unknown"
fi

echo "Confidential Compute: ${TECH}"
echo ""

# Check if instance already exists
EXISTING=$(${GCLOUD} compute instances list \
    --project="${PROJECT}" \
    --filter="name=${INSTANCE_NAME} AND zone:${ZONE}" \
    --format="value(name)" \
    2>/dev/null || echo "")

if [ -n "${EXISTING}" ]; then
    echo "Error: Instance '${INSTANCE_NAME}' already exists in zone ${ZONE}"
    exit 1
fi

echo "Creating instance with REQUIRED Confidential VM settings:"
echo "  ✓ --confidential-compute-type    (enables memory encryption)"
echo "  ✓ --maintenance-policy=TERMINATE (prevents live migration)"
echo "  ✓ --shielded-secure-boot         (UEFI Secure Boot)"
echo "  ✓ --shielded-vtpm                (virtual TPM 2.0)"
echo "  ✓ --shielded-integrity-monitoring"
echo "  ✓ --boot-disk-type=pd-standard  (cheapest, loaded once into memory)"
echo "  ✓ --boot-disk-auto-delete        (cleanup on instance delete)"
echo ""

# Determine confidential compute type based on machine type
if [[ "${MACHINE_TYPE}" =~ ^c3- ]]; then
    CONF_COMPUTE_TYPE="TDX"
elif [[ "${MACHINE_TYPE}" =~ ^(n2d-|c2d-) ]]; then
    CONF_COMPUTE_TYPE="SEV"
elif [[ "${MACHINE_TYPE}" =~ ^t2a- ]]; then
    # ARM doesn't need explicit type
    CONF_COMPUTE_TYPE=""
else
    CONF_COMPUTE_TYPE="SEV"  # Default to SEV
fi

# Launch instance with all required Confidential VM settings
if [ -n "${CONF_COMPUTE_TYPE}" ]; then
    ${GCLOUD} compute instances create "${INSTANCE_NAME}" \
        --project="${PROJECT}" \
        --zone="${ZONE}" \
        --machine-type="${MACHINE_TYPE}" \
        --image="${IMAGE}" \
        --network-interface=nic-type=GVNIC \
        --boot-disk-type=pd-standard \
        --boot-disk-auto-delete \
        --metadata-from-file=user-data="${USER_DATA_FILE}" \
        --metadata=serial-port-enable=true \
        --confidential-compute-type="${CONF_COMPUTE_TYPE}" \
        --maintenance-policy=TERMINATE \
        --shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        "$@"
else
    # ARM: use old flag for now (TODO: check if ARM needs specific type)
    ${GCLOUD} compute instances create "${INSTANCE_NAME}" \
        --project="${PROJECT}" \
        --zone="${ZONE}" \
        --machine-type="${MACHINE_TYPE}" \
        --image="${IMAGE}" \
        --network-interface=nic-type=GVNIC \
        --boot-disk-type=pd-standard \
        --boot-disk-auto-delete \
        --metadata-from-file=user-data="${USER_DATA_FILE}" \
        --metadata=serial-port-enable=true \
        --confidential-compute \
        --maintenance-policy=TERMINATE \
        --shielded-secure-boot \
        --shielded-vtpm \
        --shielded-integrity-monitoring \
        "$@"
fi

echo ""
echo "=== Instance Created Successfully ==="
echo ""
echo "Connect to instance:"
echo "  ${GCLOUD} compute ssh ${INSTANCE_NAME} --zone=${ZONE}"
echo ""
echo "View serial console:"
echo "  ${GCLOUD} compute instances get-serial-port-output ${INSTANCE_NAME} --zone=${ZONE}"
echo "  Or use: ./get-console.sh ${INSTANCE_NAME} ${ZONE}"
echo ""
echo "View instance details:"
echo "  ${GCLOUD} compute instances describe ${INSTANCE_NAME} --zone=${ZONE}"
echo ""
echo "Launch with spot/preemptible pricing (up to 90% cheaper):"
echo "  Add --provisioning-model=SPOT --instance-termination-action=DELETE to the create command"
echo ""
echo "IMPORTANT: This instance will TERMINATE (not migrate) during maintenance events."
echo "This is required to maintain the Confidential Computing trust model."
