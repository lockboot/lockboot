# GCP Confidential VM Image Publishing

## Trust Model Requirements

**CRITICAL**: Live migration is **DISABLED** for Confidential VMs. Live migration would break the trust model by allowing the hypervisor to access decrypted memory during migration.

- `--maintenance-policy=TERMINATE` is **REQUIRED**
- Never use `SEV_LIVE_MIGRATABLE` guest OS feature
- Instances will terminate (not migrate) during host maintenance

## Confidential VM Technologies

### x86_64
- **AMD SEV** (1st gen): Memory encryption with single key
- **AMD SEV-SNP** (Secure Nested Paging): Memory encryption + integrity protection
- **Intel TDX** (Trust Domain Extensions): Intel's confidential computing technology

GCP automatically selects based on:
- Machine type (N2D = SEV, C2D/N2D = SEV-SNP, C3 = TDX)
- Region/zone availability

### ARM64 (aarch64)
- Uses ARM TrustZone-based confidential computing
- No special guest OS features required
- Automatically enabled with `--confidential-compute` flag

## Image Creation Workflow

**Two-step approach** (required for custom guest OS features):

```bash
# Use the provided script
./create-image.sh <project-id> <arch> [version]

# Example:
./create-image.sh my-gcp-project x86_64 v0.1.0
./create-image.sh my-gcp-project x86_64 local
```

### What it does internally

1. Uploads the disk image to Google Cloud Storage (GCS)
2. Creates custom image from GCS with specific guest OS features
3. Reuses existing GCS upload if it already exists (idempotent)

**Why not use `gcloud compute images import`?**
The import command requires a predefined `--os` type (like "ubuntu-2204") and doesn't support custom guest OS features for custom UKI images. We need full control over UEFI_COMPATIBLE, SEV_CAPABLE, etc.

### Manual approach (if needed)

For **x86_64** (SEV/SEV-SNP/TDX):
```bash
# Upload to GCS
gcloud storage cp boot.disk gs://${BUCKET}/${PATH}

# Create image with custom features
gcloud compute images create ${IMAGE_NAME} \
  --source-uri=gs://${BUCKET}/${PATH} \
  --guest-os-features=UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,GVNIC \
  --family=${IMAGE_FAMILY}
```

For **aarch64**:
```bash
# Upload to GCS
gcloud storage cp boot.disk gs://${BUCKET}/${PATH}

# Create image with custom features
gcloud compute images create ${IMAGE_NAME} \
  --source-uri=gs://${BUCKET}/${PATH} \
  --guest-os-features=UEFI_COMPATIBLE,GVNIC \
  --family=${IMAGE_FAMILY}
```

### Guest OS Features Explained

- `UEFI_COMPATIBLE` - **REQUIRED** for UEFI boot
- `SEV_CAPABLE` - Mark as compatible with AMD SEV Confidential VMs
- `SEV_SNP_CAPABLE` - Mark as compatible with AMD SEV-SNP Confidential VMs (recommended)
- `GVNIC` - Use Google Virtual NIC (better performance, recommended)
- ~~`SEV_LIVE_MIGRATABLE`~~ - **NEVER USE** (breaks trust model)

## Instance Creation

### Quick Launch (Recommended)

Use the provided launch script which has all Confidential VM settings baked in:

```bash
# Launch with required user-data configuration
./launch-instance.sh my-vm us-central1-a n2d-standard-2 lockboot-x86_64 config.json

# With additional network settings
./launch-instance.sh my-vm us-central1-a t2a-standard-1 lockboot-aarch64 config.json \
  --network-interface=network=my-vpc,subnet=my-subnet
```

**Note**: The `config.json` user-data file is **REQUIRED** - it contains the lockboot configuration for stage2 download and verification.

The script automatically:
- Uses your default gcloud project
- Validates user-data file exists
- Validates machine type supports Confidential Compute
- Sets all required security flags
- Prevents accidental live migration

### Manual Instance Creation

```bash
gcloud compute instances create ${INSTANCE_NAME} \
  --zone=${ZONE} \
  --machine-type=${MACHINE_TYPE} \
  --image=${IMAGE_NAME} \
  --confidential-compute \
  --maintenance-policy=TERMINATE \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --metadata-from-file=user-data=config.json
```

### Machine Type Selection (x86_64)

For **SEV-SNP** (recommended):
- N2D series: `n2d-standard-*` (AMD Milan)
- C2D series: `c2d-standard-*` (AMD Milan, compute-optimized)

For **TDX** (Intel):
- C3 series: `c3-standard-*` (Intel Sapphire Rapids)

For **ARM64**:
- T2A series: `t2a-standard-*` (Ampere Altra)

### Required Flags Explained

- `--confidential-compute` - **REQUIRED** enables memory encryption
- `--maintenance-policy=TERMINATE` - **REQUIRED** prevents live migration
- `--shielded-secure-boot` - Enables UEFI Secure Boot validation
- `--shielded-vtpm` - Provides virtual TPM 2.0 (measured boot)
- `--shielded-integrity-monitoring` - Baseline integrity measurement

## Key Differences from AWS

| Feature | AWS (Nitro) | GCP (Confidential VM) |
|---------|-------------|----------------------|
| UEFI vars | Provided via `--uefi-data` | Managed by platform |
| vTPM | Enabled via `--tpm-support v2.0` | Automatic with `--shielded-vtpm` |
| Memory encryption | Nitro Enclaves | SEV/SEV-SNP/TDX |
| Metadata | IMDSv2 | Metadata server |
| User data | `--user-data` | `--metadata-from-file=user-data=` |
| User data required | Optional | **Required** (stage1 config) |
