#!/bin/bash
# Script to download and install gcloud CLI locally in this directory
# Usage: ./install-gcloud.sh [--init|--no-init] [--force]
#   --init      Automatically run gcloud init after installation
#   --no-init   Skip gcloud init after installation
#   --force     Force reinstall if already installed
#   (no flags: prompt user for both)

set -euo pipefail

# Parse flags
AUTO_INIT=""
FORCE_REINSTALL=false

for arg in "$@"; do
    case $arg in
        --init)
            AUTO_INIT="yes"
            shift
            ;;
        --no-init)
            AUTO_INIT="no"
            shift
            ;;
        --force)
            FORCE_REINSTALL=true
            shift
            ;;
        *)
            echo "Usage: $0 [--init|--no-init] [--force]"
            echo "  --init      Automatically run gcloud init"
            echo "  --no-init   Skip gcloud init"
            echo "  --force     Force reinstall if already installed"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${SCRIPT_DIR}/google-cloud-sdk"
GCLOUD_SYMLINK="${SCRIPT_DIR}/gcloud"

echo "=== Google Cloud SDK Installer ==="
echo "Installing to: ${INSTALL_DIR}"
echo ""

# Check if already installed locally
if [ -x "${INSTALL_DIR}/bin/gcloud" ]; then
    CURRENT_VERSION=$(${INSTALL_DIR}/bin/gcloud version --format="value(version)" 2>/dev/null || echo "unknown")
    echo "gcloud is already installed locally: ${CURRENT_VERSION}"
    echo ""

    if [ "${FORCE_REINSTALL}" = true ]; then
        echo "Force reinstall requested, removing existing installation..."
        rm -rf "${INSTALL_DIR}"
    else
        read -p "Reinstall anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
        rm -rf "${INSTALL_DIR}"
    fi
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
    linux)
        case "${ARCH}" in
            x86_64)
                PACKAGE="google-cloud-cli-linux-x86_64.tar.gz"
                ;;
            aarch64|arm64)
                PACKAGE="google-cloud-cli-linux-arm.tar.gz"
                ;;
            *)
                echo "Error: Unsupported architecture: ${ARCH}"
                exit 1
                ;;
        esac
        ;;
    darwin)
        case "${ARCH}" in
            x86_64)
                PACKAGE="google-cloud-cli-darwin-x86_64.tar.gz"
                ;;
            arm64)
                PACKAGE="google-cloud-cli-darwin-arm.tar.gz"
                ;;
            *)
                echo "Error: Unsupported architecture: ${ARCH}"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "Error: Unsupported OS: ${OS}"
        echo "For Windows, download from: https://cloud.google.com/sdk/docs/install"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/${PACKAGE}"
ARCHIVE_PATH="${SCRIPT_DIR}/${PACKAGE}"

echo "Detected platform: ${OS} ${ARCH}"
echo "Package: ${PACKAGE}"
echo ""

# Download archive if it doesn't exist
if [ -f "${ARCHIVE_PATH}" ]; then
    echo "Using cached archive: ${ARCHIVE_PATH}"
else
    echo "Downloading gcloud SDK..."
    curl -L -o "${ARCHIVE_PATH}" "${DOWNLOAD_URL}"
fi

echo "Extracting to ${SCRIPT_DIR}..."
tar -xzf "${ARCHIVE_PATH}" -C "${SCRIPT_DIR}"

# Create symlink to gcloud binary
echo "Creating symlink: ${GCLOUD_SYMLINK} -> ${INSTALL_DIR}/bin/gcloud"
ln -sf "${INSTALL_DIR}/bin/gcloud" "${GCLOUD_SYMLINK}"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "gcloud installed to: ${INSTALL_DIR}/bin/gcloud"
echo "Symlink created: ./gcloud"
echo ""

# Handle gcloud init based on flags or prompt
case "${AUTO_INIT}" in
    yes)
        echo "Running gcloud init..."
        "${INSTALL_DIR}/bin/gcloud" init
        ;;
    no)
        echo "Skipping gcloud init."
        echo ""
        echo "Initialize gcloud later with:"
        echo "  ./gcloud init"
        echo ""
        echo "Or set project manually:"
        echo "  ./gcloud config set project <project-id>"
        echo "  ./gcloud auth login"
        ;;
    *)
        # Prompt user
        read -p "Initialize gcloud now? (authenticate and set project) (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            "${INSTALL_DIR}/bin/gcloud" init
        else
            echo ""
            echo "Initialize gcloud later with:"
            echo "  ./gcloud init"
            echo ""
            echo "Or set project manually:"
            echo "  ./gcloud config set project <project-id>"
            echo "  ./gcloud auth login"
        fi
        ;;
esac

echo ""
echo "The scripts in this directory will automatically use this local gcloud installation."
