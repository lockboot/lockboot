#!/bin/bash
set -e

# Usage: download-and-verify.sh <output_file> <expected_sha256> <url>
OUTPUT_FILE="$1"
EXPECTED_SHA256="$2"
URL="$3"

if [ -z "$OUTPUT_FILE" ] || [ -z "$EXPECTED_SHA256" ] || [ -z "$URL" ]; then
    echo "Usage: $0 <output_file> <expected_sha256> <url>" >&2
    exit 1
fi

# Create directory if needed
mkdir -p "$(dirname "$OUTPUT_FILE")"

# Download if file doesn't exist
if [ ! -f "$OUTPUT_FILE" ]; then
    wget -q -O "$OUTPUT_FILE" "$URL"
    sha256sum "$OUTPUT_FILE"
fi

# Verify hash
echo "${EXPECTED_SHA256}  ${OUTPUT_FILE}" | sha256sum -c - > /dev/null || {
    rm -f "$OUTPUT_FILE"
    exit 1
}
