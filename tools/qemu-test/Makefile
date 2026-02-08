.PHONY: all clean

# Amazon EC2 Metadata Mock
AEMM_VERSION := v1.13.0
AEMM_URL := https://github.com/aws/amazon-ec2-metadata-mock/releases/download/$(AEMM_VERSION)/ec2-metadata-mock-linux-amd64
AEMM_SHA256 := 4f89ddc71ac53ce540bda1f9c340526d558eed8e41349761f2798acf1b254950

all: ec2-metadata-mock-linux-amd64

ec2-metadata-mock-linux-amd64:
	@echo "Downloading EC2 metadata mock..."
	@curl -fsSL -o "$@.tmp" "$(AEMM_URL)"
	@echo "$(AEMM_SHA256)  $@.tmp" | sha256sum -c - || (rm -f "$@.tmp"; exit 1)
	@mv "$@.tmp" "$@"
	@chmod +x "$@"
	@echo "✓ Downloaded and verified: $@"

clean:
	rm -f ec2-metadata-mock-linux-amd64
