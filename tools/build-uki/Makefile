.PHONY: all help clean check-urls

# Alpine Linux version (stable)
ALPINE_VERSION := v3.22
ALPINE_BASE_URL := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_VERSION)/main

# Busybox (static) from Alpine Linux
BUSYBOX_VERSION := 1.37.0-r20
BUSYBOX_SHA256_x86_64 := 488ad6efd04b5a722719e79f8e0dcc2c24afd6758867af3ce41b04839e60c74b
BUSYBOX_SHA256_aarch64 := ee469aee2958feffd7f64dd96655704025ff60af614f77a1d7323dc237c34da2
BUSYBOX_APK := busybox-static-$(BUSYBOX_VERSION).apk
BUSYBOX_URL_x86_64 := $(ALPINE_BASE_URL)/x86_64/$(BUSYBOX_APK)
BUSYBOX_URL_aarch64 := $(ALPINE_BASE_URL)/aarch64/$(BUSYBOX_APK)

# systemd-boot-unsigned from Amazon Linux (provides EFI stub)
# x86_64 provides: /usr/lib/systemd/boot/efi/linuxx64.efi.stub
# aarch64 provides: /usr/lib/systemd/boot/efi/linuxaa64.efi.stub
SYSTEMD_BOOT_VERSION := 252.23-8.amzn2023
SYSTEMD_BOOT_SHA256_x86_64 := d036e8fa194d4d660ef05fd2d4f12037a251fee0f20adfd6a45992d83532bbc9
SYSTEMD_BOOT_SHA256_aarch64 := ad89706bf213071aa3053fa23a19452bac5d95ab618f32ace3e485eea0e6eea3
SYSTEMD_BOOT_RPM_x86_64 := systemd-boot-unsigned-$(SYSTEMD_BOOT_VERSION).x86_64.rpm
SYSTEMD_BOOT_RPM_aarch64 := systemd-boot-unsigned-$(SYSTEMD_BOOT_VERSION).aarch64.rpm
SYSTEMD_BOOT_URL_x86_64 := https://cdn.amazonlinux.com/al2023/blobstore/$(SYSTEMD_BOOT_SHA256_x86_64)/$(SYSTEMD_BOOT_RPM_x86_64)
SYSTEMD_BOOT_URL_aarch64 := https://cdn.amazonlinux.com/al2023/blobstore/$(SYSTEMD_BOOT_SHA256_aarch64)/$(SYSTEMD_BOOT_RPM_aarch64)

# Amazon Linux 2023 kernel 6.12 and modules
AMAZON_KERNEL_PACKAGE := kernel6.12
AMAZON_KERNEL_SHA256_x86_64 := 2583dc9eb7ab114238aaecbbe76ab3d0bb650a8ed0ef0b666b54573dc4c1da5e
AMAZON_KERNEL_SHA256_aarch64 := 5eba5a6cffb9a5798533834bff1cb39d5d8303a454dc639c97179914ecafa7fb
AMAZON_KERNEL_VERSION := 6.12.53-69.119.amzn2023
AMAZON_KERNEL_RPM_x86_64 := $(AMAZON_KERNEL_PACKAGE)-$(AMAZON_KERNEL_VERSION).x86_64.rpm
AMAZON_KERNEL_RPM_aarch64 := $(AMAZON_KERNEL_PACKAGE)-$(AMAZON_KERNEL_VERSION).aarch64.rpm
AMAZON_KERNEL_URL_x86_64 := https://cdn.amazonlinux.com/al2023/blobstore/$(AMAZON_KERNEL_SHA256_x86_64)/$(AMAZON_KERNEL_RPM_x86_64)
AMAZON_KERNEL_URL_aarch64 := https://cdn.amazonlinux.com/al2023/blobstore/$(AMAZON_KERNEL_SHA256_aarch64)/$(AMAZON_KERNEL_RPM_aarch64)

ARCHS = x86_64 aarch64
TARGETS = busybox stub.efi kernel.rpm

all: $(ARCHS)

x86_64: $(addprefix x86_64/,$(TARGETS))
aarch64: $(addprefix aarch64/,$(TARGETS))

%/$(BUSYBOX_APK):
	@./download-and-verify.sh "$@" "$(BUSYBOX_SHA256_$*)" "$(BUSYBOX_URL_$*)"

%/busybox: %/$(BUSYBOX_APK)
	@mkdir -p $*
	@tar --warning=no-unknown-keyword -xzOf $< bin/busybox.static > "$@"
	@chmod +x "$@"

# Download systemd-boot-unsigned RPM from Amazon Linux
x86_64/$(SYSTEMD_BOOT_RPM_x86_64):
	@./download-and-verify.sh "$@" "$(SYSTEMD_BOOT_SHA256_x86_64)" "$(SYSTEMD_BOOT_URL_x86_64)"

aarch64/$(SYSTEMD_BOOT_RPM_aarch64):
	@./download-and-verify.sh "$@" "$(SYSTEMD_BOOT_SHA256_aarch64)" "$(SYSTEMD_BOOT_URL_aarch64)"

# Extract EFI stub from systemd-boot RPM
x86_64/stub.efi: x86_64/$(SYSTEMD_BOOT_RPM_x86_64)
	@mkdir -p x86_64
	@rpm2cpio $< | cpio -i --quiet --to-stdout ./usr/lib/systemd/boot/efi/linuxx64.efi.stub > $@
	@chmod +x $@

aarch64/stub.efi: aarch64/$(SYSTEMD_BOOT_RPM_aarch64)
	@mkdir -p aarch64
	@rpm2cpio $< | cpio -i --quiet --to-stdout ./usr/lib/systemd/boot/efi/linuxaa64.efi.stub > $@
	@chmod +x $@

# Download Amazon Linux kernel RPM from blobstore
x86_64/$(AMAZON_KERNEL_RPM_x86_64):
	@./download-and-verify.sh "$@" "$(AMAZON_KERNEL_SHA256_x86_64)" "$(AMAZON_KERNEL_URL_x86_64)"

x86_64/kernel.rpm: x86_64/$(AMAZON_KERNEL_RPM_x86_64)
	@ln -sf $(notdir $<) $@

aarch64/$(AMAZON_KERNEL_RPM_aarch64):
	@./download-and-verify.sh "$@" "$(AMAZON_KERNEL_SHA256_aarch64)" "$(AMAZON_KERNEL_URL_aarch64)"

aarch64/kernel.rpm: aarch64/$(AMAZON_KERNEL_RPM_aarch64)
	@ln -sf $(notdir $<) $@

# Retrieve package URLs from dnf
kernel-hash-%:
	docker run --rm --platform linux/amd64 amazonlinux:latest bash -c "dnf repoquery --forcearch=$* --arch=$* --location $(AMAZON_KERNEL_PACKAGE)-$(AMAZON_KERNEL_VERSION).$*"

clean:
	rm -rf x86_64 aarch64

# Check all download URLs are still valid
check-urls:
	@echo "Checking URLs..."
	@curl -sfI "$(BUSYBOX_URL_x86_64)" > /dev/null && echo "OK: busybox x86_64" || echo "FAIL: busybox x86_64"
	@curl -sfI "$(BUSYBOX_URL_aarch64)" > /dev/null && echo "OK: busybox aarch64" || echo "FAIL: busybox aarch64"
	@curl -sfI "$(SYSTEMD_BOOT_URL_x86_64)" > /dev/null && echo "OK: systemd-boot x86_64" || echo "FAIL: systemd-boot x86_64"
	@curl -sfI "$(SYSTEMD_BOOT_URL_aarch64)" > /dev/null && echo "OK: systemd-boot aarch64" || echo "FAIL: systemd-boot aarch64"
	@curl -sfI "$(AMAZON_KERNEL_URL_x86_64)" > /dev/null && echo "OK: kernel x86_64" || echo "FAIL: kernel x86_64"
	@curl -sfI "$(AMAZON_KERNEL_URL_aarch64)" > /dev/null && echo "OK: kernel aarch64" || echo "FAIL: kernel aarch64"
