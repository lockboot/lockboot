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

# systemd-boot-unsigned from Fedora 41 (provides EFI stub)
# v256 supports PE vmlinuz on aarch64 (LoadImage/StartImage instead of direct jump)
# x86_64 provides: /usr/lib/systemd/boot/efi/linuxx64.efi.stub
# aarch64 provides: /usr/lib/systemd/boot/efi/linuxaa64.efi.stub
SYSTEMD_BOOT_VERSION := 256.17-1.fc41
SYSTEMD_BOOT_SHA256_x86_64 := ec5ce2a3e685750a7743cf933ed9ff583fe4e90cef743c76349a158631b3dae5
SYSTEMD_BOOT_SHA256_aarch64 := f188ea9f918be9c2314c4208c0c247bd6dc7eae96df85fa9e3c672619853ddcf
SYSTEMD_BOOT_RPM_x86_64 := systemd-boot-unsigned-$(SYSTEMD_BOOT_VERSION).x86_64.rpm
SYSTEMD_BOOT_RPM_aarch64 := systemd-boot-unsigned-$(SYSTEMD_BOOT_VERSION).aarch64.rpm
SYSTEMD_BOOT_URL_x86_64 := https://kojipkgs.fedoraproject.org/packages/systemd/256.17/1.fc41/x86_64/$(SYSTEMD_BOOT_RPM_x86_64)
SYSTEMD_BOOT_URL_aarch64 := https://kojipkgs.fedoraproject.org/packages/systemd/256.17/1.fc41/aarch64/$(SYSTEMD_BOOT_RPM_aarch64)

# Fedora 41 kernel 6.12 (has both ena and gve drivers)
FEDORA_KERNEL_VERSION := 6.12.4-200.fc41
FEDORA_KERNEL_BASE_URL := https://kojipkgs.fedoraproject.org/packages/kernel/6.12.4/200.fc41

# kernel-core (contains vmlinuz)
FEDORA_KERNEL_CORE_SHA256_x86_64 := f7df5e7d36b7ed4c311f358340fcf2ae414cd1b4b8ad8d8555bb5cae2403cfc3
FEDORA_KERNEL_CORE_SHA256_aarch64 := 5494b00c95832eb52b39b306fd4ab912893824cd0419612fb52fc97643fa56cb
FEDORA_KERNEL_CORE_RPM_x86_64 := kernel-core-$(FEDORA_KERNEL_VERSION).x86_64.rpm
FEDORA_KERNEL_CORE_RPM_aarch64 := kernel-core-$(FEDORA_KERNEL_VERSION).aarch64.rpm
FEDORA_KERNEL_CORE_URL_x86_64 := $(FEDORA_KERNEL_BASE_URL)/x86_64/$(FEDORA_KERNEL_CORE_RPM_x86_64)
FEDORA_KERNEL_CORE_URL_aarch64 := $(FEDORA_KERNEL_BASE_URL)/aarch64/$(FEDORA_KERNEL_CORE_RPM_aarch64)

# kernel-modules-core (contains core .ko modules including gve and ena)
FEDORA_KERNEL_MODULES_SHA256_x86_64 := 7d9e7d9f925de56f04c103a65011285d0ded2fc45a79ca1b300828316916200c
FEDORA_KERNEL_MODULES_SHA256_aarch64 := 4bbe3e2922b044519d126cc1a06f0416d3f4f26523f0bae75d5fe355d4abb7ac
FEDORA_KERNEL_MODULES_RPM_x86_64 := kernel-modules-core-$(FEDORA_KERNEL_VERSION).x86_64.rpm
FEDORA_KERNEL_MODULES_RPM_aarch64 := kernel-modules-core-$(FEDORA_KERNEL_VERSION).aarch64.rpm
FEDORA_KERNEL_MODULES_URL_x86_64 := $(FEDORA_KERNEL_BASE_URL)/x86_64/$(FEDORA_KERNEL_MODULES_RPM_x86_64)
FEDORA_KERNEL_MODULES_URL_aarch64 := $(FEDORA_KERNEL_BASE_URL)/aarch64/$(FEDORA_KERNEL_MODULES_RPM_aarch64)

ARCHS = x86_64 aarch64
TARGETS = busybox stub.efi kernel-core.rpm kernel-modules-core.rpm

all: $(ARCHS)

x86_64: $(addprefix x86_64/,$(TARGETS))
aarch64: $(addprefix aarch64/,$(TARGETS))

%/$(BUSYBOX_APK):
	@./download-and-verify.sh "$@" "$(BUSYBOX_SHA256_$*)" "$(BUSYBOX_URL_$*)"

%/busybox: %/$(BUSYBOX_APK)
	@mkdir -p $*
	@tar --warning=no-unknown-keyword -xzOf $< bin/busybox.static > "$@"
	@chmod +x "$@"

# Download systemd-boot-unsigned RPM from Fedora
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

# Download Fedora kernel-core RPMs from kojipkgs
x86_64/$(FEDORA_KERNEL_CORE_RPM_x86_64):
	@./download-and-verify.sh "$@" "$(FEDORA_KERNEL_CORE_SHA256_x86_64)" "$(FEDORA_KERNEL_CORE_URL_x86_64)"

x86_64/kernel-core.rpm: x86_64/$(FEDORA_KERNEL_CORE_RPM_x86_64)
	@ln -sf $(notdir $<) $@

aarch64/$(FEDORA_KERNEL_CORE_RPM_aarch64):
	@./download-and-verify.sh "$@" "$(FEDORA_KERNEL_CORE_SHA256_aarch64)" "$(FEDORA_KERNEL_CORE_URL_aarch64)"

aarch64/kernel-core.rpm: aarch64/$(FEDORA_KERNEL_CORE_RPM_aarch64)
	@ln -sf $(notdir $<) $@

# Download Fedora kernel-modules-core RPMs from kojipkgs
x86_64/$(FEDORA_KERNEL_MODULES_RPM_x86_64):
	@./download-and-verify.sh "$@" "$(FEDORA_KERNEL_MODULES_SHA256_x86_64)" "$(FEDORA_KERNEL_MODULES_URL_x86_64)"

x86_64/kernel-modules-core.rpm: x86_64/$(FEDORA_KERNEL_MODULES_RPM_x86_64)
	@ln -sf $(notdir $<) $@

aarch64/$(FEDORA_KERNEL_MODULES_RPM_aarch64):
	@./download-and-verify.sh "$@" "$(FEDORA_KERNEL_MODULES_SHA256_aarch64)" "$(FEDORA_KERNEL_MODULES_URL_aarch64)"

aarch64/kernel-modules-core.rpm: aarch64/$(FEDORA_KERNEL_MODULES_RPM_aarch64)
	@ln -sf $(notdir $<) $@

# Retrieve package URLs from koji (for reference)
kernel-hash-%:
	@echo "Fedora kernel: $(FEDORA_KERNEL_PACKAGE)-$(FEDORA_KERNEL_VERSION).$*"
	@echo "Download from: https://koji.fedoraproject.org/koji/buildinfo?buildID=2599252"

clean:
	rm -rf x86_64 aarch64

# Check all download URLs are still valid
check-urls:
	@echo "Checking URLs..."
	@curl -sfI "$(BUSYBOX_URL_x86_64)" > /dev/null && echo "OK: busybox x86_64" || echo "FAIL: busybox x86_64"
	@curl -sfI "$(BUSYBOX_URL_aarch64)" > /dev/null && echo "OK: busybox aarch64" || echo "FAIL: busybox aarch64"
	@curl -sfI "$(SYSTEMD_BOOT_URL_x86_64)" > /dev/null && echo "OK: systemd-boot x86_64" || echo "FAIL: systemd-boot x86_64"
	@curl -sfI "$(SYSTEMD_BOOT_URL_aarch64)" > /dev/null && echo "OK: systemd-boot aarch64" || echo "FAIL: systemd-boot aarch64"
	@curl -sfI "$(FEDORA_KERNEL_CORE_URL_x86_64)" > /dev/null && echo "OK: kernel-core x86_64" || echo "FAIL: kernel-core x86_64"
	@curl -sfI "$(FEDORA_KERNEL_CORE_URL_aarch64)" > /dev/null && echo "OK: kernel-core aarch64" || echo "FAIL: kernel-core aarch64"
	@curl -sfI "$(FEDORA_KERNEL_MODULES_URL_x86_64)" > /dev/null && echo "OK: kernel-modules-core x86_64" || echo "FAIL: kernel-modules-core x86_64"
	@curl -sfI "$(FEDORA_KERNEL_MODULES_URL_aarch64)" > /dev/null && echo "OK: kernel-modules-core aarch64" || echo "FAIL: kernel-modules-core aarch64"
