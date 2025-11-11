.PRECIOUS: keys/% downloads/%

all: build

ARCHS=x86_64 aarch64
build: $(ARCHS)

amd64 x86_64: x86_64/boot.disk
arm64 aarch64: aarch64/boot.disk

DEFAULT_STAGE2_URL = https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/user-data.json
user-data.json:
	wget -O "$@" $(DEFAULT_STAGE2_URL)

# Docker image names
BUILD_IMAGE = lockboot:build
DEV_IMAGE = lockboot:dev
RUNTIME_IMAGE ?= lockboot:latest

keys/%:
	$(MAKE) -C keys

clean:
	rm -rf $(ARCHS)

distclean: clean
	$(MAKE) -C downloads clean
	$(MAKE) -C keys clean

# Generate separate rules for each artifact to avoid grouped target behavior
define ARTIFACT_RULE
.PRECIOUS: %/$(1)
%/$(1)::
	@mkdir -p $$*
	@make -C downloads $$@
	@cp downloads/$$@ $$@
endef

$(foreach artifact,busybox bubblewrap stub.efi kernel.rpm,$(eval $(call ARTIFACT_RULE,$(artifact))))

downloads/%:
	$(MAKE) -C downloads $*


#####################################################################
# Docker build

docker-build-base:
	docker build -f Dockerfile.build -t $(BUILD_IMAGE) .

# Build the dev image (extends build image)
docker-build-dev: docker-build-base
	docker build -f Dockerfile.dev -t $(DEV_IMAGE) .

# Alias for building both
docker-build: docker-build-dev

docker-clean:
	docker rmi $(BUILD_IMAGE) $(DEV_IMAGE) || true

docker-dev: build run

docker-prune-system-wide:
	docker image prune -f
	docker system prune -f
	docker system prune -f --volumes
	docker system df

# Setup buildx builder (run once)
docker-buildx-setup:
	docker buildx create --name lockboot-builder --use || docker buildx use lockboot-builder
	docker buildx inspect --bootstrap

# Build runtime image for current platform only and load into Docker
docker-runtime: x86_64/busybox x86_64/bubblewrap x86_64/stage1 aarch64/busybox aarch64/bubblewrap aarch64/stage1
	docker buildx build \
		-f Dockerfile.runtime \
		-t $(RUNTIME_IMAGE) \
		--load \
		.

# Build multi-arch and export to OCI tar (for local multi-arch without registry)
docker-runtime-oci: x86_64/busybox x86_64/bubblewrap x86_64/stage1 aarch64/busybox aarch64/bubblewrap aarch64/stage1
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile.runtime \
		-t $(RUNTIME_IMAGE) \
		--output type=oci,dest=lockboot.oci \
		.

.PHONY: docker-buildx-setup docker-runtime docker-runtime-push docker-runtime-oci


#####################################################################
# Docker run

USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)

# Options for giving docker kvm access
KVM_GID := $(shell stat -c %g /dev/kvm 2>/dev/null || echo "")
KVM_MOUNT := $(shell test -e /dev/kvm && echo "-v /dev/kvm:/dev/kvm")
DOCKER_GROUP_KVM := $(if $(KVM_GID),--group-add $(KVM_GID))
DOCKER_OPT_KVM := $(DOCKER_GROUP_KVM) $(KVM_MOUNT)

# Options for recursive docker
DOCKER_SOCK_GID := $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo "")
DOCKER_SOCK_MOUNT := $(shell test -e /var/run/docker.sock && echo "-v /var/run/docker.sock:/var/run/docker.sock")
DOCKER_GROUP_DOCKER := $(if $(DOCKER_SOCK_GID),--group-add $(DOCKER_SOCK_GID))
DOCKER_OPT_DOCKER := $(DOCKER_SOCK_MOUNT) $(DOCKER_GROUP_DOCKER)

DOCKER_SAMEUSER := -u $(USER_ID):$(GROUP_ID)

# Base docker run command with all common flags
DOCKER_RUN = docker run --rm \
	--privileged \
	-v $(CURDIR):/src \
	-h lockboot \
	--add-host lockboot:127.0.0.1 \
	-e OWNER_UID=$(USER_ID) \
	-e OWNER_GID=$(GROUP_ID) \
	-w /src

docker-shell-base: docker-build-base
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash

docker-shell-dev: docker-build-dev
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(DOCKER_OPT_DOCKER) $(DOCKER_OPT_KVM) $(DEV_IMAGE) bash

# Build the UKI and boot disk for a specific architecture
# This creates: UKI, disk image with EFI boot structure
%/boot.disk: %/busybox %/bubblewrap %/stage1 %/stub.efi %/kernel.rpm keys/db.crt
	$(DOCKER_RUN) $(DOCKER_OPT_DOCKER) -e ARCH=$* \
		$(BUILD_IMAGE) ./scripts/build.sh

boot-%: downloads/ec2-metadata-mock-linux-amd64 %/boot.disk user-data.json
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_OPT_KVM) \
		-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
		$(DEV_IMAGE) ./scripts/boot.sh

%/stage1: docker-build-base
	mkdir -p $*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-linux-musl && cargo build --release --locked --all --target $*-unknown-linux-musl"
	cp target/$*-unknown-linux-musl/release/stage1 $@


#####################################################################

# Git tagging helpers
TAG ?= v0.1.0

# Create and push a new tag (or recreate if it exists)
tag:
	@echo "Creating tag: $(TAG)"
	git tag -d $(TAG) 2>/dev/null || true
	git push origin :refs/tags/$(TAG) 2>/dev/null || true
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)

# Delete a tag locally and remotely
untag:
	@echo "Deleting tag: $(TAG)"
	git tag -d $(TAG) 2>/dev/null || true
	git push origin :refs/tags/$(TAG) 2>/dev/null || true

# List all tags
list-tags:
	git tag -l

# Amend the most recent commit with staged changes
git-edit:
	git commit --amend --no-edit
