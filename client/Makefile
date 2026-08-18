# 0trust client — cross-compile to all major platforms.
#
# Produces statically-linked binaries in dist/.
# Reproducible builds: -trimpath strips local paths, -buildvcs=false drops VCS info.
#
# Two naming schemes, on purpose:
#
#   all                 dist/0trust-$(VERSION)-<os>-<arch>   release artifacts.
#                       scripts/release.sh copies these verbatim into
#                       releases/<version>/ and signs their SHA256SUMS, so the
#                       version has to be in the filename.
#
#   linux/darwin/windows
#                       dist/0trust-<os>-<arch>              installer inputs.
#                       The .deb, AppImage and MSI builders all reference the
#                       bare name; keeping the version out of it means the
#                       installer sources don't churn on every release.

VERSION := 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILDFLAGS := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

LINUX_ARCHES   := amd64 arm64
DARWIN_ARCHES  := amd64 arm64
WINDOWS_ARCHES := amd64 arm64

.PHONY: build clean test all linux darwin windows

build:
	go build $(BUILDFLAGS) -o dist/0trust ./cmd/0trust

all: clean
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "→ $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build $(BUILDFLAGS) \
				-o dist/0trust-$(VERSION)-$$os-$$arch$$ext \
				./cmd/0trust; \
	done
	@(cd dist && sha256sum 0trust-* > SHA256SUMS)
	@echo "✓ built $$(ls dist/0trust-* | wc -l) binaries"
	@echo "  signed checksums: gpg --detach-sign dist/SHA256SUMS"

# --- Per-OS targets: unversioned names, consumed by the installer builders ---

linux:
	@mkdir -p dist
	@for arch in $(LINUX_ARCHES); do \
		echo "→ linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
			go build $(BUILDFLAGS) -o dist/0trust-linux-$$arch ./cmd/0trust; \
	done

darwin:
	@mkdir -p dist
	@for arch in $(DARWIN_ARCHES); do \
		echo "→ darwin/$$arch"; \
		CGO_ENABLED=0 GOOS=darwin GOARCH=$$arch \
			go build $(BUILDFLAGS) -o dist/0trust-darwin-$$arch ./cmd/0trust; \
	done

windows:
	@mkdir -p dist
	@for arch in $(WINDOWS_ARCHES); do \
		echo "→ windows/$$arch"; \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch \
			go build $(BUILDFLAGS) -o dist/0trust-windows-$$arch.exe ./cmd/0trust; \
	done

test:
	go test ./...

clean:
	rm -rf dist/
