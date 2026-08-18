# 0trust client — cross-compile to all major platforms.
#
# Produces statically-linked binaries in dist/.
# Reproducible builds: -trimpath strips local paths, -buildvcs=false drops VCS info.

VERSION := 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILDFLAGS := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: build clean test all

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

test:
	go test ./...

clean:
	rm -rf dist/
