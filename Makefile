# iec104-shield — build/test automation.
# The project is plain Go: `go build ./...` works without make.

BINARY := iec104-shield
GO     ?= go
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test fmt-check vet staticcheck govulncheck race verify acceptance peers interop interop-required cover release release-all release-assets sbom vulnscan security clean

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/iec104-shield

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; fi

test: fmt-check
	# -p 1: fixtures bind and probe TCP ports; serialising packages keeps
	# the socket tests deterministic.
	$(GO) test ./... -p 1 -race -timeout 600s

vet:
	$(GO) vet ./...

staticcheck:
	~/go/bin/staticcheck ./...

govulncheck:
	~/go/bin/govulncheck ./...

race: test

verify: build test vet

# Acceptance requires the independent wendy512/iec104 peer. A missing peer
# is a failure, not a skip.
acceptance: verify interop-required

# Release security gate. Requires staticcheck, govulncheck, syft and grype;
# a missing tool fails this target.
security: verify staticcheck govulncheck vulnscan

# peers downloads the independent peer module. It needs network access.
peers:
	cd test/peers/iec104peer && $(GO) mod download

# interop drives the built gateway with an independent IEC-104 master and
# outstation: interrogation, an allowed command, a denied command, and
# fail-closed after the proxy stops. Exit 77 when the peer cannot be built.
interop: build
	sh scripts/interop-iec104.sh

interop-required: build
	INTEROP_REQUIRED=1 sh scripts/interop-iec104.sh

# cover measures statement coverage and enforces the per-package floors.
cover:
	@mkdir -p dist
	$(GO) test ./... -p 1 -covermode=atomic -coverprofile=dist/cover.out -timeout 600s
	$(GO) run ./scripts/covercheck dist/cover.out coverage.floors

# release builds a stripped static binary for appliance deployment.
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/iec104-shield

# release-all cross-builds stripped static binaries for the appliance
# platforms (amd64 + arm64 + armv7) into dist/.
release-all:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/iec104-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/iec104-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-armv7 ./cmd/iec104-shield
	@echo "release binaries written to dist/ ($(BINARY)-linux-{amd64,arm64,armv7}) version $(VERSION)"

# release-assets produces the Linux binaries, per-binary SPDX + CycloneDX
# SBOMs and SHA256SUMS. Requires syft; exits 77 when missing.
release-assets: release-all
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/syft/cmd/syft@latest)"; exit 77; }
	@for bin in dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 dist/$(BINARY)-linux-armv7; do \
		syft "$$bin" -o spdx-json="$$bin.spdx.json" -o cyclonedx-json="$$bin.cdx.json"; \
	done
	@cd dist && shasum -a 256 $(BINARY)-linux-amd64 $(BINARY)-linux-amd64.cdx.json $(BINARY)-linux-amd64.spdx.json \
		$(BINARY)-linux-arm64 $(BINARY)-linux-arm64.cdx.json $(BINARY)-linux-arm64.spdx.json \
		$(BINARY)-linux-armv7 $(BINARY)-linux-armv7.cdx.json $(BINARY)-linux-armv7.spdx.json > SHA256SUMS
	@echo "release assets in dist/ (binaries, SBOMs, SHA256SUMS)"

# sbom generates SPDX + CycloneDX SBOMs for the release binary into dist/.
sbom: release
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/syft/cmd/syft@latest)"; exit 77; }
	@mkdir -p dist
	syft bin/$(BINARY) -o spdx-json=dist/$(BINARY).spdx.json -o cyclonedx-json=dist/$(BINARY).cdx.json
	@echo "SBOMs written to dist/$(BINARY).spdx.json + dist/$(BINARY).cdx.json"

# vulnscan matches the SBOM against vulnerability databases (NVD/GHSA/OSV)
# via grype and fails on findings at severity HIGH or above.
vulnscan: sbom
	@command -v grype >/dev/null 2>&1 || { echo "grype not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/grype/cmd/grype@latest)"; exit 77; }
	grype db update
	grype dist/$(BINARY).spdx.json --fail-on high

clean:
	rm -f bin/$(BINARY)
	rm -rf dist/
