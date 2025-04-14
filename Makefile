# Include toolbox tasks
include ./.toolbox.mk

# Run go fmt against code
fmt:
	go fmt ./...
	gofmt -s -w .

# Run go vet against code
vet:
	go vet ./...

# Run go golanci-lint
lint: tb.golangci-lint
	$(TB_GOLANGCI_LINT) run --fix

# Run go mod tidy
tidy:
	go mod tidy

# Run tests
test: generate tidy fmt vet lint
	go test ./...  -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Build docker image
build-docker:
	docker build --build-arg upx_brute=" " -t traefik-cert-extractor .

# Build podman image
build-podman:
	podman build --build-arg upx_brute=" " -t traefik-cert-extractor .

release: tb.goreleaser tb.semver
	@version=$$($(TB_SEMVER)); \
	git tag -s $$version -m"Release $$version"
	$(TB_GORELEASER) --clean

test-release: tb.goreleaser
	$(TB_GORELEASER) --skip=publish --snapshot --clean

generate:
	go generate ./...
