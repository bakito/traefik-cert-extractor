# Run go fmt against code
fmt:
	go fmt ./...
	gofmt -s -w .

# Run go vet against code
vet:
	go vet ./...

# Run golangci-lint
lint: golangci-lint
	golangci-lint run

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

release: goreleaser
	@version=$$(semver); \
	git tag -s $$version -m"Release $$version"
	goreleaser --rm-dist

test-release: goreleaser
	goreleaser --skip-publish --snapshot --rm-dist

tools: golangci-lint goreleaser

generate:
	go generate ./...

goreleaser:
ifeq (, $(shell which goreleaser))
 $(shell go get github.com/goreleaser/goreleaser)
endif
golangci-lint:
ifeq (, $(shell which golangci-lint))
 $(shell go get github.com/golangci/golangci-lint/cmd/golangci-lint)
endif