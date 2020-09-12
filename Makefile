# Run go fmt against code
fmt:
	go fmt ./...
	gofmt -s -w .

# Run go vet against code
vet:
	go vet ./...

# Run go mod tidy
tidy:
	go mod tidy

# Run tests
test: generate tidy fmt vet
	go test ./...  -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Run ci tests
test-ci: test
	goveralls -service=travis-ci -v -coverprofile=coverage.out

# Build docker image
build-docker:
	docker build --build-arg upx_brute=" " -t traefik-cert-extractor .

# Build podman image
build-podman:
	podman build --build-arg upx_brute=" " -t traefik-cert-extractor .

release: goreleaser
	goreleaser --rm-dist

test-release: goreleaser
	goreleaser --skip-publish --snapshot --rm-dist

licenses: go-licenses
	go-licenses csv "github.com/bakito/traefik-cert-extractor/cmd/generic"  2>/dev/null | sort > ./dependency-licenses.csv

tools: goveralls goreleaser go-licenses


release: goreleaser
	goreleaser --rm-dist

test-release: goreleaser
	goreleaser --skip-publish --snapshot --rm-dist

generate:
	go generate ./...

goveralls:
ifeq (, $(shell which goveralls))
 $(shell go get github.com/mattn/goveralls)
endif
go-licenses:
ifeq (, $(shell which go-licenses))
 $(shell go get github.com/google/go-licenses)
endif
goreleaser:
ifeq (, $(shell which goreleaser))
 $(shell go get github.com/goreleaser/goreleaser)
endif
helm:
ifeq (, $(shell which helm))
 $(shell curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash)
endif