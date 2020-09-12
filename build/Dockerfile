FROM golang:1.15 as builder

WORKDIR /build

RUN apt-get update && apt-get install -y upx

ARG ARG_GOARCH=amd64
ARG ARG_GOARM
ENV GOPROXY=https://goproxy.io \
  GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=${ARG_GOARCH}\
  GOARM=${ARG_GOARM}
COPY . .

RUN if GIT_TAG=$(git describe --tags --abbrev=0 --exact-match 2>/dev/null); then VERSION=${GIT_TAG}; else VERSION=$(git rev-parse --short HEAD); fi \
  && echo Building version ${VERSION} \
  && go build -a -installsuffix cgo -ldflags="-w -s -X github.com/bakito/traefik-cert-extractor/version.Version=${VERSION}" -o traefik-cert-extractor . \
  && upx -q traefik-cert-extractor

# application image
FROM scratch
WORKDIR /opt/go

LABEL maintainer="bakito <github@bakito.ch>"
EXPOSE 8080
ENTRYPOINT ["/opt/go/traefik-cert-extractor"]

COPY --from=builder /build/traefik-cert-extractor  /opt/go/traefik-cert-extractor
