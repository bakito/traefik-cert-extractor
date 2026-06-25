# Multi-stage build with explicit platform specification
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder


WORKDIR /go/src/app

RUN apk add --no-cache upx

ARG VERSION=main
ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux

ADD . /go/src/app/

RUN go build -a -installsuffix cgo -ldflags="-w -s -X github.com/bakito/traefik-cert-extractor/version.Version=${VERSION}" -o traefik-cert-extractor . \
  && upx -q traefik-cert-extractor

# application image
FROM scratch
WORKDIR /opt/go

LABEL maintainer="bakito <github@bakito.ch>"
EXPOSE 8080
HEALTHCHECK CMD ["/opt/go/traefik-cert-extractor", "-healthz"]
ENTRYPOINT ["/opt/go/traefik-cert-extractor"]

COPY --from=builder /go/src/app/traefik-cert-extractor  /opt/go/traefik-cert-extractor
