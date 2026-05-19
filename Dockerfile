# Multi-stage build with explicit platform specification
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder


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
