FROM docker.io/library/golang:1.16 as builder

WORKDIR /go/src/app

RUN apt-get update && apt-get install -y upx

ARG VERSION=master
ENV GOPROXY=https://goproxy.io \
  GO111MODULE=on \
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
ENTRYPOINT ["/opt/go/traefik-cert-extractor"]

COPY --from=builder /go/src/app/traefik-cert-extractor  /opt/go/traefik-cert-extractor
