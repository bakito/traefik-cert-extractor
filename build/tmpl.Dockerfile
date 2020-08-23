FROM golang:1.14 as builder

WORKDIR /build

RUN apt-get update && apt-get install -y upx

ENV GOPROXY=https://goproxy.io \
  GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH={{ .GoARCH }}\
  GOARM={{ .GoARM }}
COPY . .

RUN go build -a -installsuffix cgo -o traefik-cert-extractor . && \
  upx -q traefik-cert-extractor

# application image
FROM scratch
WORKDIR /opt/go

LABEL maintainer="bakito <github@bakito.ch>"
EXPOSE 8080
ENTRYPOINT ["/opt/go/traefik-cert-extractor"]

COPY --from=builder /build/traefik-cert-extractor  /opt/go/traefik-cert-extractor