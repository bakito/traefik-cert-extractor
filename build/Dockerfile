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

RUN make generate \
  && go build -a -installsuffix cgo -o traefik-cert-extractor . \
  && upx -q traefik-cert-extractor

# application image
FROM scratch
WORKDIR /opt/go

LABEL maintainer="bakito <github@bakito.ch>"
EXPOSE 8080
ENTRYPOINT ["/opt/go/traefik-cert-extractor"]

COPY --from=builder /build/traefik-cert-extractor  /opt/go/traefik-cert-extractor
