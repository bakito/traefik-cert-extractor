FROM scratch

CMD ["/opt/go/traefik-cert-extractor"]

EXPOSE 8080

COPY ./traefik-cert-extractor opt/go/traefik-cert-extractor
WORKDIR /opt/go/

