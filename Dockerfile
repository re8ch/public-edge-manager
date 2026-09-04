FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/re8ch/public-edge-manager" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app
COPY src/public_edge_manager /app/public_edge_manager
USER 65532:65532
EXPOSE 53/udp 53/tcp 8080/tcp
ENTRYPOINT ["python3", "-m", "public_edge_manager"]
