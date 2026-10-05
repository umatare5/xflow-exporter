# Dockerfile for xflow-exporter

FROM scratch

# dockers_v2 lays the build context out as linux/<arch>/<binary>
ARG TARGETPLATFORM

# Copy ca-certificates: the remote write client is the only outbound TLS path
COPY --from=alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the pre-built binary from GoReleaser
COPY $TARGETPLATFORM/xflow-exporter /xflow-exporter

# extra_files in .goreleaser.yml is what puts these in the build context
COPY LICENSE NOTICE /

# Create a non-root user (using numeric ID for scratch image)
USER 65534:65534

# Declare the ports; publishing them still requires docker run -p.
# 10053 serves /metrics and 4739/udp is the default flow receiver port.
EXPOSE 10053
EXPOSE 4739/udp

ENTRYPOINT ["/xflow-exporter"]
