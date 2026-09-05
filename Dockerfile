# Dockerfile for xflow-exporter

FROM scratch

# dockers_v2 lays the build context out as linux/<arch>/<binary>
ARG TARGETPLATFORM

# Copy ca-certificates: the remote write client is the only outbound TLS path
COPY --from=alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

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
