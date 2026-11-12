# Dockerfile for xflow-exporter

FROM scratch

# dockers_v2 lays the build context out as linux/<arch>/<binary>
ARG TARGETPLATFORM

# Copy ca-certificates: the remote write client is the only outbound TLS path
COPY --from=alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

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
