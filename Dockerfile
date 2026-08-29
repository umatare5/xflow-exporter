# Dockerfile for xflow-exporter

FROM scratch

# Copy ca-certificates for HTTPS requests from enrichment modules
COPY --from=alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the pre-built binary from GoReleaser
COPY xflow-exporter /xflow-exporter

# extra_files in .goreleaser.yml is what puts these in the build context
COPY LICENSE NOTICE /

# Create a non-root user (using numeric ID for scratch image)
USER 65534:65534

# Declare the ports; publishing them still requires docker run -p.
# 10052 serves /metrics and 2055/udp is the default flow receiver port.
EXPOSE 10052
EXPOSE 2055/udp

# Set the entrypoint
ENTRYPOINT ["/xflow-exporter"]
