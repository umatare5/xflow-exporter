# Documentation

This directory contains the documentation for xflow-exporter's implementation, features, and technical details.

Following pages describe the implementation details of the exporter.

## For Users Docs

- **[Collectors](collectors.md)**

  This documentation provides an overview of the collectors supported by the xflow-exporter. If you are new to the xflow-exporter, it's recommended to start with the overview section of this documentation.

- **[Health](health.md)**

  This documentation provides an overview of the health metrics exposed by the xflow-exporter. If you want to monitor the health and performance of the exporter, this section is essential.

- **[Enrichment](enrichment.md)**

  This documentation provides an overview of the enrichments supported by the xflow-exporter, AS, countries, threats and mappings. If you want to understand how the exporter enriches the collected data, this section is essential.

- **[Help](help.md)**

  The dump of the `xflow-exporter --help` — showing all available command-line options and their descriptions.

## For Developers Docs

- **[Architecture](architecture.md)**

  This document preserves the foundational design and architectural principles of the xflow-exporter.

- **[Protocols](protocols.md)**

  This documentation provides an overview of the supported protocols and their verification matrix. This document deepdives into the Netflow v5,v8,v9, IPFIX, and sFlow protocols. It's for the development and maintenance of the xflow-exporter.
