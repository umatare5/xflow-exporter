# Changelog

Notable changes to the metric surface, one section per release — a short preamble, the breaking change where the release has one, then the metric changes and the flag changes.

A minor release may rename or remove a metric. Every collector module flag is off by default, so a release that adds one adds no series until you set it.

## [Unreleased]

Initial scaffolding: CLI, configuration, HTTP server (`/metrics`, `/healthz`), and the `xflow_build_info` series.

The UDP flow receiver: `--receiver.*` flags, `recvmmsg` batching on Linux, a bounded queue that drops rather than blocks, and the `xflow_receiver_*` health series. Received datagrams are counted and discarded until the decoders land.
