# ExposureIQ Findings Format

## Overview

ExposureIQ stores scan results as JSON files. This document describes the fields used in the findings format for schema version `0.1`.

## Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | String | Version of the findings schema. Currently `0.1`. |
| `scan_id` | String | Unique identifier for the scan. |
| `target` | String | Main target associated with the scan. |
| `started_at` | String | Scan start time in UTC, using ISO 8601 format (for example `2026-10-13T20:15:00Z`). |
| `assets` | Array | List of discovered assets and their network information. |

## Asset Fields

Each object in `assets` represents a discovered host.

| Field | Type | Description |
|---|---|---|
| `host` | String | Hostname or subdomain, such as `api.example.com`. |
| `ips` | Array | IP addresses associated with the host. |

## IP Fields

Each object in an asset's `ips` array contains:

| Field | Type | Description |
|---|---|---|
| `ip` | String | A valid IPv4 or IPv6 address associated with the host. |
| `open_ports` | Array | List of open ports identified for the IP address. An empty array means no open ports are recorded. |

## Open Port Fields

Each object in `open_ports` contains:

| Field | Type | Description |
|---|---|---|
| `port` | Integer | Port number from 1 to 65535. |
| `protocol` | String | Transport protocol, such as `tcp`. |
| `service` | String | Service name, such as `https` or `ssh`. |

## Example

A complete example is available at [`docs/examples/scan-example.json`](examples/scan-example.json).

The example uses `example.com` and IP addresses from the documentation-only range `203.0.113.0/24`. These addresses are reserved for examples and should not be treated as real scan results.

## Validation and Storage

The storage module (`exposureiq/storage.py`) provides these functions:

- `build_scan(target, assets, started_at=None)`: creates a scan result using the current schema version. If `started_at` is not given, the current UTC time is used.
- `save_scan(scan, path)`: validates and writes scan data as readable UTF-8 JSON. Missing folders are created.
- `load_scan(path)`: reads JSON, validates the required fields and schema version, and returns the scan data.

Invalid JSON, unsupported schema versions, missing required fields, invalid IP addresses, and invalid field values produce clear errors.

## Compatibility

The schema version is `0.1`. Changes to field names or structure should be coordinated with the ExposureIQ team before implementation.
