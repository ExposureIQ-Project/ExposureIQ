# ExposureIQ Findings Format

## Overview

ExposureIQ stores scan results as JSON files. This document describes the fields used in the findings format for schema version `0.2`.

Version `0.2` adds two optional lists to every asset: `technologies` and `findings`. Old `0.1` files still load without any change.

## Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | String | Version of the findings schema. New scans use `0.2`. Files with `0.1` or `0.2` can be loaded. |
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
| `technologies` | Array | Optional (0.2). Technologies detected on the host. |
| `findings` | Array | Optional (0.2). Security findings for the host. |

A scan that was made without checks has neither list. If a list exists, it must be valid.

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

## Technology Fields (0.2)

Each object in `technologies` contains:

| Field | Type | Description |
|---|---|---|
| `name` | String | Product name, such as `nginx`. Not empty. |
| `version` | String | Version, such as `1.18.0`. May be an empty string if the version is unknown. |
| `source` | String | Where it was seen, such as `Server header`. Not empty. |

## Finding Fields (0.2)

Each object in `findings` contains:

| Field | Type | Description |
|---|---|---|
| `id` | String | Finding ID, such as `F-0001`. |
| `rule` | String | Rule ID, such as `https.cert_expired`. |
| `check` | String | Check that found it, such as `https` or `security_headers`. |
| `severity` | String | Only `low`, `medium` or `high`. |
| `title` | String | Short title. |
| `detail` | String | What was found, for this host. |
| `recommendation` | String | What to do about it. |
| `ip` | String | Optional. A valid IPv4 or IPv6 address (used by port findings). |
| `port` | Integer | Optional. Port number from 1 to 65535 (used by port findings). |

All text fields except the optional ones must be non-empty strings.

## Example

A complete example is available at [`docs/examples/scan-example.json`](examples/scan-example.json).

The example uses `example.com` and IP addresses from the documentation-only range `203.0.113.0/24`. These addresses are reserved for examples and should not be treated as real scan results.

## Validation and Storage

The storage module (`exposureiq/storage.py`) provides these functions:

- `build_scan(target, assets, started_at=None)`: creates a scan result using the current schema version. If `started_at` is not given, the current UTC time is used.
- `save_scan(scan, path)`: validates and writes scan data as readable UTF-8 JSON. Missing folders are created.
- `load_scan(path)`: reads JSON, validates the required fields and schema version, and returns the scan data.

`save_scan` and `load_scan` accept every version in `SUPPORTED_VERSIONS` (`0.1` and `0.2`). `build_scan` always writes `0.2`.

Invalid JSON, unsupported schema versions, missing required fields, invalid IP addresses, and invalid field values produce clear errors, for example:
`Invalid scan: assets[0].findings[1].severity must be low, medium or high.`

## Compatibility

The current schema version is `0.2`. Version `0.1` files still load. Changes to field names or structure should be coordinated with the ExposureIQ team before implementation.
