# ExposureIQ

**Discover your attack surface. Track what changes. Turn findings into reports.**

An open-source attack surface management (ASM) tool written in Python, with a deterministic scanner, scan-to-scan diffing, a built-in reporting engine, and an optional, advisory-only AI layer that runs locally.

**Status:** idea and planning stage. Python 3.10+, MIT license.

---

> **Heads up:** ExposureIQ is at the idea stage and no code has been written yet. This README describes what we plan to build; see [Project status](#project-status) for progress. Everything here may change.

## Why ExposureIQ?

Most organizations don't know everything they expose to the internet, and they notice changes too late: a forgotten staging subdomain, a database port opened "temporarily", a service that quietly went out of date.

ExposureIQ is built around three ideas:

1. **Discover**: continuously map external assets (subdomains, open ports, running services).
2. **Diff**: show what is *new, changed, or gone* since the last scan, because change is where risk appears.
3. **Report**: turn raw findings into clear reports that both engineers and non-technical readers can use.

### Design principles

- **The scanner is deterministic.** Same input, same behavior. No AI is involved in discovery or scanning.
- **AI is optional and advisory.** It only reads the structured findings the scanner produced and writes draft text. It never chooses targets, runs tools, or executes anything.
- **Local-first.** The AI layer is designed for local models (via Ollama), so your scan data doesn't have to leave your machine.
- **One shared schema.** Every module reads and writes the same findings format, so parts can be swapped or extended independently.
- **Humans stay in the loop.** All AI output is labeled as a draft for review.

---

## Features

| Area | Capability | Status |
| --- | --- | --- |
| **Discovery** | Subdomain enumeration (certificate transparency, DNS) | Planned |
| | Port and service scanning (Nmap integration) | Planned |
| **Fingerprinting** | Tech stack and version detection | Planned |
| | Basic checks (missing security headers, outdated software) | Planned |
| **Diffing** | Compare two scans: new, changed, removed assets | Planned |
| **Storage** | Structured JSON/YAML findings schema | In design |
| **Reporting** | HTML / PDF / DOCX reports with charts, findings table, remediation | Planned |
| | Custom branding and templates | Planned |
| **AI (optional)** | Risk prioritization and triage | Planned |
| | Plain-language explanations | Planned |
| | Significance analysis of changes between scans | Planned |
| | Draft executive summary and remediation text | Planned |

---

## Architecture

```
 Target scope
      |
      v
+--------------+     +----------------+     +----------------+
|  Discovery   | --> | Fingerprinting | --> | Findings store |
| (subdomains, |     |  and diffing   |     |  (JSON/YAML)   |
|  ports)      |     +----------------+     +--------+-------+
+--------------+                                     |
                                           +---------+---------+
                                           |                   |
                                           v                   v
                                  +----------------+   +----------------+
                                  | Report engine  |<--|  AI layer      |
                                  | (Jinja2, PDF/  |   | (optional,     |
                                  |  DOCX, charts) |   |  advisory only)|
                                  +----------------+   +----------------+
```

The findings store is the contract between every component. If you want to add a new scanner or a new report format, you only need to speak the schema.

---

## Quick start

> **Not yet available.** The commands below describe the planned CLI. They will be enabled as each milestone lands.

```bash
# 1. Install
git clone https://github.com/ExposureIQ-Project/ExposureIQ.git
cd ExposureIQ
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Scan a domain you own
exposureiq scan example.com

# 3. See what changed since last time
exposureiq diff scan_old.json scan_new.json

# 4. Generate a report
exposureiq report findings.json -o report.pdf

# 5. (Optional) Add AI-drafted sections
exposureiq report findings.json --ai-assist
```

### Requirements

- Python 3.10+
- [Nmap](https://nmap.org/) installed and on your `PATH`
- *(Optional, for the AI layer)* [Ollama](https://ollama.com/) with a local model

---

## Example finding (draft schema)

The schema is still being designed, but findings will look roughly like this:

```json
{
  "id": "F-0042",
  "asset": "staging.example.com",
  "type": "open_port",
  "detail": { "port": 8080, "service": "http", "product": "nginx", "version": "1.18.0" },
  "severity": "medium",
  "first_seen": "2026-01-10T09:12:00Z",
  "last_seen": "2026-01-17T09:15:00Z",
  "status": "new"
}
```

---

## Project status

ExposureIQ is at the **idea and planning stage**. Here is where things stand:

- [x] Project vision and architecture (this document)
- [ ] Findings schema
- [ ] Subdomain and port discovery
- [ ] Fingerprinting and basic checks
- [ ] Scan diffing
- [ ] Report engine (HTML first, then PDF/DOCX)
- [ ] AI triage and drafting layer
- [ ] Evaluation of AI accuracy and hallucinations
- [ ] CLI polish, documentation, demo

### Roadmap

| Milestone | Goal |
| --- | --- |
| **v0.1** | Schema, subdomain + port discovery, JSON output |
| **v0.2** | Fingerprinting, scan diffing |
| **v0.3** | Report engine (HTML/PDF/DOCX) |
| **v0.4** | Optional AI layer for triage and drafting, with evaluation |
| **v1.0** | Stable schema and CLI, full documentation |

Have an idea or need? Open an issue and tell us.

---

## Project structure

```
ExposureIQ/
├── exposureiq/
│   ├── discovery/       # subdomain enumeration, port scanning
│   ├── fingerprint/     # service and tech detection
│   ├── diffing/         # scan-to-scan comparison
│   ├── schema/          # shared findings data model
│   ├── report/          # templates, rendering, charts
│   ├── ai/              # optional triage and drafting layer
│   └── cli.py           # command-line entry point
├── templates/           # report templates
├── tests/
├── docs/
├── requirements.txt
└── README.md
```

---

## Responsible use

ExposureIQ **actively probes systems**.

- Only scan assets you **own** or have **explicit written permission** to test.
- Unauthorized scanning may be illegal in your jurisdiction.
- For development and demos, use a lab environment or domains you control.

The authors accept no responsibility for misuse. A scope allowlist and confirmation prompt before scanning are planned to help prevent accidents.

### About the AI layer

AI output can be wrong. It is meant to save you writing time, not to replace your judgment. Always review AI-generated prioritization and text before sharing a report.

---

## Contributing

Contributions are welcome, from code to docs to bug reports and ideas.

1. Check the [issues](https://github.com/ExposureIQ-Project/ExposureIQ/issues) for something to pick up, or open one to discuss your idea first.
2. Fork the repo and create a branch (`git checkout -b feature/my-change`).
3. Make your change, add tests where it makes sense, and open a pull request.

A full `CONTRIBUTING.md` and code of conduct are coming soon.

**Security issues:** please don't open a public issue for vulnerabilities in ExposureIQ itself. Contact the maintainers privately (a `SECURITY.md` with contact details is coming).

---

## Team

Built by a small team that wanted a clear, honest, open tool for understanding external exposure.

| Focus | Maintainer |
| --- | --- |
| ASM core: discovery, port scanning, fingerprinting | *Name / [@github-handle](https://github.com/)* |
| Diffing and data layer: scan comparison, schema, storage | *Name / [@github-handle](https://github.com/)* |
| AI triage and analysis: prompts, prioritization, evaluation | *Name / [@github-handle](https://github.com/)* |
| Reporting and integration: report engine, CLI, docs | *Name / [@github-handle](https://github.com/)* |

---

## License

Released under the [MIT License](LICENSE).

---

If ExposureIQ sounds useful, a star on the repo helps others find it.
