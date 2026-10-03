# ExposureIQ

> Discover your attack surface. Track what changes. Turn findings into reports.

ExposureIQ is a Python attack surface management (ASM) tool with a built-in reporting engine and an **optional, advisory-only AI analysis layer**. The core scanner is fully deterministic and works without AI. The AI layer only reads the structured data the scanner produces to help prioritize findings and draft report text.

> **Status:** Early development (university project). Interfaces and file formats may change.

---

## Features

### ASM core (no AI)
- **Asset discovery**: subdomain enumeration (certificate transparency, DNS)
- **Port and service scanning**: Nmap integration
- **Fingerprinting**: tech stack and version detection, basic checks (e.g. missing security headers, outdated software)
- **Scan diffing**: compare scans to show new, changed, and removed assets
- **Structured storage**: all results saved in a shared JSON/YAML findings schema

### Reporting engine
- Generates consistent reports (HTML/PDF/DOCX) from structured findings
- Cover page, executive summary, severity breakdown charts, findings table, remediation section
- Configurable branding and templates

### AI analysis layer (optional)
- Risk prioritization and triage of findings
- Plain-language explanations for non-technical readers
- Significance analysis of changes between scans
- Draft executive summary and remediation text (human reviews and edits)

**The AI never decides what to scan and never executes anything.** It only reads existing data and writes text. All AI output is a draft for a human to review.

---

## Architecture

```
 Target scope
      |
      v
+--------------+     +---------------+     +----------------+
|  Discovery   | --> | Fingerprinting| --> |  Findings store|
| (subdomains, |     | and diffing   |     |  (JSON/YAML)   |
|  ports)      |     |               |     +--------+-------+
+--------------+     +---------------+              |
                                          +---------+---------+
                                          |                   |
                                          v                   v
                                 +----------------+   +----------------+
                                 | Report engine  |   | AI layer       |
                                 | (Jinja2, PDF/  |<--| (optional,     |
                                 |  DOCX, charts) |   |  advisory only)|
                                 +----------------+   +----------------+
```

---

## Planned CLI

```bash
exposureiq scan example.com            # discover assets, ports, services
exposureiq diff scan_old.json scan_new.json   # show what changed
exposureiq report findings.json -o report.pdf  # generate a report
exposureiq report findings.json --ai-assist    # optional AI-drafted sections
```

> Commands are planned and may change as development progresses.

---

## Installation

```bash
git clone https://github.com/<your-org>/exposureiq.git
cd exposureiq
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Requirements**
- Python 3.10+
- [Nmap](https://nmap.org/) installed and on your PATH
- (Optional, for the AI layer) [Ollama](https://ollama.com/) with a local model

---

## Project structure

```
exposureiq/
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

## Roadmap

- [ ] **Week 1**: Findings schema, subdomain and port discovery, AI environment setup
- [ ] **Week 2**: Fingerprinting, scan diffing, first AI triage experiments
- [ ] **Week 3**: Report engine, AI-assisted drafting, end-to-end pipeline
- [ ] **Week 4**: Evaluation of AI accuracy and hallucinations, CLI polish, docs, live demo

---

## Responsible use

ExposureIQ actively probes systems. **Only scan assets you own or have explicit written permission to test.** Unauthorized scanning may be illegal. The authors accept no responsibility for misuse.

For development and demos, use a lab environment or domains you control.

---

## Team

| Role | Focus | Member |
|------|-------|--------|
| ASM core | Discovery, port scanning, fingerprinting | _TBD_ |
| Diffing and data layer | Scan comparison, schema, storage | _TBD_ |
| AI triage and analysis | Prompts, prioritization, evaluation | _TBD_ |
| Reporting and integration | Report engine, CLI, docs, demo | _TBD_ |

---

## License

To be decided. Suggested: [MIT](https://choosealicense.com/licenses/mit/).
