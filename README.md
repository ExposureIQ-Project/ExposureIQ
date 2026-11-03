# ExposureIQ <img src="assets/branding/icon-tight.svg" height="25" alt="ExposureIQ logo">

![ExposureIQ](./assets/branding/banner.png)

**Discover your attack surface. Track what changes. Turn findings into reports.**

An open-source attack surface management (ASM) tool written in Python: a
deterministic scanner, scan-to-scan diffing, and a built-in HTML/PDF reporting
engine. An optional, advisory-only AI layer is planned; it will only draft text
from structured findings and will never scan or act.

**Status:** active development. Stages 1–4 (discovery, checks, diffing, reports)
are implemented. Python 3.10+, MIT license.

---

## Why ExposureIQ?

Most organizations do not know everything they expose to the internet, and they
notice changes too late: a forgotten staging subdomain, a database port opened
"temporarily", a service that quietly went out of date.

ExposureIQ is built around three ideas:

1. **Discover** external assets: subdomains, IP addresses, open ports, and services.
2. **Diff** two scans to show what is new, changed, or gone.
3. **Report** the result as a clear document for engineers and decision makers.

### Design principles

- **The scanner is deterministic.** Same input, same behaviour. No AI is involved
  in discovery, probing, or severity decisions.
- **AI is optional and advisory.** The planned AI layer only reads structured
  findings and writes draft text. It never chooses targets, runs tools, or acts.
- **Local-first.** The AI layer is designed for local models (via Ollama), so
  scan data does not have to leave the machine.
- **One shared schema.** Every stage reads and writes the same versioned JSON
  format, so parts can be extended independently.
- **Humans stay in the loop.** Findings and report text are evidence for review,
  not automatic proof of a vulnerability.

---

## Features

| Area | Capability | Status |
| --- | --- | --- |
| **Discovery** | Subdomain enumeration (Subfinder, with a crt.sh fallback) | Done |
| | DNS resolution (A and AAAA) | Done |
| | Top-100 TCP port scan with Nmap, scope-gated | Done |
| **Fingerprinting** | Technology hints from headers and HTML | Done |
| | Security-headers check | Done |
| | HTTPS certificate checks | Done |
| | Risky-service rules on open ports | Done |
| | Severity, recommendation, and scan wiring | Done |
| **Storage** | Versioned JSON snapshots (schema 0.1 and 0.2) | Done |
| **Diffing** | New, changed, and removed assets, ports, technologies, findings | Done |
| | Ignore rules and confirmed-removal checks | Done |
| | Diff view in the terminal UI | Done |
| **Reporting** | Branded HTML report with executive summary on page 1 | Done |
| | Findings table with severity colours | Done |
| | "What changed" section from the Stage 3 summary | Done |
| | Charts: findings by severity, assets over time | Done |
| | PDF export with no external PDF dependency | Done |
| | Automatic PDF after a successful scan | Done |
| | `exposureiq report` command | Done |
| | DOCX output and custom templates | Planned |
| **AI (optional)** | Risk prioritisation and plain-language drafting | Planned |

---

## Quick start

```bash
git clone https://github.com/ExposureIQ-Project/ExposureIQ.git
cd ExposureIQ
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 1. Scan a domain you own or are authorised to test.
exposureiq scan example.com

# 2. See what changed since the previous saved scan.
exposureiq diff example.com

# 3. Generate an HTML and PDF report from the newest saved scan.
exposureiq report example.com

# Or choose the files explicitly.
exposureiq report results/example.com_2026-10-13T20-15-00Z.json -o assessment.pdf
```

`scan` writes JSON to `results/` (git-ignored). After a successful save it also
builds a PDF automatically in `report/` (git-ignored). `report` writes there by
default:

- `report/<target>_<scan-id>.html`
- `report/<target>_<scan-id>.pdf`

Use `scan --no-report` if you only want the JSON snapshot.

Useful report options:

```bash
exposureiq report example.com --format html      # HTML only
exposureiq report example.com --format pdf       # PDF only
exposureiq report example.com -o out/report.html # explicit file (format inferred)
exposureiq report example.com --compare old.json # explicit older scan
exposureiq report example.com --no-diff          # skip the change section
```

The report command is offline: it reads saved JSON and never sends traffic.

### Requirements

- Python 3.10+
- [Nmap](https://nmap.org/) for port scanning (optional; passive discovery still works)
- [Subfinder](https://github.com/projectdiscovery/subfinder) for broader subdomain
  discovery (optional; crt.sh is the fallback)
- No PDF library, browser, or network connection is needed to build a report.

---

## How it works

```
exposureiq scan <domain>
  normalize/validate domain
  -> subdomain discovery (Subfinder, crt.sh fallback)
  -> DNS resolution (A/AAAA)
  -> scoped HTTP/TLS checks and top-100 TCP scan
  -> build and validate a scan snapshot
  -> save results/<target>_<time>.json
  -> build report/<target>_<scan-id>.pdf (skip with --no-report)

exposureiq diff <domain | OLD.json NEW.json>
  -> pure comparison + ignore rules + readable summary

exposureiq report <domain | scan.json>
  -> load the newest saved scan
  -> find the previous scan for the same target
  -> build the report model and render HTML/PDF
```

The findings format is documented in
[`docs/findings-format.md`](docs/findings-format.md). The report command and
output sections are documented in [`docs/report-format.md`](docs/report-format.md).

---

## Example finding

```json
{
  "id": "F-0042",
  "rule": "ports.database_exposed",
  "check": "risky_services",
  "severity": "high",
  "title": "Database service exposed",
  "detail": "MySQL is reachable on tcp/3306",
  "recommendation": "Restrict the port to trusted networks or remove public access."
}
```

Findings live inside each asset in the scan snapshot, together with `host`,
`ips`, `technologies`, and `open_ports`. The report model adds presentation data
(counts, risk level, chart points) but never changes the saved scan.

---

## Project structure

```
ExposureIQ/
├── exposureiq/
│   ├── discovery/       # subdomains, DNS, scope, Nmap ports
│   ├── fingerprint/     # technology, headers, HTTPS, risky ports, severity
│   ├── diffing/         # compare, noise rules, summary, pipeline
│   ├── report/          # model, HTML, PDF, SVG charts, branding
│   ├── tui/             # Textual interface and shared scan pipeline
│   ├── cli.py           # command-line entry point
│   ├── output.py        # terminal UI and colours
│   └── storage.py       # JSON build/save/load and validation
├── assets/branding/     # logo and banner assets
├── docs/                # format specifications and examples
├── tests/               # pytest suite (no internet, no Nmap/Subfinder needed)
├── scope.txt            # targets that may be actively probed
├── ignore.txt           # optional diff noise rules
├── run.sh               # install / test / scan helper
└── pyproject.toml
```

---

## Responsible use

ExposureIQ **actively probes systems** when you run a normal scan.

- Only scan assets you **own** or have **explicit written permission** to test.
- Passive lookups (DNS and subdomain data) are safe on any domain; HTTP, TLS, and
  port probes are active and are gated by `scope.txt`.
- Unauthorized scanning may be illegal in your jurisdiction.
- If the scope check is missing or broken, active probes fail closed.
- ExposureIQ does not exploit services, brute force logins, or crawl beyond the
  front page.

The authors accept no responsibility for misuse.

### About the AI layer

AI output can be wrong. It is meant to save writing time, not replace judgement.
Any AI-generated text will be labelled as a draft for review before it is shared.

---

## Development

```bash
python -m pytest -q
```

The tests use saved sample responses and fakes. They do not need the internet,
Nmap, Subfinder, or any unmerged module.

### Git workflow

- Never commit to `main`. One task = one branch = one pull request.
- Branch names: `<type>/s<stage>-<short-name>`, for example
  `feature/s4-reports`.
- Commit messages: `type(scope): summary`, then `What I did:`, `Why:`,
  `How to test:`, and `Stage: <n>, <task>`.

---

## Contributing

Contributions are welcome, from code to docs to bug reports and ideas.

1. Check the [issues](https://github.com/ExposureIQ-Project/ExposureIQ/issues) or
   open one to discuss an idea first.
2. Fork the repository and create a branch.
3. Make the change, add tests where it makes sense, and open a pull request.

**Security issues:** please do not open a public issue for vulnerabilities in
ExposureIQ itself. Contact the maintainers privately.

---

## License

Released under the [MIT License](LICENSE).

---

If ExposureIQ sounds useful, a star on the repository helps others find it.
