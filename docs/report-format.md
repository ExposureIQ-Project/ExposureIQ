# ExposureIQ Report Format (Stage 4)

## Overview

`exposureiq report` turns one saved scan snapshot into a professional document.
It reads the same validated JSON that `exposureiq scan` writes (schema `0.1` or
`0.2`) and produces:

- a self-contained **HTML** file, and/or
- a portable **PDF** file.

Both files are generated locally. The command never sends HTTP, TLS, or port
traffic to the target.

## Command

```bash
exposureiq report <scan.json | domain> [options]
```

| Option | Meaning |
| --- | --- |
| `source` | A saved scan file, or a domain whose newest scan is in `results/`. |
| `-o, --output PATH` | An `.html`/`.pdf` file, or a directory. Default: `report/`. |
| `--format html\|pdf\|both` | Override the format. A file extension also selects it. |
| `--compare OLD.json` | Use an explicit older scan for "What changed". |
| `--no-diff` | Skip the change section entirely. |
| `--results-dir DIR` | Where to look for scan history. Default: `results/`. |
| `--title TEXT` | Replace "Security Assessment Report" on the cover. |
| `--open` | Open the HTML report in the default browser. |

When `--compare` is omitted, the command uses the newest earlier scan for the
same target from `--results-dir`. If no earlier scan exists, the report explains
that the change section is unavailable. Demo snapshots (`DEMO-…`) are never
mixed into a real report.

Output naming:

- No `-o`: `report/<target>_<scan-id>.html` and `.pdf`.
- `-o report.pdf`: only `report.pdf` (format inferred from the extension).
- `-o report.html --format both`: `report.html` and `report.pdf`.
- `-o out/` or `-o out`: both formats inside `out/`.

## Automatic report after a scan

A successful `exposureiq scan` builds a PDF automatically in `report/`, using the
same report model and the previous saved scan for the change section. This works
in both the terminal UI and `--plain` output. The scan summary shows the report
path.

Use `exposureiq scan <domain> --no-report` to keep the JSON snapshot only.
Reports are skipped automatically with `--no-save`.

## Report sections

1. **Cover + executive summary (page 1)** — brand logo, target, scan time, risk
   badge, plain-language summary, and severity totals. The executive summary is
   on the first page as requested for Stage 4.
2. **Findings** — every finding ordered by severity, with a coloured badge,
   asset, evidence, rule ID, and recommendation.
3. **What changed** — the Stage 3 summary: headline, worse/better/neutral
   counts, highlights, all change lines, and any confirmation notes.
4. **Exposure at a glance** — a donut chart of findings by severity and a line
   chart of hosts across saved scans.
5. **Asset inventory** — hosts, IP addresses, open ports, technologies, and
   finding counts, including assets with no findings.
6. **Methodology and scope** — what was checked, the scope/safety model, severity
   definitions, report metadata, and a point-in-time disclaimer.

## Data model

`exposureiq.report.model.build_report()` is pure data work. It takes:

- a validated scan dictionary,
- an optional Stage 3 diff document,
- an optional list of older scans for the trend chart,
- an optional generation timestamp and title.

It returns a plain dictionary with `counts`, `severity`, `risk`, `findings`,
`assets`, `history`, `diff_summary`, `executive_summary`, and presentation rows.
The saved scan is never modified.

## Branding

Colours, fonts, severity colours, and the inline logo live in
`exposureiq/report/branding.py`. The HTML uses a system font stack and inline
CSS/SVG, so it works offline and in print. The PDF uses the standard Helvetica
fonts and vector drawing; it does not require WeasyPrint, ReportLab, a headless
browser, or an internet connection.

## PDF limitations

- The PDF writer uses the PDF standard fonts (Helvetica and Helvetica-Bold) with
  WinAnsi text, so very unusual Unicode characters are replaced with `?`.
- It is intentionally small and supports only the layout this report needs:
  text, rules, rectangles, circles, rings, tables, and simple charts.
- For heavily customised reports, the HTML output can be printed to PDF by a
  browser without changing the data.

## Tests

The report tests live in `tests/test_report_*.py`. They use the checked-in
example scan, temporary directories, and fixed timestamps. They do not need the
internet, a browser, or a PDF library.
