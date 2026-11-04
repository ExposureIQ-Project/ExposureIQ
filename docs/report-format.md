# ExposureIQ Report Format (Stage 4)

## Overview

`exposureiq report` turns saved scan snapshots into an offline domain workspace
or a professional document for the selected scan.
It reads the same validated JSON that `exposureiq scan` writes (schema `0.1` or
`0.2`) and produces:

- a self-contained, interactive **HTML** domain dashboard with selectable scans,
- a portable **PDF** file, or
- an editable **DOCX** (Word) document.

All files are generated locally. The command never sends HTTP, TLS, or port
traffic to the target.

## Command

```bash
exposureiq report <scan.json | domain> [options]
```

| Option | Meaning |
| --- | --- |
| `source` | A saved scan file, or a domain whose newest scan is in `results/<domain>/` or legacy `results/`. |
| `-o, --output PATH` | An exact `.html`/`.pdf`/`.docx` file, or an output root. Default: `report/<domain>/`. |
| `--format html\|pdf\|docx\|both` | Override the format. A file extension also selects it. `both` remains HTML + PDF. |
| `--compare OLD.json` | Use an explicit older baseline for the selected scan's "What changed". |
| `--no-diff` | Disable comparisons; scan selection and charts remain available. |
| `--results-dir DIR` | Results root or the domain's own folder. Default: `results/`. |
| `--title TEXT` | Replace "Security Assessment Report" on the cover. |
| `--open` | Open the HTML report in the default browser. |

When `--compare` is omitted, the **first compatible saved scan** is the baseline.
"What changed" shows both the overall baseline-to-selected change and every
adjacent comparison in between. Overall counts are **net changes**, not a sum
of repeated events: a temporary problem remains visible in the timeline even
if it was fixed before the selected scan.

Each scan's detail history always ends at that scan. For example, scan 5 uses
scans 1–5, while scan 3 uses only scans 1–3, even when later snapshots exist.
This applies to HTML detail views, PDF, DOCX, automatic PDFs, and TUI diff previews.
The HTML **home page** deliberately lists all saved scans for the domain and
shows the full history in separate real/demo groups.
Charts follow the same window; duplicate copies do not count as new scans.
Ordering uses the saved UTC start time, then scan ID for same-time ties—not
the file's modification time.

`--compare OLD.json` chooses an explicit earlier baseline; its change timeline
starts there, while charts still show earlier compatible history. A newer
comparison file or a real/demo mixture is rejected. If no earlier scan exists,
the report explains that the change section is unavailable. Demo snapshots
(`DEMO-…`) are never mixed with real ones, and the `DEMO-HISTORY-…` ten-scan
story is kept separate from unrelated one-off demos.

A removal is "not seen this time" after one absent snapshot, and only confirmed
after two included snapshots agree. Future scans cannot confirm a removal in an
earlier report.

Output naming:

- No `-o`: `report/<domain>/index.html` and
  `report/<domain>/<target>_<scan-id>.pdf`.
- `-o report.pdf`: only `report.pdf` (format inferred from the extension).
- `-o report.html --format both`: `report.html` and `report.pdf`.
- `-o report.docx`: only `report.docx` (format inferred from the extension).
- `--format docx`: `report/<domain>/<target>_<scan-id>.docx`.
- `-o out/` or `-o out`: HTML + PDF inside `out/<domain>/`, unless a format is selected.
- Passing an existing domain folder, such as `-o report/example.com/`, does not
  add a second `example.com` folder.

New scan JSON goes in `results/<domain>/`. Directory overrides also group by
domain, while explicit JSON filenames stay exact. Discovery reads both domain
folders and legacy flat files; exports never move or rewrite old snapshots.

## HTML domain home

`report/<domain>/index.html` is one portable webpage, including its scan detail
views, styles, logo and script. No server, internet connection or sibling HTML
files are needed. Re-exporting any scan refreshes this domain home from all
discoverable saved scans; it does not create another per-scan HTML file.

- **Dated scan cards**, newest first by saved UTC start time, with scan number,
  ID, hosts, ports and severity counts. A card opens that exact saved snapshot;
  **All scans** returns to the home page. Browser Back/Forward also works.
- **Separate real/demo charts and timelines** so simulated findings cannot
  become evidence about a real target.
- **Hover/focus cursor**: a dashed vertical line snaps to the nearest chart
  point, with a small tooltip showing scan number, UTC date and finding counts.
  Clicking a point jumps to its exact dated history entry. Keyboard users can
  move with arrow keys and select with Enter or Space.
- **First-reveal animation**: graphs grow when first scrolled into view, not
  every time they reappear. Reduced-motion preferences disable animation.
- **Past-only detail views**: an older scan's findings, charts and comparisons
  do not use later snapshots, even though later cards exist on the home page.

`--compare` affects only the selected detail view; the home retains the full
timeline. `--no-diff` disables comparison throughout the export. With JavaScript
disabled, the content remains readable as linked sections instead of switchable
views. Printing uses the active home/detail view without hiding chart data.

## Automatic report after a scan

A successful `exposureiq scan` builds a PDF automatically in `report/<domain>/`, using the
same report model and the complete compatible history through that scan. This works
in both the terminal UI and `--plain` output. The scan summary shows the report
path.

Use `exposureiq scan <domain> --no-report` to keep the JSON snapshot only.
Reports are skipped automatically with `--no-save`.
`scan --demos` writes ten deterministic demo snapshots and a separate PDF for
each. The scan 3 PDF contains history through 3; the scan 10 PDF contains the
entire regression/recovery story. See [demo-history.md](demo-history.md).

## TUI exports after a scan

The results screen has an **Export** button in the top-right corner. Click it
or press `e`, then select **HTML** or **DOCX**. Escape or Cancel closes the
picker without writing anything. Export is also available in saved-scan
previews, but is disabled for an unsaved scan or while a scope re-run/export
is in progress.

HTML builds `report/<domain>/index.html` from all discoverable saved scans of
that domain. DOCX uses the exact selected JSON and its past-only history, saved
as `report/<domain>/<target>_<scan-id>.docx`. The results summary and status line
show its path. Export runs outside the UI thread, so the interface stays
responsive. Errors are shown without closing the TUI and can be retried.

The automatic PDF remains unchanged. `--no-report` disables automatic PDF
generation but still allows a manual export when the JSON was saved.
Exporting HTML again refreshes the domain home. Exporting the same DOCX again
replaces that scan's previous DOCX;
other formats and the saved JSON are not changed. No network calls are made.

## Report sections

1. **Cover + executive summary (page 1)** — brand logo, target, scan time, risk
   badge, plain-language summary, and severity totals. The executive summary is
   on the first page as requested for Stage 4.
2. **Findings** — every finding ordered by severity, with a coloured badge,
   asset, evidence, rule ID, and recommendation.
3. **What changed** — the Stage 3 summary: headline, worse/better/neutral
    net counts, highlights, all change lines, confirmation notes, and the full
    scan-by-scan change timeline.
4. **Exposure at a glance** — a donut chart of findings by severity and a line
    chart of hosts, plus total/high-severity findings over time through this scan.
5. **Asset inventory** — hosts, IP addresses, open ports, technologies, and
   finding counts, including assets with no findings.
6. **Methodology and scope** — what was checked, the scope/safety model, severity
    definitions, report metadata, and a point-in-time disclaimer.

HTML places the charts immediately after the overview. DOCX follows the PDF's
section order and styling, with native editable charts, a severity table beside
the donut, and a chart-data appendix containing every included scan's values.
All change lines are retained.

## Data model

`exposureiq.report.model.build_report()` is pure data work. It takes:

- a validated scan dictionary,
- an optional Stage 3 diff document,
- an optional list of older scans for the trend chart,
- an optional generation timestamp and title.
- an optional comparison-enabled flag so an opt-out is not described as missing history.

It returns a plain dictionary with `counts`, `severity`, `risk`, `findings`,
`assets`, `history`, `diff_summary`, `executive_summary`, and presentation rows.
History points include scan ID, scan number, timestamp, UTC date, hosts, open ports and all three
severity counts. `diff.history` contains each adjacent comparison using the
existing diff shape. These are report/diff presentation fields only: the saved
scan schema (`0.1`/`0.2`) is unchanged, and no saved scan is modified.

`exposureiq.report.domain.build_domain_report()` combines these presentation
models into an ordered domain home and independently bounded detail views.
`generate_report()` returns the selected `report` plus the optional `domain`
model; PDF and DOCX remain selected-scan exports.

## Branding

Colours, fonts, severity colours, and the inline logo live in
`exposureiq/report/branding.py`. The HTML uses a system font stack and inline
CSS/SVG, so it works offline and in print. The PDF uses the standard Helvetica
fonts and vector drawing; it does not require WeasyPrint, ReportLab, a headless
browser, or an internet connection. All formats use the current **scan aperture**
icon from `assets/branding/icon.svg`, not the retired triangular mark. HTML
embeds SVG, PDF draws the same shapes as vectors, and DOCX embeds a small PNG
drawn from the same geometry without another image dependency.

HTML's screen layout is a responsive dashboard with rounded panels, section
links, smooth scrolling, and CSS animations. A small, fixed embedded script
handles selection, chart cursors and first-reveal timing, with no remote
dependency or network requests. Animation is disabled for reduced-motion
preferences and printing; print layout stays A4. The document's content
security policy blocks external resources and permits only that script's exact
SHA-256 hash (a fingerprint of its contents). Scan text is HTML-escaped and never
inserted into script source; tooltip text uses `textContent`, not executable HTML.

DOCX uses `python-docx` (installed by `pip install -e .` or
`pip install -r requirements.txt`). It shares the palette, with a dark branded
cover, severity/count cards, printable A4 body pages, section headings, repeating
table headers, and a confidential footer with page numbers. Severity, host-history,
and total/high-finding charts are native Word charts, not screenshots. Right-click
a chart and choose **Edit Data** to change its embedded workbook. Its cached values
and workbook contain only the selected scan and compatible earlier history; no
later snapshots or external data links are included. Chart text and numbers are
also available in ordinary editable tables. Report text stays editable, not
embedded HTML or macros; worksheet strings are literal text, never formulas.
Rendering needs no Office installation, image converter, or network connection.

The same palette is shared with Rich terminal output and the Textual TUI.
Screen reports use dark panels, teal accents, and red/amber/blue for
HIGH/MEDIUM/LOW severity. PDF body pages and HTML print pages stay white for
printing, with pale row fills and dark palette text. Bright severity badges
use dark text for contrast. The PDF's 0–1 RGB values are converted from the
shared hex colours by `branding.hex_to_rgb()`.

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
internet, a browser, Word, or a PDF library. `tests/test_tui_export.py` exercises
the picker, both formats, cancellation, errors, and unchanged JSON/PDF output
with headless Textual tests and blocked network access.
`tests/test_demos.py`, `tests/test_report_history.py`, and the TUI history tests
cover the ten-scan story, complete history, future-scan exclusion, output
collisions, demo/real isolation, and all three report formats.
`tests/test_domain_paths.py` and `tests/test_report_domain.py` cover per-domain
folders, legacy files, newest-first cards, deduplicated scans, safe scripts,
and graph links to exact history entries.
