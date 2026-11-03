"""Render a report model as one self-contained HTML document.

No web fonts, no JavaScript, no remote images: the file can be opened offline,
attached to an email, or printed to PDF from a browser. All scan text is escaped
before it reaches the template.
"""

from __future__ import annotations

import html

from exposureiq.report import branding, charts


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _join(values, empty: str = "—") -> str:
    values = [value for value in (values or []) if value]
    return "<br>".join(_e(value) for value in values) if values else _e(empty)


def _severity_badge(name: str) -> str:
    key = name if name in branding.SEVERITY_COLORS else "low"
    label = branding.SEVERITY_LABELS.get(key, key.title())
    return f'<span class="badge badge-{key}">{_e(label)}</span>'


def _scorecards(report: dict) -> str:
    counts = report["severity"]
    cards = []
    for name in ("high", "medium", "low"):
        cards.append(
            f'<div class="scorecard score-{name}">'
            f'<span class="num">{counts.get(name, 0)}</span>'
            f'<span class="caption">{_e(branding.SEVERITY_LABELS[name])}</span></div>'
        )
    cards.append(
        f'<div class="scorecard score-total">'
        f'<span class="num">{counts.get("total", 0)}</span>'
        f'<span class="caption">Total findings</span></div>'
    )
    return "".join(cards)


def _cover(report: dict) -> str:
    paragraphs = "".join(f"<p>{_e(text)}</p>" for text in report["executive_summary"])
    risk = report["risk"]
    return f"""
<section class="page cover">
  <div class="cover-mark">{branding.LOGO_SVG}</div>
  <div class="brandline"><strong>Exposure<span>IQ</span></strong>
    <span>Attack surface management</span></div>
  <p class="kicker">{_e(report['title'])}</p>
  <h1>{_e(report['target'])}</h1>
  <p class="meta">Scan <strong>{_e(report['scan_id'])}</strong> &middot;
     {_e(report['started_label'])}</p>
  <div class="risk" style="background:{risk['color']}">{_e(risk['label'])}</div>
  <div class="exec">
    <h2>Executive summary</h2>
    {paragraphs}
  </div>
  <div class="scorecards">{_scorecards(report)}</div>
  <p class="confidential">Confidential &middot; Prepared for the owner of {_e(report['target'])} &middot;
     Generated {_e(report['generated_label'])}</p>
</section>
"""


def _findings(report: dict) -> str:
    findings = report["findings"]
    if not findings:
        body = (
            '<div class="empty"><strong>No findings were recorded.</strong> '
            "The checks that ran did not see a problem; this is not proof that the "
            "target is secure.</div>"
        )
    else:
        rows = []
        for finding in findings:
            endpoint = ""
            if finding.get("ip"):
                endpoint = _e(finding["ip"])
                if finding.get("port"):
                    endpoint += _e(f":{finding['port']}")
            rows.append(
                f'<tr class="finding-{_e(finding["severity"])}">'
                f'<td>{_severity_badge(finding["severity"])}'
                f'<div class="fid">{_e(finding.get("id"))}</div></td>'
                f'<td><strong>{_e(finding.get("host"))}</strong>'
                + (f'<div class="muted">{endpoint}</div>' if endpoint else "")
                + f'</td>'
                f'<td><strong>{_e(finding.get("title"))}</strong>'
                f'<div class="detail">{_e(finding.get("detail"))}</div>'
                f'<div class="rule">{_e(finding.get("rule"))}</div></td>'
                f'<td>{_e(finding.get("recommendation"))}</td></tr>'
            )
        body = (
            '<table class="findings"><thead><tr>'
            "<th>Severity</th><th>Asset</th><th>Finding and evidence</th>"
            "<th>Recommendation</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    return f"""
<section class="page">
  <h2>Findings</h2>
  <p class="lede">Ordered by severity, then by asset. Each row names the evidence
  ExposureIQ collected and the recommended next step.</p>
  {body}
</section>
"""


def _what_changed(report: dict) -> str:
    diff = report.get("diff")
    summary = report.get("diff_summary") or {}
    if not diff:
        body = (
            '<div class="empty"><strong>No earlier saved scan was found.</strong> '
            "This report describes the current exposure only. Run another scan of "
            "the same target and generate the report again to see what changed.</div>"
        )
    else:
        counts = summary.get("counts") or {}
        highlights = summary.get("highlights") or []
        lines = summary.get("lines") or []
        shown = lines[:40]
        more = len(lines) - len(shown)
        highlight_html = "".join(f"<li>{_e(item)}</li>" for item in highlights)
        line_html = "".join(f"<li>{_e(item)}</li>" for item in shown)
        note_html = "".join(f"<li>{_e(note)}</li>" for note in (diff.get("notes") or []))
        body = f"""
  <div class="diff-headline">{_e(summary.get('headline') or 'Changes compared with the previous scan')}</div>
  <div class="diff-counts">
    <div class="diff-count worse"><span>{counts.get('worse', 0)}</span>worse</div>
    <div class="diff-count better"><span>{counts.get('better', 0)}</span>better</div>
    <div class="diff-count neutral"><span>{counts.get('neutral', 0)}</span>neutral</div>
  </div>
  {f'<h3>Highlights</h3><ul class="highlights">{highlight_html}</ul>' if highlights else ''}
  {f'<h3>All changes</h3><ul class="changes">{line_html}</ul>' if lines else ''}
  {f'<p class="muted">{more} more change(s) are in the JSON diff output.</p>' if more > 0 else ''}
  {f'<ul class="notes">{note_html}</ul>' if note_html else ''}
  <p class="muted">Compared scan <strong>{_e((diff.get('old') or {}).get('scan_id'))}</strong>
     ({_e((diff.get('old') or {}).get('started_at'))}) with
     <strong>{_e((diff.get('new') or {}).get('scan_id'))}</strong>
     ({_e((diff.get('new') or {}).get('started_at'))}).</p>
"""
    return f"""
<section class="page">
  <h2>What changed</h2>
  <p class="lede">Changes are security-relevant differences between saved scans.
  Removals are only called confirmed when a later scan agrees.</p>
  {body}
</section>
"""


def _charts(report: dict) -> str:
    counts = report["severity"]
    legend = "".join(
        f'<li><span class="swatch" style="background:{row["color"]}"></span>'
        f'<span class="legend-label">{_e(row["label"])}</span>'
        f'<span class="legend-value">{_e(row["count_label"])} &middot; {row["percent"]}%</span></li>'
        for row in charts.severity_legend(counts)
    )
    return f"""
<section class="page">
  <h2>Exposure at a glance</h2>
  <p class="lede">The severity mix shows where attention is needed. The trend shows
  how the number of discovered hosts has moved across saved scans.</p>
  <div class="charts">
    <div class="card">
      <h3>Findings by severity</h3>
      {charts.severity_donut(counts)}
      <ul class="legend">{legend}</ul>
    </div>
    <div class="card wide">
      <h3>Assets over time</h3>
      {charts.assets_over_time(report.get("history") or [])}
      <p class="muted">{len(report.get('history') or [])} saved scan(s) for this target.</p>
    </div>
  </div>
</section>
"""


def _inventory(report: dict) -> str:
    rows = []
    for asset in report["assets"]:
        rows.append(
            f"<tr><td><strong>{_e(asset['host'])}</strong></td>"
            f"<td>{_join(asset['ips'])}</td>"
            f"<td>{_join(asset['ports'], 'none recorded')}</td>"
            f"<td>{_join(asset['technologies'], 'none detected')}</td>"
            f"<td>{asset['findings']} "
            f"<span class=\"muted\">{_e(asset['highest_label'] if asset['findings'] else '')}</span></td></tr>"
        )
    body = (
        '<table class="inventory"><thead><tr><th>Host</th><th>IP addresses</th>'
        "<th>Open ports</th><th>Technologies</th><th>Findings</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows else '<div class="empty">No hosts were saved in this scan.</div>'
    )
    return f"""
<section class="page">
  <h2>Asset inventory</h2>
  <p class="lede">What the scan found, including hosts with no recorded findings.</p>
  {body}
</section>
"""


def _methodology(report: dict) -> str:
    severity_rows = "".join(
        f'<li><span class="badge badge-{name}">{_e(branding.SEVERITY_LABELS[name])}</span> '
        f"{_e(text)}</li>"
        for name, text in report["severity_help"].items()
    )
    return f"""
<section class="page">
  <h2>Methodology and scope</h2>

  <h3>What ExposureIQ checked</h3>
  <ul class="plain">
    <li>Passive subdomain discovery and DNS resolution (A and AAAA records).</li>
    <li>Front-page HTTP response: security headers and technology hints.</li>
    <li>HTTPS certificate: expiry, hostname coverage, and trust chain.</li>
    <li>Top-100 TCP ports on authorized IPv4 addresses, then offline risky-service rules.</li>
  </ul>

  <h3>Scope and safety</h3>
  <p>Active probes (HTTP, TLS, and ports) were sent only to hosts authorized in
  <code>scope.txt</code>. Other hosts were discovered passively and skipped. ExposureIQ
  does not exploit a service, brute force a login, or crawl beyond the front page.
  A finding is evidence, not proof of a vulnerability.</p>

  <h3>Severity levels</h3>
  <ul class="severity-help">{severity_rows}</ul>

  <h3>About this report</h3>
  <table class="details">
    <tr><th>Target</th><td>{_e(report['target'])}</td></tr>
    <tr><th>Scan ID</th><td>{_e(report['scan_id'])}</td></tr>
    <tr><th>Scan started</th><td>{_e(report['started_label'])}</td></tr>
    <tr><th>Report generated</th><td>{_e(report['generated_label'])}</td></tr>
    <tr><th>Schema version</th><td>{_e(report['schema_version'])}</td></tr>
    <tr><th>ExposureIQ version</th><td>{_e(report.get('tool_version') or '0.1.0')}</td></tr>
  </table>

  <div class="disclaimer">
    <strong>Point-in-time assessment.</strong> This report describes the state seen
    during one scan. A clean result is not proof that the target is secure, and a
    finding is not proof of exploitability. Re-scan regularly and review changes.
  </div>

  <footer class="report-footer">
    <span>ExposureIQ &middot; {_e(report.get('target'))} &middot; {_e(report.get('scan_id'))}</span>
    <span>Confidential &middot; {_e(report.get('generated_label'))}</span>
  </footer>
</section>
"""


_CSS = f"""
:root {{
  --background: {branding.PAGE_BACKGROUND};
  --panel: {branding.PANEL};
  --surface: {branding.INNER_SURFACE};
  --header: {branding.TABLE_HEADER};
  --text: {branding.TEXT_PRIMARY};
  --light-text: {branding.TEXT_PRIMARY};
  --subtle: {branding.TEXT_SUBTLE};
  --heading: {branding.TEAL};
  --teal: {branding.TEAL};
  --indigo: {branding.INDIGO};
  --amber: {branding.AMBER};
  --dark: {branding.DARK};
  --slate: {branding.SLATE};
  --muted: {branding.MUTED};
  --line: {branding.LINE};
  --paper: {branding.PAPER};
  --high: {branding.SEVERITY_COLORS['high']};
  --medium: {branding.SEVERITY_COLORS['medium']};
  --low: {branding.SEVERITY_COLORS['low']};
}}
* {{ box-sizing: border-box; }}
html {{ background: var(--background); }}
body {{
  margin: 0; color: var(--text); background: var(--background);
  font-family: {branding.FONT_STACK}; font-size: 14px; line-height: 1.55;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}}
.page {{
  width: 210mm; min-height: 297mm; margin: 24px auto; padding: 18mm 16mm;
  background: var(--panel); box-shadow: 0 10px 35px {branding.css_rgba(branding.GRADIENT_END, .16)};
  page-break-after: always; position: relative;
}}
.page:last-child {{ page-break-after: auto; }}
h1, h2, h3, p {{ margin-top: 0; }}
h1 {{ font-size: 40px; line-height: 1.1; letter-spacing: -.02em; margin-bottom: 12px; }}
h2 {{ font-size: 24px; letter-spacing: -.01em; margin: 0 0 8px; color: var(--heading); }}
h3 {{ font-size: 14px; text-transform: uppercase; letter-spacing: .08em;
      color: var(--heading); margin: 24px 0 8px; }}
.lede {{ color: var(--muted); margin-bottom: 22px; max-width: 640px; }}
.muted {{ color: var(--muted); font-size: 12px; }}
.cover {{
  --text: {branding.TEXT_PRIMARY}; --slate: {branding.TEXT_SECONDARY};
  --muted: {branding.MUTED}; --subtle: {branding.TEXT_SUBTLE};
  --heading: {branding.TEAL}; --surface: {branding.INNER_SURFACE};
  background: var(--background); color: var(--text); padding: 20mm 18mm;
  overflow: hidden;
}}
.cover::before {{
  content: ""; position: absolute; right: -120px; top: -130px; width: 420px;
  height: 420px; border-radius: 50%;
  background: radial-gradient(circle, {branding.css_rgba(branding.GLOW, .28)}, {branding.css_rgba(branding.PAGE_BACKGROUND, 0)} 68%);
}}
.cover::after {{
  content: ""; position: absolute; left: -140px; bottom: -170px; width: 420px;
  height: 420px; border-radius: 50%;
  background: radial-gradient(circle, {branding.css_rgba(branding.INDIGO, .22)}, {branding.css_rgba(branding.PAGE_BACKGROUND, 0)} 68%);
}}
.cover-mark {{ width: 54px; height: 54px; position: relative; z-index: 1; }}
.cover-mark svg {{ width: 54px; height: 54px; display: block; }}
.brandline {{ display: flex; align-items: baseline; gap: 12px; margin-top: 10px;
  position: relative; z-index: 1; }}
.brandline strong {{ font-size: 22px; letter-spacing: -.02em; }}
.brandline strong span {{ color: var(--teal); }}
.brandline > span {{ color: var(--subtle); font-size: 11px; text-transform: uppercase;
  letter-spacing: .14em; }}
.kicker {{ color: var(--teal); text-transform: uppercase; letter-spacing: .18em;
  font-size: 11px; font-weight: 700; margin: 54px 0 10px; position: relative; z-index: 1; }}
.cover h1 {{ font-size: 46px; position: relative; z-index: 1; }}
.cover .meta {{ color: var(--subtle); margin-bottom: 18px; position: relative; z-index: 1; }}
.risk {{ display: inline-block; padding: 6px 14px; border-radius: 999px;
  color: var(--dark); font-weight: 800; font-size: 12px; text-transform: uppercase;
  letter-spacing: .06em; position: relative; z-index: 1; }}
.exec {{ margin-top: 34px; position: relative; z-index: 1; }}
.exec h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .12em;
  color: var(--teal); }}
.exec p {{ color: var(--slate); font-size: 13px; max-width: 620px; margin-bottom: 10px; }}
.scorecards {{ display: flex; gap: 12px; margin-top: 30px; position: relative; z-index: 1; }}
.scorecard {{ flex: 1; border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; background: var(--surface); }}
.scorecard .num {{ display: block; font-size: 30px; font-weight: 800; line-height: 1; }}
.scorecard .caption {{ display: block; margin-top: 6px; color: var(--subtle); font-size: 11px;
  text-transform: uppercase; letter-spacing: .08em; }}
.score-high .num {{ color: var(--high); }}
.score-medium .num {{ color: var(--medium); }}
.score-low .num {{ color: var(--low); }}
.score-total .num {{ color: var(--teal); }}
.confidential {{ position: absolute; left: 18mm; right: 18mm; bottom: 12mm;
  color: var(--muted); font-size: 10px; border-top: 1px solid var(--line);
  padding-top: 8px; }}
.badge {{ display: inline-block; padding: 3px 9px; border-radius: 999px; color: var(--dark);
  font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; }}
.badge-high {{ background: var(--high); }}
.badge-medium {{ background: var(--medium); }}
.badge-low {{ background: var(--low); }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; }}
.findings, .inventory {{ background: var(--surface); }}
.findings thead th {{ background: var(--header); color: var(--light-text); padding: 10px 8px; }}
.findings td {{ padding: 11px 8px; border-bottom: 1px solid var(--line);
  vertical-align: top; }}
.findings tr {{ page-break-inside: avoid; }}
.findings tr:nth-child(even) td {{ background: var(--panel); }}
.fid {{ color: var(--muted); font-size: 10px; margin-top: 5px; font-family: {branding.MONO_STACK}; }}
.detail {{ color: var(--slate); margin-top: 4px; }}
.rule {{ color: var(--muted); font-size: 10px; margin-top: 5px; font-family: {branding.MONO_STACK}; }}
.inventory thead th {{ background: var(--header); color: var(--light-text); padding: 9px 8px;
  border-bottom: 2px solid var(--line); }}
.inventory td {{ padding: 9px 8px; border-bottom: 1px solid var(--line);
  vertical-align: top; }}
.empty {{ border: 1px solid var(--line); border-left: 4px solid var(--teal);
  background: var(--paper); padding: 16px 18px; border-radius: 6px; color: var(--slate); }}
.diff-headline {{ font-size: 22px; font-weight: 800; letter-spacing: -.01em; margin: 6px 0 18px; }}
.diff-counts {{ display: flex; gap: 12px; margin-bottom: 22px; }}
.diff-count {{ flex: 1; border: 1px solid var(--line); border-radius: 8px; padding: 12px;
  background: {branding.INNER_SURFACE}; color: {branding.MUTED}; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }}
.diff-count span {{ display: block; font-size: 26px; font-weight: 800; line-height: 1.1; }}
.diff-count.worse span {{ color: var(--high); }}
.diff-count.better span {{ color: {branding.GREEN}; }}
.diff-count.neutral span {{ color: {branding.TEXT_SECONDARY}; }}
.highlights, .changes, .notes, .plain, .severity-help {{ margin: 0 0 16px; padding-left: 20px; }}
.highlights li {{ margin-bottom: 7px; }}
.changes li {{ margin-bottom: 5px; color: var(--slate); font-size: 12px; }}
.notes li {{ color: var(--muted); font-size: 11px; }}
.charts {{ display: flex; gap: 20px; align-items: stretch; }}
.card {{ flex: 1; border: 1px solid var(--line); border-radius: 10px; padding: 18px;
  background: var(--surface); }}
.card.wide {{ flex: 1.35; }}
.card h3 {{ margin-top: 0; }}
.chart {{ width: 100%; height: auto; display: block; }}
.chart-donut {{ max-width: 220px; margin: 0 auto 10px; }}
.donut-total {{ font-size: 34px; font-weight: 800; fill: var(--text); }}
.chart-line circle {{ fill: var(--surface); }}
.donut-label {{ font-size: 10px; fill: var(--muted); text-transform: uppercase;
  letter-spacing: .08em; }}
.axis-label {{ font-size: 9px; fill: var(--muted); }}
.axis-title {{ font-size: 9px; fill: var(--muted); text-transform: uppercase;
  letter-spacing: .08em; }}
.chart-empty {{ font-size: 12px; fill: var(--muted); }}
.legend {{ list-style: none; margin: 8px 0 0; padding: 0; }}
.legend li {{ display: flex; align-items: center; gap: 8px; font-size: 12px;
  padding: 5px 0; border-bottom: 1px dashed var(--line); }}
.legend li:last-child {{ border-bottom: 0; }}
.swatch {{ width: 10px; height: 10px; border-radius: 3px; display: inline-block; }}
.legend-label {{ flex: 1; color: var(--slate); }}
.legend-value {{ color: var(--muted); font-variant-numeric: tabular-nums; }}
.details th {{ width: 150px; color: var(--slate); padding: 6px 0; }}
.details td {{ padding: 6px 0; }}
.disclaimer {{ margin-top: 26px; border: 1px solid var(--line); border-left: 4px solid var(--amber);
  background: var(--paper); padding: 14px 16px; border-radius: 6px; color: var(--slate);
  font-size: 12px; }}
.disclaimer strong {{ color: var(--amber); }}
code {{ font-family: {branding.MONO_STACK}; font-size: .92em; background: var(--paper);
  padding: 1px 4px; border-radius: 3px; }}
footer.report-footer {{ color: var(--muted); font-size: 10px; margin-top: 28px;
  border-top: 1px solid var(--line); padding-top: 8px; display: flex;
  justify-content: space-between; }}
@page {{ size: A4; margin: 0; }}
@media print {{
  :root {{
    --text: {branding.DARK}; --panel: {branding.PRINT_PAGE};
    --surface: {branding.PRINT_SURFACE}; --paper: {branding.PRINT_SURFACE};
    --slate: {branding.PRINT_SECONDARY}; --muted: {branding.PRINT_MUTED};
    --heading: {branding.PRINT_ACCENT_TEXT};
  }}
  html, body {{ background: {branding.PRINT_PAGE}; }}
  .chart {{ background: var(--surface) !important; }}
  .disclaimer strong {{ color: {branding.PRINT_ACCENT_TEXT}; }}
  .page {{ width: auto; min-height: 297mm; margin: 0; padding: 16mm;
    box-shadow: none; page-break-after: always; }}
  .page:last-child {{ page-break-after: auto; }}
  .cover {{ min-height: 297mm; padding: 20mm 18mm; }}
}}
"""


def render_html(report: dict) -> str:
    """Return a complete HTML document for one report model."""
    if not isinstance(report, dict):
        raise ValueError("report must be a dictionary")
    body = (
        _cover(report)
        + _findings(report)
        + _what_changed(report)
        + _charts(report)
        + _inventory(report)
        + _methodology(report)
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="ExposureIQ">
<title>{_e(report.get('title') or 'Security Assessment Report')} — {_e(report.get('target'))}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"""
