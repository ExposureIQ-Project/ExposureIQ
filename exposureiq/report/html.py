"""Render a report model as one self-contained HTML document.

No web fonts, remote images, or requests: the interactive dashboard works offline.
A fixed embedded script handles scan selection, chart cursors and first-reveal
animations. All scan text is escaped and never inserted into JavaScript.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json

from exposureiq.report import branding, charts, interactive
from exposureiq.report.model import format_time


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _join(values, empty: str = "—") -> str:
    values = [value for value in (values or []) if value]
    return "<br>".join(_e(value) for value in values) if values else _e(empty)


def _severity_badge(name: str) -> str:
    key = name if name in branding.SEVERITY_COLORS else "low"
    label = branding.SEVERITY_LABELS.get(key, key.title())
    return f'<span class="badge badge-{key}">{_e(label)}</span>'


def _navigation(report: dict, *, prefix: str = "", home_prefix: str | None = None) -> str:
    links = "".join(
        f'<a href="#{prefix}{anchor}"'
        + (f' data-report-section="{anchor}"' if home_prefix else "")
        + f'>{label}</a>' for anchor, label in (
            ("overview", "Overview"), ("exposure", "Charts"), ("findings", "Findings"),
            ("changes", "Changes"), ("inventory", "Assets"), ("methodology", "Scope"),
        )
    )
    if home_prefix:
        links = ('<a href="#domain-home">Scans</a>'
                 '<a class="home-nav" href="#domain-scans">Choose scan</a>'
                 f'<a class="home-nav" href="#{home_prefix}exposure">Charts</a>'
                 f'<a class="home-nav" href="#{home_prefix}changes">Timeline</a>' + links)
    return f"""
<a class="skip-link" href="#report-main">Skip to report</a>
<header class="report-topbar">
  <div class="topbar-inner">
    <div class="topbar-logo">{branding.LOGO_SVG}</div>
    <div class="topbar-copy"><strong>ExposureIQ</strong>
      <span class="topbar-target">{_e(report['target'])}</span></div>
    <span class="offline-badge">Offline report</span>
    <nav class="report-nav" aria-label="Report sections">{links}</nav>
  </div>
</header>
"""


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


def _cover(report: dict, prefix: str = "") -> str:
    paragraphs = "".join(f"<p>{_e(text)}</p>" for text in report["executive_summary"])
    risk = report["risk"]
    return f"""
<section class="page cover" id="{prefix}overview" tabindex="-1" aria-label="Executive summary">
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


def _findings(report: dict, prefix: str = "") -> str:
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
            '<div class="table-scroll"><table class="findings"><thead><tr>'
            "<th>Severity</th><th>Asset</th><th>Finding and evidence</th>"
            "<th>Recommendation</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )
    return f"""
<section class="page" id="{prefix}findings" tabindex="-1" aria-label="Findings">
  <h2>Findings</h2>
  <p class="lede">Ordered by severity, then by asset. Each row names the evidence
  ExposureIQ collected and the recommended next step.</p>
  {body}
</section>
"""


def _scan_key(scan: dict) -> tuple[str, str]:
    return str(scan.get("scan_id") or ""), str(scan.get("started_at") or "")


def _scan_token(scan: dict) -> str:
    identity = json.dumps(_scan_key(scan), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()[:20]


def _history_id(scan: dict, prefix: str = "") -> str:
    return prefix + "history-" + _scan_token(scan)


def _baseline_step(scan: dict, prefix: str = "", *, disabled: bool = False) -> str:
    description = ("Comparison was disabled for this export." if disabled else
                   "First included snapshot. There is no earlier comparison in this timeline.")
    return f"""
  <article class="history-step" id="{_history_id(scan, prefix)}" tabindex="-1"
           data-history-scan="{_e(scan.get('scan_id'))}" data-history-time="{_e(scan.get('started_at'))}">
    <h4>{'Selected' if disabled else 'Baseline'} scan &middot; {_e(scan.get('scan_id'))}</h4>
    <p class="muted">{_e(format_time(scan.get('started_at')))}</p>
    <p>{description}</p>
  </article>"""


def _change_history(diff: dict, prefix: str = "") -> str:
    steps = []
    baseline = diff.get("old") or {}
    if baseline:
        steps.append(_baseline_step(baseline, prefix))
    for step in diff.get("history") or []:
        old, new = step.get("old") or {}, step.get("new") or {}
        summary = step.get("summary") or {}
        lines = "".join(f"<li>{_e(line)}</li>" for line in summary.get("lines") or [])
        notes = "".join(f"<li>{_e(note)}</li>" for note in step.get("notes") or [])
        steps.append(f"""
  <article class="history-step" id="{_history_id(new, prefix)}" tabindex="-1"
           data-history-scan="{_e(new.get('scan_id'))}" data-history-time="{_e(new.get('started_at'))}">
    <h4>{_e(old.get('scan_id'))} &rarr; {_e(new.get('scan_id'))}</h4>
    <p class="muted">{_e(old.get('started_at'))} &rarr; {_e(new.get('started_at'))}</p>
    <p><strong>{_e(summary.get('headline') or 'No changes')}</strong></p>
    {f'<ul class="changes">{lines}</ul>' if lines else ''}
    {f'<ul class="notes">{notes}</ul>' if notes else ''}
  </article>""")
    if not steps:
        return ""
    return ('<h3>Scan-by-scan history</h3><p class="muted">Overall counts above are net changes. '
            'These steps retain issues that appeared and were later fixed, through the selected scan only.</p>'
            + "".join(steps))


def _what_changed(report: dict, prefix: str = "") -> str:
    diff = report.get("diff")
    summary = report.get("diff_summary") or {}
    if not diff:
        disabled = not report.get("comparison_enabled", True)
        description = ("This export shows saved exposure without change comparisons. "
                       "Export again with comparisons enabled to see what changed." if disabled else
                       "This report describes the current exposure only. Run another scan of "
                       "the same target and generate the report again to see what changed.")
        body = (
            '<div class="empty"><strong>'
            + ("Comparison was disabled." if disabled else "No earlier saved scan was found.")
            + '</strong> ' + description + '</div>'
            + _baseline_step(report, prefix, disabled=disabled)
        )
    else:
        counts = summary.get("counts") or {}
        highlights = summary.get("highlights") or []
        lines = summary.get("lines") or []
        highlight_html = "".join(f"<li>{_e(item)}</li>" for item in highlights)
        line_html = "".join(f"<li>{_e(item)}</li>" for item in lines)
        note_html = "".join(f"<li>{_e(note)}</li>" for note in (diff.get("notes") or []))
        body = f"""
  <h3>Overall change since baseline</h3>
  <div class="diff-headline">{_e(summary.get('headline') or 'Saved scan changes compared')}</div>
  <div class="diff-counts">
    <div class="diff-count worse"><span>{counts.get('worse', 0)}</span>worse</div>
    <div class="diff-count better"><span>{counts.get('better', 0)}</span>better</div>
    <div class="diff-count neutral"><span>{counts.get('neutral', 0)}</span>neutral</div>
  </div>
  {f'<h3>Highlights</h3><ul class="highlights">{highlight_html}</ul>' if highlights else ''}
  {f'<h3>All changes</h3><ul class="changes">{line_html}</ul>' if lines else ''}
  {f'<ul class="notes">{note_html}</ul>' if note_html else ''}
  <p class="muted">Compared scan <strong>{_e((diff.get('old') or {}).get('scan_id'))}</strong>
     ({_e((diff.get('old') or {}).get('started_at'))}) with
     <strong>{_e((diff.get('new') or {}).get('scan_id'))}</strong>
      ({_e((diff.get('new') or {}).get('started_at'))}).</p>
  {_change_history(diff, prefix)}
"""
    return f"""
<section class="page" id="{prefix}changes" tabindex="-1" aria-label="What changed">
  <h2>What changed</h2>
  <p class="lede">Changes are security-relevant differences between saved scans.
  Removals are confirmed only when another included snapshot agrees, never using
  a snapshot after the selected scan.</p>
  {body}
</section>
"""


def _chart_anchors(report: dict, prefix: str, fallbacks: dict | None = None) -> dict:
    diff = report.get("diff") or {}
    included = [diff.get("old") or report]
    included.extend(step.get("new") or {} for step in diff.get("history") or [])
    ids = {_scan_key(item): _history_id(item, prefix) for item in included}
    return {_scan_key(point): ids.get(_scan_key(point))
            or (fallbacks or {}).get(_scan_key(point)) or prefix + "changes"
            for point in report.get("history") or []}


def _chart_shell(svg: str) -> str:
    return ('<div class="chart-shell">' + svg
            + '<div class="chart-tooltip" role="status" aria-live="polite" hidden>'
              '<strong class="tooltip-number"></strong><span class="tooltip-id"></span>'
              '<span class="tooltip-date"></span><span class="tooltip-counts"></span></div></div>')


def _charts(report: dict, prefix: str = "", fallbacks: dict | None = None) -> str:
    counts = report["severity"]
    anchors = _chart_anchors(report, prefix, fallbacks)
    legend = "".join(
        f'<li><span class="swatch" style="background:{row["color"]}"></span>'
        f'<span class="legend-label">{_e(row["label"])}</span>'
        f'<span class="legend-value">{_e(row["count_label"])} &middot; {row["percent"]}%</span></li>'
        for row in charts.severity_legend(counts)
    )
    return f"""
<section class="page" id="{prefix}exposure" tabindex="-1" aria-label="Exposure charts">
  <h2>Exposure at a glance</h2>
  <p class="lede">The severity mix shows where attention is needed. The trend shows
  how hosts and findings changed from the first saved scan through this scan.</p>
  <div class="charts">
    <div class="card">
      <h3>Findings by severity</h3>
      {charts.severity_donut(counts)}
      <ul class="legend">{legend}</ul>
    </div>
    <div class="card wide">
      <h3>Assets over time</h3>
      {_chart_shell(charts.assets_over_time(report.get("history") or [], anchors=anchors))}
      <p class="muted">{len(report.get('history') or [])} saved scan(s) for this target.</p>
    </div>
    <div class="card trend-wide">
      <h3>Findings over time</h3>
      {_chart_shell(charts.findings_over_time(report.get("history") or [], anchors=anchors))}
      <p class="muted"><span class="swatch" style="background:{branding.INDIGO}"></span> All findings
        &middot; <span class="swatch" style="background:{branding.HIGH}"></span> High severity (dashed line).</p>
    </div>
  </div>
  <p class="muted">Hover or focus a point to see its scan number and UTC date.
  Click a point to jump to that scan's history changes. Arrow keys move between points.</p>
</section>
"""


def _inventory(report: dict, prefix: str = "") -> str:
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
        '<div class="table-scroll"><table class="inventory"><thead><tr><th>Host</th><th>IP addresses</th>'
        "<th>Open ports</th><th>Technologies</th><th>Findings</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        if rows else '<div class="empty">No hosts were saved in this scan.</div>'
    )
    return f"""
<section class="page" id="{prefix}inventory" tabindex="-1" aria-label="Asset inventory">
  <h2>Asset inventory</h2>
  <p class="lede">What the scan found, including hosts with no recorded findings.</p>
  {body}
</section>
"""


def _methodology(report: dict, prefix: str = "") -> str:
    scope = ("DEMO: all hosts, ports, certificates and findings are simulated. No discovery, DNS, "
             "HTTP, TLS or port probes were sent. No exploitation was attempted."
             if report.get("demo") else
             "Active probes (HTTP, TLS, and ports) were sent only to hosts authorized in scope.txt. "
             "Other hosts were discovered passively and skipped. ExposureIQ does not exploit a service, "
             "brute force a login, or crawl beyond the front page. A finding is evidence, not proof of a vulnerability.")
    severity_rows = "".join(
        f'<li><span class="badge badge-{name}">{_e(branding.SEVERITY_LABELS[name])}</span> '
        f"{_e(text)}</li>"
        for name, text in report["severity_help"].items()
    )
    return f"""
<section class="page" id="{prefix}methodology" tabindex="-1" aria-label="Methodology and scope">
  <h2>Methodology and scope</h2>

  <h3>What ExposureIQ checked</h3>
  <ul class="plain">
    <li>Passive subdomain discovery and DNS resolution (A and AAAA records).</li>
    <li>Front-page HTTP response: security headers and technology hints.</li>
    <li>HTTPS certificate: expiry, hostname coverage, and trust chain.</li>
    <li>Top-100 TCP ports on authorized IPv4 addresses, then offline risky-service rules.</li>
  </ul>

  <h3>Scope and safety</h3>
  <p>{_e(scope)}</p>

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
.history-step {{ border-left: 3px solid var(--teal); padding: 8px 18px;
  margin: 16px 0; background: var(--surface); border-radius: 0 10px 10px 0;
  overflow-wrap: anywhere; }}
.history-step h4 {{ margin: 0 0 6px; color: var(--indigo); }}
.charts {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.35fr);
  gap: 20px; align-items: stretch; }}
.card {{ flex: 1; border: 1px solid var(--line); border-radius: 10px; padding: 18px;
  background: var(--surface); }}
.card.wide {{ flex: 1.35; }}
.card.trend-wide {{ grid-column: 1 / -1; }}
.trend-wide .chart {{ max-width: 900px; margin: 0 auto; }}
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
.report-topbar {{ position: sticky; top: 0; z-index: 10;
  background: {branding.css_rgba(branding.PANEL, .96)};
  border-bottom: 1px solid var(--line); backdrop-filter: blur(14px); }}
.topbar-inner {{ max-width: 1228px; margin: auto; padding: 12px 24px;
  display: flex; align-items: center; gap: 12px; }}
.topbar-logo, .topbar-logo svg {{ width: 32px; height: 32px; flex-shrink: 0; }}
.topbar-copy {{ min-width: 0; }}
.topbar-copy strong {{ color: var(--teal); font-size: 15px; }}
.topbar-target {{ display: block; max-width: 28ch; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; color: var(--muted); font-size: 11px; }}
.offline-badge {{ color: var(--indigo); border: 1px solid var(--line); border-radius: 6px;
  padding: 4px 8px; font-size: 10px; white-space: nowrap; }}
.report-nav {{ display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; margin-left: auto; }}
.report-nav a {{ color: var(--muted); text-decoration: none; padding: 7px 10px;
  border-radius: 7px; font-size: 12px; white-space: nowrap;
  transition: background .2s ease, color .2s ease; }}
.report-nav a:hover {{ background: var(--surface); color: var(--teal); }}
.report-nav a:focus-visible, .skip-link:focus-visible {{ outline: 2px solid var(--teal); outline-offset: 3px; }}
.skip-link {{ position: absolute; top: -80px; left: 16px; z-index: 20;
  background: var(--panel); color: var(--teal); padding: 10px 16px; border-radius: 8px; }}
.skip-link:focus {{ top: 12px; }}
@keyframes panel-enter {{ from {{ opacity: 0; transform: translateY(18px); }}
                         to {{ opacity: 1; transform: none; }} }}
@keyframes segment-enter {{ from {{ opacity: 0; stroke-width: 4; }} to {{ opacity: 1; }} }}
@keyframes trend-draw {{ from {{ stroke-dashoffset: 1; }} to {{ stroke-dashoffset: 0; }} }}
@keyframes chart-enter {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
@media screen {{
  html {{ scroll-behavior: smooth; scroll-padding-top: 100px; color-scheme: dark;
    scrollbar-width: thin; scrollbar-color: var(--line) var(--panel); }}
  .report-nav, .table-scroll {{ scrollbar-width: thin; scrollbar-color: var(--line) var(--surface); }}
  body {{ background: radial-gradient(ellipse at 90% 0%, {branding.css_rgba(branding.TEAL, .055)}, transparent 45%),
          var(--background); }}
  .page {{ width: calc(100% - 48px); max-width: 1180px; min-height: 0;
    margin: 24px auto; padding: 32px; border: 1px solid var(--line); border-radius: 16px;
    box-shadow: 0 12px 36px {branding.css_rgba(branding.GRADIENT_END, .28)};
    scroll-margin-top: 16px; animation: panel-enter .65s cubic-bezier(.2,.7,.2,1) both; }}
  .page:target {{ border-color: var(--teal); }}
  .cover {{ padding: 40px; }}
  .cover h1 {{ font-size: clamp(28px, 4vw, 52px); overflow-wrap: anywhere; }}
  .kicker {{ margin-top: 28px; }}
  .exec p {{ max-width: 900px; font-size: 14px; }}
  .confidential {{ position: relative; left: auto; right: auto; bottom: auto;
    margin: 28px 0 0; padding-top: 12px; }}
  .scorecards {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); }}
  .scorecard, .card {{ transition: transform .25s ease, border-color .25s ease, box-shadow .25s ease; }}
  .scorecard:hover, .card:hover {{ transform: translateY(-4px); border-color: var(--teal);
    box-shadow: 0 8px 22px {branding.css_rgba(branding.GRADIENT_END, .3)}; }}
  .scorecard .num {{ font-variant-numeric: tabular-nums; font-size: 36px; }}
  .charts {{ display: grid; grid-template-columns: minmax(240px, .8fr) minmax(0, 1.4fr); }}
  .card {{ min-width: 0; padding: 24px; }}
  .card h3 {{ color: var(--indigo); }}
  .chart-line {{ margin-top: 24px; }}
  .trend-line {{ stroke-dashoffset: 0; }}
  .table-scroll {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }}
  .findings {{ min-width: 700px; }}
  .inventory {{ min-width: 640px; }}
  td {{ overflow-wrap: anywhere; }}
  .findings tbody tr:hover td, .inventory tbody tr:hover td {{ background: {branding.HIGHLIGHT}; }}
  .findings td, .inventory td {{ transition: background .2s ease; }}
  .findings th:first-child {{ width: 12%; }}
  .findings th:nth-child(2) {{ width: 20%; }}
  .findings th:nth-child(3) {{ width: 40%; }}
  .findings th:nth-child(4) {{ width: 28%; }}
  @supports (animation-timeline: view()) {{
    .page:not(.cover) {{ animation: panel-enter linear both; animation-timeline: view();
      animation-range: entry 0% entry 20%; }}
  }}
}}
@media screen and (max-width: 760px) {{
  html {{ scroll-padding-top: 140px; }}
  .topbar-inner {{ flex-wrap: wrap; padding: 10px 16px; gap: 8px; }}
  .offline-badge {{ margin-left: auto; }}
  .report-nav {{ width: 100%; flex-wrap: nowrap; justify-content: flex-start;
    overflow-x: auto; margin-left: 0; }}
  .report-nav a {{ padding: 6px 9px; }}
  .page {{ width: calc(100% - 24px); margin: 12px auto; padding: 20px; border-radius: 12px; }}
  .cover {{ padding: 24px; }}
  .brandline {{ flex-wrap: wrap; gap: 4px 12px; }}
  .scorecards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
  .charts {{ grid-template-columns: minmax(0, 1fr); gap: 16px; }}
  .diff-counts {{ gap: 8px; }}
  .diff-count {{ min-width: 0; padding: 10px; }}
  .details th {{ width: 110px; }}
  .details td {{ overflow-wrap: anywhere; }}
  footer.report-footer {{ flex-direction: column; gap: 4px; }}
}}
@media (prefers-reduced-motion: reduce) {{
  html {{ scroll-behavior: auto !important; }}
  *, *::before, *::after {{ animation: none !important; transition: none !important; }}
}}
@page {{ size: A4; margin: 0; }}
@media print {{
  .report-topbar, .skip-link {{ display: none; }}
  *, *::before, *::after {{ animation: none !important; transition: none !important; }}
  .table-scroll {{ overflow: visible; }}
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


_PORTAL_CSS = """
.interactive-ready .domain-view:not(.is-active) { display: none; }
.showing-home [data-report-section], body:not(.showing-home) .home-nav { display: none; }
.scan-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
.scan-card { display: block; min-width: 0; padding: 20px; color: var(--text); text-decoration: none;
  border: 1px solid var(--line); border-radius: 12px; background: var(--surface);
  transition: transform .25s ease, border-color .25s ease, box-shadow .25s ease; }
.scan-card:hover { transform: translateY(-4px); border-color: var(--teal); box-shadow: 0 8px 24px #0004; }
.scan-card:focus-visible, .back-link:focus-visible { outline: 2px solid var(--teal); outline-offset: 3px; }
.scan-card strong { color: var(--teal); font-size: 18px; }
.scan-card time, .scan-card .scan-id, .scan-card .scan-totals { display: block; margin-top: 7px; }
.scan-card time { color: var(--text); font-size: 13px; }
.scan-id { font-family: Consolas, monospace; color: var(--muted); font-size: 10px; overflow-wrap: anywhere; }
.scan-totals { color: var(--muted); font-size: 12px; }
.scan-levels { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 14px; }
.scan-group { color: var(--indigo); font-size: 11px; }
.latest-tag { float: right; color: var(--indigo); border: 1px solid var(--line);
  border-radius: 5px; padding: 2px 7px; font-size: 10px; }
.portal-controls { max-width: 1180px; width: calc(100% - 48px); margin: 24px auto 0;
  display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
.back-link { color: var(--teal); text-decoration: none; border: 1px solid var(--line);
  border-radius: 8px; padding: 8px 12px; }
.history-step:target { border-left-color: var(--indigo); box-shadow: 0 0 0 1px var(--teal); }
.group-title { color: var(--indigo); margin-top: 0; }
@media screen and (max-width: 760px) {
  .scan-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
  .scan-card { padding: 16px; }
  .portal-controls { width: calc(100% - 24px); }
}
@media screen and (max-width: 520px) { .scan-grid { grid-template-columns: minmax(0, 1fr); } }
@media print { .scan-grid { display: block; } .scan-card { margin: 12px 0; page-break-inside: avoid; } }
"""


def _report_body(report: dict, prefix: str = "", fallbacks: dict | None = None) -> str:
    return (_cover(report, prefix) + _charts(report, prefix, fallbacks)
            + _findings(report, prefix) + _what_changed(report, prefix)
            + _inventory(report, prefix) + _methodology(report, prefix))


def _document(report: dict, body: str, navigation: str) -> str:
    digest = base64.b64encode(hashlib.sha256(interactive.SCRIPT.encode("utf-8")).digest()).decode("ascii")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="ExposureIQ">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>{_e(report.get('title') or 'Security Assessment Report')} — {_e(report.get('target'))}</title>
<style>{_CSS}{interactive.CSS}{_PORTAL_CSS}</style>
</head>
<body>
{navigation}
<main id="report-main" tabindex="-1">
{body}
</main>
<script id="exposureiq-interactions">{interactive.SCRIPT}</script>
</body>
</html>
"""


def render_html(report: dict) -> str:
    """Return a complete, interactive document for one report model."""
    if not isinstance(report, dict):
        raise ValueError("report must be a dictionary")
    return _document(report, _report_body(report), _navigation(report))


def render_domain_html(domain: dict) -> str:
    """One portable HTML home page and separately bounded saved-scan views."""
    if not isinstance(domain, dict) or not domain.get("reports") or not domain.get("groups"):
        raise ValueError("domain report must contain saved reports and history groups")
    reports = domain["reports"]
    latest = reports[-1]
    view_ids = {_scan_key(report): "scan-" + _scan_token(report) for report in reports}
    fallbacks = {_scan_key(report): _history_id(report, view_ids[_scan_key(report)] + "-")
                 for report in reports}
    cards = []
    for report in reversed(reports):
        number = (report.get("history") or [{}])[-1].get("number", 1)
        group = ("Demo story" if report["scan_id"].startswith("DEMO-HISTORY-") else
                 "One-off demo" if report.get("demo") else "Real scan")
        severity, counts = report["severity"], report["counts"]
        cards.append(f"""
    <a class="scan-card" href="#{view_ids[_scan_key(report)]}-overview"
       data-scan-card="{_e(report['scan_id'])}" data-scan-time="{_e(report['started_at'])}">
      {'<span class="latest-tag">Latest</span>' if report is latest else ''}
      <strong>Scan {number}</strong> <span class="scan-group">{group}</span>
      <time datetime="{_e(report['started_at'])}">{_e(report['started_label'])}</time>
      <span class="scan-id">{_e(report['scan_id'])}</span>
      <span class="scan-totals">{counts['assets']} hosts &middot; {counts['ports']} open ports</span>
      <span class="scan-levels"><span class="badge badge-high">{severity['high']} high</span>
        <span class="badge badge-medium">{severity['medium']} medium</span>
        <span class="badge badge-low">{severity['low']} low</span></span>
    </a>""")
    home = f"""
<article class="domain-view is-active" id="domain-home" tabindex="-1" aria-label="Domain scan home">
  <section class="page cover" id="domain-overview" tabindex="-1">
    <div class="cover-mark">{branding.LOGO_SVG}</div>
    <div class="brandline"><strong>Exposure<span>IQ</span></strong><span>Saved scan workspace</span></div>
    <p class="kicker">Domain dashboard &middot; offline</p>
    <h1>{_e(domain['target'])}</h1>
    <p class="meta">{len(reports)} saved scan(s) &middot; Latest scan {_e(latest['started_label'])}</p>
    <div class="exec"><p>Choose a scan below to inspect its findings, assets and changes.
      Newer scans appear first. Each detail view uses only the history available through that scan.</p>
      <p>Real scans and demo stories have separate trend lines. This page reads saved results only;
      it never scans or contacts a target.</p></div>
    <div class="scorecards">{_scorecards(latest)}</div>
    <p class="muted">Severity counts above belong to the latest saved scan.</p>
  </section>
  <section class="page" id="domain-scans" tabindex="-1" aria-label="Choose a saved scan">
    <h2>Choose a scan</h2><p class="lede">Newest first. Open a dated card to inspect that exact snapshot.</p>
    <div class="scan-grid">{''.join(cards)}</div>
  </section>"""
    for group in domain["groups"]:
        prefix = f"domain-{group['key']}-"
        home += (f'<section class="page"><h2 class="group-title">{_e(group["label"])}</h2>'
                 '<p class="muted">Full saved history for this group. The point you select links '
                 'to its exact history entry below.</p></section>'
                 + _charts(group["report"], prefix, fallbacks)
                 + _what_changed(group["report"], prefix))
    home += f'<footer class="portal-controls"><p class="muted">Confidential &middot; Generated {_e(domain["generated_label"])}</p></footer></article>'
    views = []
    for report in reports:
        view_id = view_ids[_scan_key(report)]
        views.append(
            f'<article class="scan-view domain-view" id="{view_id}" '
            f'data-scan-id="{_e(report["scan_id"])}" data-scan-time="{_e(report["started_at"])}">'
            '<div class="portal-controls"><a class="back-link" href="#domain-home">&larr; All scans</a>'
            f'<span class="muted">{_e(report["started_label"])}</span></div>'
            + _report_body(report, view_id + "-", fallbacks) + '</article>')
    first_group = "domain-" + domain["groups"][0]["key"] + "-"
    navigation = _navigation(latest, prefix=view_ids[_scan_key(latest)] + "-", home_prefix=first_group)
    return _document(latest, home + "".join(views), navigation)
