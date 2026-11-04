"""Small, dependency-free SVG charts used by the HTML report.

Each function returns one complete ``<svg>`` string. The PDF renderer draws the
same data with PDF operators, so the numbers and colours stay in sync.
"""

from __future__ import annotations

import html
import math

from exposureiq.report import branding


def _escape(value) -> str:
    return html.escape(str(value), quote=True)


def _nice_max(value: int) -> int:
    """Round a chart maximum up so the four grid lines land on whole numbers."""
    step = max(1, math.ceil(value / 4))
    return step * 4


def severity_donut(counts: dict, size: int = 220, thickness: int = 34) -> str:
    """A donut chart of findings by severity, with the total in the middle."""
    total = int(counts.get("total") or 0)
    centre = size / 2
    radius = (size - thickness) / 2 - 2
    circumference = 2 * math.pi * radius
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'class="chart chart-donut" role="img" aria-label="Findings by severity" '
        f'style="background:{branding.INNER_SURFACE}">',
        "<title>Findings by severity</title>",
        f'<circle cx="{centre}" cy="{centre}" r="{radius:.2f}" fill="none" '
        f'stroke="{branding.LINE}" stroke-width="{thickness}"/>',
    ]

    offset = 0.0
    for name in ("high", "medium", "low"):
        count = int(counts.get(name) or 0)
        if count <= 0 or total <= 0:
            continue
        length = circumference * count / total
        parts.append(
            f'<circle class="donut-segment" cx="{centre}" cy="{centre}" r="{radius:.2f}" fill="none" '
            f'stroke="{branding.SEVERITY_COLORS[name]}" stroke-width="{thickness}" '
            f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {centre} {centre})">'
            f'<title>{branding.SEVERITY_LABELS[name]}: {count} '
            f'{"finding" if count == 1 else "findings"}</title></circle>'
        )
        offset += length

    parts += [
        f'<text x="{centre}" y="{centre - 2}" text-anchor="middle" '
        f'class="donut-total" fill="{branding.TEXT_PRIMARY}">{total}</text>',
        f'<text x="{centre}" y="{centre + 18}" text-anchor="middle" '
        f'class="donut-label" fill="{branding.MUTED}">findings</text>',
        "</svg>",
    ]
    return "".join(parts)


def severity_legend(counts: dict) -> list[dict]:
    """Legend rows shared by the HTML template and the PDF renderer."""
    total = int(counts.get("total") or 0)
    rows = []
    for name in ("high", "medium", "low"):
        count = int(counts.get(name) or 0)
        rows.append({
            "key": name,
            "label": branding.SEVERITY_LABELS[name],
            "count": count,
            "percent": round(count * 100 / total) if total else 0,
            "count_label": f"{count} finding" if count == 1 else f"{count} findings",
            "color": branding.SEVERITY_COLORS[name],
        })
    return rows


def assets_over_time(points: list[dict], width: int = 640, height: int = 240, *,
                     anchors: dict | None = None) -> str:
    """A line chart of host count across the saved scans of one target."""
    return _trend_chart(points, width, height, metric="assets", title="Assets over time",
                        axis="Hosts", color=branding.TEAL, anchors=anchors)


def findings_over_time(points: list[dict], width: int = 640, height: int = 240, *,
                       anchors: dict | None = None) -> str:
    """Total and high-severity findings, so regressions and recovery stay visible."""
    return _trend_chart(points, width, height, metric="findings", title="Findings over time",
                        axis="Findings", color=branding.INDIGO, show_high=True, anchors=anchors)


def _trend_chart(points: list[dict], width: int, height: int, *, metric: str,
                  title: str, axis: str, color: str, show_high: bool = False,
                  anchors: dict | None = None) -> str:
    left, right, top, bottom = 48, 18, 22, 38
    plot_width = max(width - left - right, 1)
    plot_height = max(height - top - bottom, 1)
    points = [point for point in (points or []) if isinstance(point, dict)]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'class="chart chart-line" role="{"group" if anchors else "img"}" aria-label="{_escape(title)}" '
        f'style="background:{branding.INNER_SURFACE}">',
        f"<title>{_escape(title)}</title>",
    ]

    if not points:
        parts += [
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" '
            f'class="chart-empty" fill="{branding.MUTED}">No scan history yet</text>',
            "</svg>",
        ]
        return "".join(parts)

    values = [int(point.get(metric) or 0) for point in points]
    maximum = _nice_max(max(values) if values else 0)

    # Horizontal grid and value labels.
    for step in range(5):
        value = maximum * step / 4
        y = top + plot_height - plot_height * step / 4
        parts.append(
            f'<line x1="{left}" y1="{y:.2f}" x2="{left + plot_width}" y2="{y:.2f}" '
            f'stroke="{branding.LINE}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{left - 10}" y="{y + 3:.2f}" text-anchor="end" '
            f'class="axis-label" fill="{branding.MUTED}">{value:.0f}</text>'
        )

    count = len(points)
    if count == 1:
        xs = [left + plot_width / 2]
    else:
        xs = [left + plot_width * index / (count - 1) for index in range(count)]
    ys = [top + plot_height - plot_height * (value / maximum) for value in values]

    line = " ".join(f"{x:.2f},{y:.2f}" for x, y in zip(xs, ys))
    area = (f"{xs[0]:.2f},{top + plot_height:.2f} " + line +
            f" {xs[-1]:.2f},{top + plot_height:.2f}")
    parts.append(f'<g class="chart-series" style="transform-origin:{left}px {top + plot_height}px">')
    parts.append(
        f'<polygon class="chart-area" points="{area}" fill="{color}" opacity="0.10"/>'
    )
    parts.append(
        f'<polyline class="trend-line" pathLength="1" points="{line}" fill="none" stroke="{color}" '
        f'stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>'
    )

    if show_high:
        high_values = [int(point.get("high") or 0) for point in points]
        high_ys = [top + plot_height - plot_height * value / maximum for value in high_values]
        high_line = " ".join(f"{x:.2f},{y:.2f}" for x, y in zip(xs, high_ys))
        parts.append(f'<polyline class="high-trend" points="{high_line}" fill="none" '
                     f'stroke="{branding.HIGH}" stroke-width="2" stroke-dasharray="5 4" '
                     'stroke-linejoin="round"><title>High-severity findings</title></polyline>')

    for index, (x, y, point) in enumerate(zip(xs, ys, points)):
        key = (str(point.get("scan_id") or ""), str(point.get("started_at") or ""))
        anchor = (anchors or {}).get(key, "")
        number = point.get("number") or index + 1
        date = point.get("date") or point.get("started_at") or point.get("label") or "unknown date"
        tag = "a" if anchor else "g"
        parts.append(
            f'<{tag} class="chart-node" tabindex="0" '
            + (f'href="#{_escape(anchor)}" role="link" ' if anchor else 'role="img" ')
            + f'aria-label="Scan {_escape(number)}, {_escape(date)}" '
            f'data-x="{x:.2f}" data-y="{y:.2f}" data-anchor="{_escape(anchor)}" '
            f'data-scan-number="{_escape(number)}" data-scan-id="{_escape(point.get("scan_id") or "")}" '
            f'data-scan-time="{_escape(point.get("started_at") or "")}" '
            f'data-scan-date="{_escape(date)}" data-assets="{int(point.get("assets") or 0)}" '
            f'data-findings="{int(point.get("findings") or 0)}" data-high="{int(point.get("high") or 0)}">'
            f'<circle class="node-hit" cx="{x:.2f}" cy="{y:.2f}" r="12" fill="transparent" stroke="none"/>'
        )
        parts.append(
            f'<circle class="node-dot" cx="{x:.2f}" cy="{y:.2f}" r="4" fill="{branding.INNER_SURFACE}" '
            f'stroke="{color}" stroke-width="2"/>'
            f'<title>Scan {_escape(number)} · {_escape(date)}: '
            f'{int(point.get("assets") or 0)} assets, '
            f'{int(point.get("findings") or 0)} findings, '
            f'{int(point.get("high") or 0)} high severity</title></{tag}>'
        )
    parts.append("</g>")
    parts.append(f'<line class="chart-cursor is-hidden" x1="{left}" x2="{left}" '
                 f'y1="{top}" y2="{top + plot_height}" aria-hidden="true"/>')
    label_step = max(1, math.ceil(count / 8))
    for index, (x, point) in enumerate(zip(xs, points)):
        if index % label_step == 0 or index == count - 1:
            parts.append(
                f'<text x="{x:.2f}" y="{top + plot_height + 20}" '
                f'text-anchor="middle" class="axis-label" fill="{branding.MUTED}">'
                f'{_escape(point.get("label") or "?")}</text>'
            )

    parts.append(
        f'<text x="{left}" y="{height - 4}" class="axis-title" fill="{branding.MUTED}">Scan date</text>'
    )
    parts.append(
        f'<text x="{left}" y="{top - 8}" text-anchor="start" '
        f'class="axis-title" fill="{branding.MUTED}">{_escape(axis)}</text>'
    )
    parts.append("</svg>")
    return "".join(parts)
