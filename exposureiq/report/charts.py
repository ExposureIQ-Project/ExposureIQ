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
        f'class="chart chart-donut" role="img" aria-label="Findings by severity">',
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
            f'<circle cx="{centre}" cy="{centre}" r="{radius:.2f}" fill="none" '
            f'stroke="{branding.SEVERITY_COLORS[name]}" stroke-width="{thickness}" '
            f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {centre} {centre})"/>'
        )
        offset += length

    parts += [
        f'<text x="{centre}" y="{centre - 2}" text-anchor="middle" '
        f'class="donut-total">{total}</text>',
        f'<text x="{centre}" y="{centre + 18}" text-anchor="middle" '
        f'class="donut-label">findings</text>',
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


def assets_over_time(points: list[dict], width: int = 640, height: int = 240) -> str:
    """A line chart of host count across the saved scans of one target."""
    left, right, top, bottom = 48, 18, 22, 38
    plot_width = max(width - left - right, 1)
    plot_height = max(height - top - bottom, 1)
    points = [point for point in (points or []) if isinstance(point, dict)]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'class="chart chart-line" role="img" aria-label="Assets over time">',
        "<title>Assets over time</title>",
    ]

    if not points:
        parts += [
            f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" '
            f'class="chart-empty">No scan history yet</text>',
            "</svg>",
        ]
        return "".join(parts)

    values = [int(point.get("assets") or 0) for point in points]
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
            f'class="axis-label">{value:.0f}</text>'
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
    parts.append(
        f'<polygon points="{area}" fill="{branding.TEAL}" opacity="0.10"/>'
    )
    parts.append(
        f'<polyline points="{line}" fill="none" stroke="{branding.TEAL}" '
        f'stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>'
    )

    label_step = max(1, math.ceil(count / 8))
    for index, (x, y, point) in enumerate(zip(xs, ys, points)):
        parts.append(
            f'<g><circle cx="{x:.2f}" cy="{y:.2f}" r="4" fill="{branding.WHITE}" '
            f'stroke="{branding.TEAL}" stroke-width="2"/>'
            f'<title>{_escape(point.get("label") or "?")}: '
            f'{int(point.get("assets") or 0)} assets, '
            f'{int(point.get("findings") or 0)} findings</title></g>'
        )
        if index % label_step == 0 or index == count - 1:
            parts.append(
                f'<text x="{x:.2f}" y="{top + plot_height + 20}" '
                f'text-anchor="middle" class="axis-label">'
                f'{_escape(point.get("label") or "?")}</text>'
            )

    parts.append(
        f'<text x="{left}" y="{height - 4}" class="axis-title">Scan date</text>'
    )
    parts.append(
        f'<text x="{left - 10}" y="{top - 8}" text-anchor="end" '
        f'class="axis-title">Hosts</text>'
    )
    parts.append("</svg>")
    return "".join(parts)
