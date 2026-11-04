"""Tests for the pure SVG chart helpers."""

from xml.etree import ElementTree

from exposureiq.report import branding
from exposureiq.report.charts import assets_over_time, findings_over_time, severity_donut, severity_legend


def test_donut_contains_each_severity_and_the_total():
    svg = severity_donut({"high": 1, "medium": 1, "low": 1, "total": 3})

    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert ">3</text>" in svg
    assert "stroke-dasharray" in svg
    assert svg.count("<circle") == 4  # background + three non-zero segments
    colors = [branding.SEVERITY_COLORS[name] for name in ("high", "medium", "low")]
    assert len(set(colors)) == 3
    for color in colors:
        assert f'stroke="{color}"' in svg
    assert f'fill="{branding.TEXT_PRIMARY}"' in svg
    assert f'fill="{branding.MUTED}"' in svg


def test_donut_handles_zero_findings():
    svg = severity_donut({"high": 0, "medium": 0, "low": 0, "total": 0})

    assert ">0</text>" in svg
    assert "stroke-dasharray" not in svg


def test_legend_percentages_and_singular_label():
    rows = severity_legend({"high": 1, "medium": 2, "low": 0, "total": 3})

    assert [row["percent"] for row in rows] == [33, 67, 0]
    assert rows[0]["count_label"] == "1 finding"
    assert rows[1]["count_label"] == "2 findings"


def test_line_chart_draws_points_and_labels():
    svg = assets_over_time([
        {"label": "01 Oct", "assets": 1, "findings": 0},
        {"label": "15 Oct", "assets": 3, "findings": 2},
        {"label": "29 Oct", "assets": 2, "findings": 1},
    ])

    assert "<polyline" in svg
    assert f'stroke="{branding.TEAL}"' in svg
    assert f'fill="{branding.INNER_SURFACE}"' in svg
    assert "01 Oct" in svg
    assert "29 Oct" in svg
    assert svg.count('class="chart-node"') == 3


def test_line_chart_empty_state():
    svg = assets_over_time([])

    assert "No scan history yet" in svg
    assert "<polyline" not in svg


def test_findings_chart_shows_total_and_high_severity_not_host_counts():
    svg = findings_over_time([
        {"label": "01 Oct", "assets": 80, "findings": 2, "high": 0},
        {"label": "04 Oct", "assets": 90, "findings": 23, "high": 11},
        {"label": "10 Oct", "assets": 40, "findings": 1, "high": 0},
    ])
    assert 'aria-label="Findings over time"' in svg
    assert svg.count("<polyline") == 2
    assert f'stroke="{branding.INDIGO}"' in svg
    assert f'stroke="{branding.HIGH}"' in svg and 'stroke-dasharray="5 4"' in svg
    assert "23 findings, 11 high severity" in svg
    axis = [element.text for element in ElementTree.fromstring(svg).iter()
            if element.attrib.get("class") == "axis-label"
            and element.attrib.get("text-anchor") == "end"]
    assert "24" in axis and "92" not in axis


def test_findings_chart_empty_state_and_escaped_labels():
    assert "No scan history yet" in findings_over_time([])
    assert "<polyline" not in findings_over_time([])
    svg = findings_over_time([{"label": "<script>&", "findings": 1, "high": 0}])
    assert "<script>" not in svg and "&lt;script&gt;&amp;" in svg


def test_long_findings_axis_title_starts_inside_the_svg():
    svg = findings_over_time([{"label": "01 Oct", "findings": 1, "high": 0}])
    title = next(element for element in ElementTree.fromstring(svg).iter()
                 if element.text == "Findings" and element.attrib.get("class") == "axis-title")
    assert title.attrib["text-anchor"] == "start"
    assert float(title.attrib["x"]) > 0
