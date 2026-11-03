"""Tests for the pure SVG chart helpers."""

from exposureiq.report.charts import assets_over_time, severity_donut, severity_legend


def test_donut_contains_each_severity_and_the_total():
    svg = severity_donut({"high": 2, "medium": 1, "low": 0, "total": 3})

    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert ">3</text>" in svg
    assert "stroke-dasharray" in svg
    assert svg.count("<circle") == 3  # background + two non-zero segments


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
    assert "01 Oct" in svg
    assert "29 Oct" in svg
    assert svg.count("<g>") == 3


def test_line_chart_empty_state():
    svg = assets_over_time([])

    assert "No scan history yet" in svg
    assert "<polyline" not in svg
