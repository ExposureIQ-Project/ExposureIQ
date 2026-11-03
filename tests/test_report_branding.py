"""The shared palette stays valid, readable, and present in offline reports."""

import re
import socket
from pathlib import Path

import pytest

from exposureiq import storage
from exposureiq.report import branding
from exposureiq.report.html import render_html
from exposureiq.report.model import build_report
from exposureiq.report.pdf import render_pdf


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("branding tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def test_palette_is_hex_and_html_pdf_use_the_new_accent():
    colors = [value for name, value in vars(branding).items()
              if name.isupper() and isinstance(value, str)
              and name not in {"FONT_STACK", "MONO_STACK", "LOGO_SVG"}]
    assert colors and all(re.fullmatch(r"#[0-9a-fA-F]{6}", color) for color in colors)
    assert branding.hex_to_rgb(branding.TEAL) == (56 / 255, 225 / 255, 195 / 255)

    example = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
    report = build_report(storage.load_scan(str(example)), generated_at="2026-11-02T12:00:00Z")
    page, pdf = render_html(report), render_pdf(report)
    assert f"--teal: {branding.TEAL};" in page
    assert f'fill="{branding.TEAL}"' in page
    for color in (branding.TEAL, branding.HIGH, branding.AMBER, branding.LOW):
        assert color in page
        rgb = " ".join(f"{channel:.3f}" for channel in branding.hex_to_rgb(color))
        assert f"{rgb} rg".encode("ascii") in pdf


def test_text_and_badge_colors_have_readable_contrast():
    def luminance(color):
        channels = [channel / 12.92 if channel <= .04045
                    else ((channel + .055) / 1.055) ** 2.4
                    for channel in branding.hex_to_rgb(color)]
        return sum(channel * weight for channel, weight in zip(channels, (.2126, .7152, .0722)))

    def check(foreground, background):
        low, high = sorted((luminance(foreground), luminance(background)))
        assert (high + .05) / (low + .05) >= 4.5, (foreground, background)

    surfaces = (branding.PAGE_BACKGROUND, branding.PANEL, branding.INNER_SURFACE,
                branding.TABLE_HEADER, branding.HIGHLIGHT, branding.FOOTER)
    for text in (branding.TEXT_PRIMARY, branding.TEXT_SECONDARY, branding.TEXT_SUBTLE,
                 branding.MUTED, branding.TEAL, branding.INDIGO, branding.AMBER, branding.LOW):
        for surface in surfaces:
            check(text, surface)
    # HIGH labels retain an inner-surface backing even on selected TUI rows.
    for surface in surfaces:
        if surface != branding.HIGHLIGHT:
            check(branding.HIGH, surface)
    for fill in branding.SEVERITY_COLORS.values():
        check(branding.DARK, fill)
    check(branding.BUTTON_TEXT, branding.BUTTON_FILL)
    check(branding.BUTTON_TEXT, branding.TEAL)
    for text in (branding.DARK, branding.PRINT_SECONDARY, branding.PRINT_MUTED,
                 branding.PRINT_ACCENT_TEXT):
        for surface in (branding.PRINT_PAGE, branding.PRINT_SURFACE):
            check(text, surface)
