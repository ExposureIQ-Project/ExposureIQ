"""The shared palette stays valid, readable, and present in offline reports."""

import re
import socket
import struct
import zlib
from pathlib import Path
from xml.etree import ElementTree

import pytest

from exposureiq import storage
from exposureiq.report import branding
from exposureiq.report.html import render_html
from exposureiq.report.model import build_report
from exposureiq.report.pdf import PAGE_HEIGHT, ReportPdf, render_pdf


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


def test_embedded_svg_matches_the_current_brand_asset():
    asset = Path(__file__).resolve().parents[1] / "assets" / "branding" / "icon.svg"
    source = ElementTree.fromstring(asset.read_text(encoding="utf-8"))
    embedded = ElementTree.fromstring(branding.LOGO_SVG)

    def shapes(root):
        return [(element.tag.rsplit("}", 1)[-1],
                 {name: re.sub(r"\s+", "", value).lower() for name, value in element.attrib.items()})
                for element in root.iter() if element is not root and not element.tag.endswith("title")]

    assert embedded.attrib["viewBox"] == source.attrib["viewBox"] == "0 0 107 107"
    assert shapes(embedded) == shapes(source)
    assert "scan aperture" in embedded.attrib["aria-label"]
    assert "M200 80" not in branding.LOGO_SVG and "polygon" not in branding.LOGO_SVG


def test_pdf_uses_current_aperture_geometry_as_vectors():
    writer = ReportPdf({})
    writer._logo(0, 0, branding.LOGO_SIZE)
    drawing = "\n".join(writer.content)
    assert writer.content[0] == "q" and writer.content[-1] == "Q"
    assert "2 J 0 j 5.00 w" in drawing and "3.00 w" in drawing
    for points in (*branding.LOGO_FRAMES, branding.LOGO_CROSSBAR):
        for index, (x, y) in enumerate(points):
            assert f"{x:.2f} {PAGE_HEIGHT - y:.2f} {'m' if index == 0 else 'l'}" in drawing
    teal = " ".join(f"{channel:.3f}" for channel in branding.hex_to_rgb(branding.TEAL))
    assert f"{teal} RG" in drawing and f"{teal} rg" in drawing
    assert "f*" not in drawing and "/Image" not in drawing


def test_generated_png_has_current_mark_colors_and_transparent_corners():
    image = branding.logo_png(107)
    assert image.startswith(b"\x89PNG\r\n\x1a\n")
    chunks, offset = {}, 8
    while offset < len(image):
        length = struct.unpack(">I", image[offset:offset + 4])[0]
        kind = image[offset + 4:offset + 8]
        content = image[offset + 8:offset + 8 + length]
        checksum = struct.unpack(">I", image[offset + 8 + length:offset + 12 + length])[0]
        assert checksum == zlib.crc32(kind + content)
        chunks[kind] = content
        offset += length + 12
    assert struct.unpack(">IIBBBBB", chunks[b"IHDR"]) == (107, 107, 8, 6, 0, 0, 0)
    pixels = zlib.decompress(chunks[b"IDAT"])
    stride = 1 + 107 * 4
    assert len(pixels) == 107 * stride
    assert all(pixels[row * stride] == 0 for row in range(107))

    def pixel(x, y):
        start = y * stride + 1 + x * 4
        return pixels[start:start + 4]

    teal = bytes(round(channel * 255) for channel in branding.hex_to_rgb(branding.TEAL)) + b"\xff"
    dark = bytes(round(channel * 255) for channel in branding.hex_to_rgb(branding.PAGE_BACKGROUND)) + b"\xff"
    assert pixel(0, 0) == pixel(106, 106) == b"\x00\x00\x00\x00"
    assert pixel(25, 25) == dark
    for point in ((10, 20), (85, 10), (97, 85), (20, 97), (35, 53), (53, 53)):
        assert pixel(*point) == teal
    assert image == branding.logo_png(107)


@pytest.mark.parametrize("size", [0, 15, 1025, True, "107", None])
def test_generated_logo_rejects_invalid_sizes(size):
    with pytest.raises(ValueError, match="16 to 1024"):
        branding.logo_png(size)
