"""Loopback-only saved-scan viewer. No scanner, scope editor or acting API."""

from exposureiq.viewer.server import make_server

__all__ = ["make_server"]
