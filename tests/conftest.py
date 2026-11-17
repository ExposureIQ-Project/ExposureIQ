"""Isolated user authorization and shared offline HTML inspection helpers."""

from html.parser import HTMLParser
import ipaddress
import socket
import copy
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture(autouse=True)
def isolated_ai_and_offline_sockets(monkeypatch, tmp_path):
    """Never read a student's key/cache or reach the internet in any test.

    Loopback is permitted for fake provider and local-viewer HTTP tests.
    socketpair (used by asyncio/Textual) does not connect to a target.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "ai-config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "ai-cache"))
    monkeypatch.delenv("EXPOSUREIQ_AI_KEY", raising=False)
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_lookup = socket.getaddrinfo
    original_sendto = socket.socket.sendto
    original_by_name = socket.gethostbyname
    original_by_name_ex = socket.gethostbyname_ex

    def allowed(address):
        if not isinstance(address, tuple):
            return True  # Unix-domain sockets used by the event loop.
        name = str(address[0])
        try:
            return ipaddress.ip_address(name).is_loopback
        except ValueError:
            return name.lower() == "localhost"

    def connect(sock, address):
        if not allowed(address):
            raise AssertionError("Tests must not connect to the internet.")
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if not allowed(address):
            raise AssertionError("Tests must not connect to the internet.")
        return original_connect_ex(sock, address)

    def lookup(host, *args, **kwargs):
        if host is not None and not allowed((host, 0)):
            raise AssertionError("Tests must not perform external DNS lookups.")
        return original_lookup(host, *args, **kwargs)

    def sendto(sock, *args):
        if not allowed(args[-1]):
            raise AssertionError("Tests must not send external UDP traffic.")
        return original_sendto(sock, *args)

    def by_name(host):
        if not allowed((host, 0)):
            raise AssertionError("Tests must not perform external DNS lookups.")
        return original_by_name(host)

    def by_name_ex(host):
        if not allowed((host, 0)):
            raise AssertionError("Tests must not perform external DNS lookups.")
        return original_by_name_ex(host)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(socket.socket, "sendto", sendto)
    monkeypatch.setattr(socket, "gethostbyname", by_name)
    monkeypatch.setattr(socket, "gethostbyname_ex", by_name_ex)


@pytest.fixture
def ai_scan_factory():
    """Small schema-0.2 scans with known answers; no teammate/network fixtures."""
    def build(number=0, *, rules=None, host="db.example.com", passive=False):
        rules = rules if rules is not None else [("ports.database_exposed", "high"),
                                                 ("headers.missing_csp", "medium")]
        findings = [{"id": f"F-{i:04d}", "rule": rule,
                     "check": {"ports": "risky_services", "headers": "security_headers",
                               "https": "https", "tech": "technology"}[rule.split(".")[0]],
                     "severity": severity, "title": "Saved normalized title",
                     "detail": "Sample observation only.", "recommendation": "Apply a defensive fix."}
                    for i, (rule, severity) in enumerate(rules, 1)]
        asset = {"host": host, "ips": [{"ip": "192.0.2.10", "open_ports": [] if passive else
                  [{"port": 443, "protocol": "tcp", "service": "https"}]}]}
        if not passive:
            asset.update(findings=findings, technologies=[{"name": "nginx", "version": "1.24.0", "source": "Server header"}])
        date = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=number)
        return {"schema_version": "0.2", "scan_id": f"scan-{number:04d}", "target": "example.com",
                "started_at": date.isoformat().replace("+00:00", "Z"), "assets": [copy.deepcopy(asset)]}
    return build


@pytest.fixture(autouse=True)
def isolated_user_scope(monkeypatch, tmp_path):
    path = tmp_path / "user-config" / "scope.txt"
    monkeypatch.setenv("EXPOSUREIQUSERSCOPE", str(path))
    return path


@pytest.fixture
def portal_html():
    """Inspect generated HTML, including each separately bounded scan view."""
    class Portal(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids, self.links, self.cards, self.points, self.scripts = [], [], [], [], []
            self.views, self.history = {}, {}
            self._view, self._depth, self._script = None, 0, False

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            classes = attrs.get("class", "").split()
            if "id" in attrs:
                self.ids.append(attrs["id"])
            if tag == "a" and "href" in attrs:
                self.links.append(attrs["href"])
            if "scan-card" in classes:
                self.cards.append(attrs)
            if "chart-node" in classes:
                self.points.append(attrs)
            if "history-step" in classes:
                self.history[attrs["id"]] = attrs
            if "scan-view" in classes:
                self._view = (attrs["data-scan-id"], attrs["data-scan-time"])
                self.views[self._view] = ""
                self._depth = 0
            if self._view is not None:
                self.views[self._view] += self.get_starttag_text()
                if tag == "article":
                    self._depth += 1
            if tag == "script":
                self._script = True
                self.scripts.append("")

        def handle_endtag(self, tag):
            if self._view is not None:
                self.views[self._view] += f"</{tag}>"
                if tag == "article":
                    self._depth -= 1
                    if self._depth == 0:
                        self._view = None
            if tag == "script":
                self._script = False

        def handle_startendtag(self, tag, attrs):
            self.handle_starttag(tag, attrs)

        def handle_data(self, value):
            if self._view is not None:
                self.views[self._view] += value
            if self._script:
                self.scripts[-1] += value

    def inspect(page):
        parsed = Portal()
        parsed.feed(page)
        return parsed

    return inspect
