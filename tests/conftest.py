"""Isolated user authorization and shared offline HTML inspection helpers."""

from html.parser import HTMLParser

import pytest


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
