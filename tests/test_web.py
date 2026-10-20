"""Tests for fetch_front_page. A fake `requests` is used: no real internet."""

import pytest
import requests as real_requests

from exposureiq.fingerprint import web

IN_SCOPE = {"example.com", "www.example.com"}


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", chunk_size=10_000):
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self._chunk_size = chunk_size
        self.chunks_read = 0
        self.closed = False

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), self._chunk_size):
            self.chunks_read += 1
            yield self._body[i:i + self._chunk_size]

    def close(self):
        self.closed = True


class FakeRequests:
    """routes: url -> FakeResponse or an exception to raise. Others: no answer."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        route = self.routes.get(url)
        if route is None:
            raise real_requests.exceptions.ConnectionError("no answer")
        if isinstance(route, Exception):
            raise route
        return route


@pytest.fixture
def fake(monkeypatch):
    def install(routes=None, in_scope=lambda host: host in IN_SCOPE):
        fake_requests = FakeRequests(routes)
        monkeypatch.setattr(web, "requests", fake_requests)
        monkeypatch.setattr(web, "is_in_scope", in_scope)
        return fake_requests
    return install


def test_out_of_scope_host_makes_zero_requests(fake):
    fake_requests = fake({"https://other.com/": FakeResponse()})
    assert web.fetch_front_page("other.com") is None
    assert fake_requests.calls == []


def test_scope_check_raising_returns_none(fake):
    def broken(host):
        raise RuntimeError("scope file missing")
    fake_requests = fake({"https://example.com/": FakeResponse()}, in_scope=broken)
    assert web.fetch_front_page("example.com") is None
    assert fake_requests.calls == []


def test_https_ok_returns_contract_dict(fake):
    response = FakeResponse(200, {"Server": "nginx", "Content-Type": "text/html"}, b"<html>")
    fake_requests = fake({"https://example.com/": response})

    result = web.fetch_front_page("example.com")

    assert result == {
        "host": "example.com",
        "url": "https://example.com/",
        "scheme": "https",
        "status": 200,
        "headers": {"server": "nginx", "content-type": "text/html"},
        "body": "<html>",
    }
    url, kwargs = fake_requests.calls[0]
    assert kwargs["headers"]["User-Agent"].startswith("ExposureIQ/0.1")
    assert kwargs["verify"] is False
    assert kwargs["stream"] is True
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == 5.0
    assert response.closed


def test_https_fails_then_http_works(fake):
    fake_requests = fake({
        "https://example.com/": real_requests.exceptions.SSLError("bad tls"),
        "http://example.com/": FakeResponse(200, {"server": "apache"}, b"hi"),
    })
    result = web.fetch_front_page("example.com")
    assert result["scheme"] == "http"
    assert result["url"] == "http://example.com/"
    assert [c[0] for c in fake_requests.calls] == [
        "https://example.com/", "http://example.com/"]


def test_both_fail_returns_none(fake):
    fake_requests = fake({
        "https://example.com/": real_requests.exceptions.ConnectTimeout("slow"),
        "http://example.com/": real_requests.exceptions.ConnectionError("refused"),
    })
    assert web.fetch_front_page("example.com") is None
    assert len(fake_requests.calls) == 2


def test_error_status_is_still_an_answer(fake):
    fake_requests = fake({"https://example.com/": FakeResponse(403, {}, b"no")})
    result = web.fetch_front_page("example.com")
    assert result["status"] == 403
    assert len(fake_requests.calls) == 1  # no fallback to http


def test_body_is_capped_at_100_kb(fake):
    big = FakeResponse(200, {}, b"a" * (500 * 1024))
    fake({"https://example.com/": big})
    result = web.fetch_front_page("example.com")
    assert len(result["body"]) == 100 * 1024
    assert big.chunks_read < 50  # stopped reading early
    assert big.closed


def test_invalid_bytes_are_replaced_not_crashing(fake):
    fake({"https://example.com/": FakeResponse(200, {}, b"ok \xff\xfe end")})
    assert "ok" in web.fetch_front_page("example.com")["body"]


def test_in_scope_redirect_is_followed(fake):
    fake_requests = fake({
        "https://example.com/": FakeResponse(301, {"Location": "https://www.example.com/home"}),
        "https://www.example.com/home": FakeResponse(200, {}, b"final"),
    })
    result = web.fetch_front_page("example.com")
    assert result["url"] == "https://www.example.com/home"
    assert result["body"] == "final"
    assert len(fake_requests.calls) == 2


def test_redirect_to_out_of_scope_host_is_not_followed(fake):
    fake_requests = fake({
        "https://example.com/": FakeResponse(302, {"Location": "https://evil.com/"}),
        "https://evil.com/": FakeResponse(200, {}, b"should never be read"),
    })
    result = web.fetch_front_page("example.com")
    assert result["status"] == 302
    assert result["url"] == "https://example.com/"
    assert [c[0] for c in fake_requests.calls] == ["https://example.com/"]


def test_at_most_3_redirects_are_followed(fake):
    loop = {
        f"https://example.com/{i}": FakeResponse(302, {"Location": f"/{i + 1}"})
        for i in range(1, 10)
    }
    loop["https://example.com/"] = FakeResponse(302, {"Location": "/1"})
    fake_requests = fake(loop)
    result = web.fetch_front_page("example.com")
    assert result["status"] == 302
    assert len(fake_requests.calls) == 4  # first request + 3 redirects


def test_custom_ports_are_used(fake):
    fake_requests = fake({"https://example.com:8443/": FakeResponse(200)})
    result = web.fetch_front_page("example.com", https_port=8443)
    assert result["url"] == "https://example.com:8443/"
    assert fake_requests.calls[0][0] == "https://example.com:8443/"


def test_host_that_hides_another_host_makes_no_request(fake):
    fake_requests = fake({}, in_scope=lambda host: True)
    assert web.fetch_front_page("example.com@evil.com") is None
    assert fake_requests.calls == []


@pytest.mark.parametrize("bad", ["", "   ", None, 123])
def test_invalid_host_raises_value_error(fake, bad):
    fake_requests = fake()
    with pytest.raises(ValueError):
        web.fetch_front_page(bad)
    assert fake_requests.calls == []
