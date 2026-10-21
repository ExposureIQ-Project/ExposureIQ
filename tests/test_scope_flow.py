"""Explicit scope confirmation in Textual/plain mode; fake stages only."""

import asyncio
import copy
import ipaddress
import os
import socket
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Static

from exposureiq import cli, storage
from exposureiq.discovery import scope
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.confirm_scope import ScopeConfirmation
from exposureiq.tui.control import ScanControl
from exposureiq.tui.scan import PHASES, ScanStages
from exposureiq.tui.user_scope import remember_scan


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("scope-flow tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    assert attempts == []


def text(widget):
    rendered = widget.render()
    return rendered.plain if isinstance(rendered, Text) else str(rendered)


def fake_case(root: Path, count=3, stray=False, domain="example.com"):
    root.mkdir(parents=True, exist_ok=True)
    repo = root / "repo" / "scope.txt"
    repo.parent.mkdir(exist_ok=True)
    repo.write_text("# Fake repo scope (never written by the flow)\n", encoding="utf-8")
    hosts = [domain, f"api.{domain}", f"www.{domain}"] if count == 3 else [f"h{i:02}.{domain}" for i in range(count)]
    assets = [{"host": host, "ips": [{"ip": "192.0.2.10", "open_ports": []}],
               "technologies": [], "findings": []} for host in hosts]
    snapshot = storage.build_scan(domain, assets, started_at="2026-10-21T08:00:00Z")
    path = root / "results" / f"{domain}_sample.json"
    storage.save_scan(snapshot, str(path))
    result = {
        "target": domain, "demo": False, "started_at": snapshot["started_at"],
        "assets": assets, "names": [host for host in hosts if host != domain],
        "snapshot": snapshot, "saved_to": str(path), "elapsed": 1.0,
        "skipped_hosts": hosts + (["unrelated.example.net", "192.0.2.10", "example.com.evil.net"] if stray else []),
        "skipped_ips": ["192.0.2.10", "2001:db8::10"],
        "skipped_scope_ips": ["192.0.2.10"], "skipped_ipv6_ips": ["2001:db8::10"],
        "host_states": dict.fromkeys(hosts, "skipped: not in scope.txt"),
        "phase_counts": dict(zip(PHASES, (0, len(hosts) - 1, len(hosts), 0, 0, len(hosts)))),
        "phase_states": dict(zip(PHASES, ("done", "done", "done", "skipped", "skipped", "done"))),
        "phase_times": dict.fromkeys(PHASES, 0.1), "warnings": [], "port_rows": [], "return_code": 0,
        "mode": "passive", "mode_detail": "Passive only: the domain is not in scope.txt.",
    }
    calls = []

    def blocked(*args, **kwargs):
        raise AssertionError("re-run must not call DNS, discovery, or ports")

    def checks(entries):
        from exposureiq.fingerprint.severity import build_findings

        calls.extend(asset["host"] for asset in entries)
        for asset in entries:
            assert scope.is_in_scope(asset["host"]) is True
            asset["technologies"] = [{"name": "nginx", "version": "1.18.0", "source": "Saved fake Server header"}]
            asset["findings"] = build_findings([
                {"rule": "headers.missing_csp", "detail": "Fake saved front-page evidence."},
            ])
        return entries

    stages = ScanStages(blocked, blocked, storage.build_scan, storage.save_scan,
                        lambda: scope.is_in_scope, lambda: checks, blocked, blocked, lambda host: False)
    args = cli.build_parser().parse_args(["scan", domain, "--plain"])

    def job(*args):
        return copy.deepcopy(result)

    return SimpleNamespace(repo=repo, path=path, result=result, calls=calls, stages=stages, args=args, job=job)


@pytest.fixture
def case(monkeypatch, tmp_path):
    sample = fake_case(tmp_path)
    monkeypatch.setattr(scope, "SCOPE_FILE", sample.repo)
    return sample


async def ready(sample):
    app = ExposureIQApp(sample.args, stages=sample.stages, scan_job=sample.job)
    return app


def test_button_only_appears_with_scope_skipped_hosts(case):
    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.query_one("#add-scope", Button).display
            assert "3 hosts skipped: not in scope" in text(app.query_one("#scope-skipped-text", Static))
            assert "Passive only" in text(app.query_one("#summary-notes", Static))
            assert "Passive only" in text(app.query_one("#ports-skip-notes", Static))
            assert "Skipped: IPv6 ports not supported" in text(app.query_one("#ports-skip-notes", Static))
            await pilot.press("q")
        case.result["skipped_hosts"] = []
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert not app.query_one("#scope-skipped-panel").display
            await pilot.press("a")
            assert not isinstance(app.screen, ScopeConfirmation)
            await pilot.press("q")

    asyncio.run(exercise())


def test_exact_domain_controls_confirm_and_cancel_writes_nothing(case, isolated_user_scope):
    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assert isinstance(app.screen, ScopeConfirmation)
            assert app.focused.id == "scope-cancel"
            confirm = app.screen.query_one("#scope-confirm", Button)
            assert confirm.disabled
            field = app.screen.query_one("#scope-domain-input", Input)
            field.focus()
            for wrong in ("wrong.example.com", "EXAMPLE.COM", "example.com ", " example.com"):
                field.value = wrong
                await pilot.pause()
                assert confirm.disabled
            field.value = "example.com"
            await pilot.pause()
            assert not confirm.disabled
            await pilot.click("#scope-cancel")
            await pilot.pause()
            assert not isinstance(app.screen, ScopeConfirmation)
            assert not isolated_user_scope.exists() and case.calls == []
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.press("escape")
            assert not isolated_user_scope.exists() and case.calls == []
            await pilot.press("q")

    asyncio.run(exercise())


def test_confirm_safe_names_only_updates_tabs_same_json_and_never_ports(monkeypatch, tmp_path, isolated_user_scope):
    sample = fake_case(tmp_path, stray=True)
    monkeypatch.setattr(scope, "SCOPE_FILE", sample.repo)
    before = sample.repo.read_bytes()
    initial = storage.load_scan(str(sample.path))

    async def exercise():
        app = await ready(sample)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.click("#add-scope")
            await pilot.pause()
            assert app.screen.hosts == ["example.com", "api.example.com", "www.example.com"]
            field = app.screen.query_one("#scope-domain-input", Input)
            field.focus()
            await pilot.press(*list("example.com"))
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert sample.calls == ["example.com", "api.example.com", "www.example.com"]
            assert app.query_one("#technologies-table", DataTable).row_count == 3
            assert app.query_one("#findings-table", DataTable).row_count == 3
            assert set(app.rerun_states.values()) == {"done"}
            assert app.result["phase_counts"]["Scope"] == 3
            assert app.result["mode"] == "partial"
            assert "no port scans ran" in app.result["mode_detail"]
            assert str(isolated_user_scope) in text(app.query_one("#summary-notes", Static))
            assert str(isolated_user_scope) in text(app.query_one("#user-scope-saved", Static))
            assert not app.query_one("#add-scope", Button).display
            await pilot.press("q")

    asyncio.run(exercise())
    lines = isolated_user_scope.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("# added ") and "for example.com (confirmed by user)" in lines[0]
    assert lines[1:] == ["example.com", "api.example.com", "www.example.com"]
    for name in lines[1:]:
        with pytest.raises(ValueError):
            ipaddress.ip_address(name)
    saved = storage.load_scan(str(sample.path))
    assert saved["scan_id"] == initial["scan_id"] and saved["started_at"] == initial["started_at"]
    assert all(asset["findings"] and asset["technologies"] for asset in saved["assets"])
    assert [asset["ips"] for asset in saved["assets"]] == [asset["ips"] for asset in initial["assets"]]
    assert sample.repo.read_bytes() == before


def test_more_than_50_hosts_modal_names_cap_and_adds_only_50(monkeypatch, tmp_path, isolated_user_scope):
    sample = fake_case(tmp_path, count=60)
    monkeypatch.setattr(scope, "SCOPE_FILE", sample.repo)

    async def exercise():
        app = await ready(sample)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assert "only the first 50" in text(app.screen.query_one("#scope-cap", Static))
            assert len(app.screen.hosts) == 50
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert len(sample.calls) == 50
            assert len(app.result["skipped_hosts"]) == 10
            await pilot.press("q")

    asyncio.run(exercise())
    assert len(isolated_user_scope.read_text(encoding="utf-8").splitlines()[1:]) == 50


def test_plain_scope_add_updates_last_scan_only_after_exact_confirmation(monkeypatch, case, capsys, isolated_user_scope):
    remember_scan(case.result)
    monkeypatch.setattr(cli, "_stages", lambda: case.stages)
    monkeypatch.setattr("builtins.input", lambda prompt: "EXAMPLE.COM")
    assert cli.main(["scope", "add", "example.com"]) == 1
    assert not isolated_user_scope.exists() and case.calls == []
    monkeypatch.setattr("builtins.input", lambda prompt: "example.com")
    assert cli.main(["scope", "add", "example.com"]) == 0
    assert case.calls == ["example.com", "api.example.com", "www.example.com"]
    assert "accept responsibility" in capsys.readouterr().out
    assert cli.main(["scope", "list"]) == 0
    output = capsys.readouterr().out
    assert "Repository scope" in output and "User scope" in output
    assert "api.example.com" in output and "confirmed by user" in output
    saved = storage.load_scan(str(case.path))
    assert saved["scan_id"] == case.result["snapshot"]["scan_id"]
    assert saved["started_at"] == case.result["snapshot"]["started_at"]


def test_domain_containing_q_can_be_typed_without_quitting(monkeypatch, tmp_path):
    sample = fake_case(tmp_path, domain="iq.example.com")
    monkeypatch.setattr(scope, "SCOPE_FILE", sample.repo)

    async def exercise():
        app = await ready(sample)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).focus()
            await pilot.press(*list("iq.example.com"))
            assert app.screen.query_one("#scope-domain-input", Input).value == "iq.example.com"
            assert not app.screen.query_one("#scope-confirm", Button).disabled
            await pilot.press("escape", "q")

    asyncio.run(exercise())


def test_short_terminal_keeps_confirmation_controls_visible(case, isolated_user_scope):
    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(80, 24)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.query_one("#add-scope", Button).region.bottom <= 24
            await pilot.press("a")
            await pilot.pause()
            for selector in ("#scope-confirm", "#scope-cancel"):
                region = app.screen.query_one(selector, Button).region
                assert region.y >= 0 and region.bottom <= 24
            field = app.screen.query_one("#scope-domain-input", Input)
            field.focus()
            await pilot.pause()
            assert field.region.y >= 0 and field.region.bottom <= 24
            await pilot.press(*list("example.com"))
            assert not app.screen.query_one("#scope-confirm", Button).disabled
            await pilot.click("#scope-cancel")
            assert not isolated_user_scope.exists()
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("key", ["q", "ctrl+c"])
def test_cancel_rerun_stops_before_tls_and_next_host_and_keeps_saved_json(monkeypatch, case, isolated_user_scope, capsys, key):
    from exposureiq.fingerprint import runner

    started, ended = Event(), Event()
    control, calls = ScanControl(), []
    initial = case.path.read_bytes()
    previous_limit = runner.web.MAX_REDIRECTS

    def fetch(host):
        calls.append(("http", host))
        started.set()
        assert control.cancelled.wait(timeout=3)
        ended.set()
        return None

    def tls(host, response):
        calls.append(("tls", host))
        return []

    monkeypatch.setattr(runner, "is_in_scope", scope.is_in_scope)
    monkeypatch.setattr(runner, "fetch_front_page", fetch)
    monkeypatch.setattr(runner, "check_https", tls)
    case.stages.load_checks = lambda: runner.run_checks

    async def exercise():
        app = ExposureIQApp(case.args, stages=case.stages, scan_job=case.job, control=control)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            assert await asyncio.to_thread(started.wait, 2)
            await pilot.pause()
            assert app.rerun_states["example.com"] == "checking"
            assert app.rerun_states["api.example.com"] == "waiting"
            await pilot.press(key)
            assert await asyncio.to_thread(ended.wait, 2)
        assert app.return_value == 130 and control.cancelled.is_set()

    try:
        asyncio.run(exercise())
    finally:
        control.cancel()
    assert calls == [("http", "example.com")]
    assert case.path.read_bytes() == initial
    assert isolated_user_scope.read_text(encoding="utf-8").splitlines()[1:] == [
        "example.com", "api.example.com", "www.example.com",
    ]
    assert runner.fetch_front_page is fetch and runner.check_https is tls
    assert runner.web.MAX_REDIRECTS == previous_limit
    assert "Traceback" not in capsys.readouterr().err


def test_confirm_only_new_hosts_keeps_existing_findings_and_continues_ids(case, isolated_user_scope):
    from exposureiq.fingerprint.severity import build_findings

    existing = case.result["assets"][0]
    existing["technologies"] = [{"name": "nginx", "version": "", "source": "Existing fake header"}]
    existing["findings"] = build_findings([{"rule": "headers.missing_csp", "detail": "Existing fake evidence"}], start_id=7)
    case.result["skipped_hosts"] = ["api.example.com", "www.example.com"]
    before = copy.deepcopy(existing)

    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert app.result["assets"][0] == before
            assert case.calls == ["api.example.com", "www.example.com"]
            await pilot.press("q")

    asyncio.run(exercise())
    saved = storage.load_scan(str(case.path))
    assert [finding["id"] for asset in saved["assets"] for finding in asset["findings"]] == [
        "F-0007", "F-0008", "F-0009",
    ]
    assert isolated_user_scope.read_text(encoding="utf-8").splitlines()[1:] == ["api.example.com", "www.example.com"]


def test_failed_front_page_and_tls_are_human_and_failed_but_later_hosts_run(monkeypatch, case):
    from exposureiq.fingerprint import runner

    calls = []

    def fetch(host):
        calls.append(("http", host))
        if host == "example.com":
            runner.logger.warning("Request to https://%s/ failed: NewConnectionError([Errno 101] Network is unreachable)", host)
            return None
        return {"headers": {}, "body": "", "url": f"https://{host}/", "scheme": "https", "status_code": 200}

    def tls(host, response):
        calls.append(("tls", host))
        if host == "api.example.com":
            runner.logger.warning("Could not connect to %s:443 ([Errno 101] Network is unreachable).", host)
        return []

    monkeypatch.setattr(runner, "is_in_scope", scope.is_in_scope)
    monkeypatch.setattr(runner, "fetch_front_page", fetch)
    monkeypatch.setattr(runner, "check_https", tls)
    case.stages.load_checks = lambda: runner.run_checks

    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert app.rerun_states == {"example.com": "failed", "api.example.com": "failed", "www.example.com": "done"}
            warnings = text(app.query_one("#summary-notes", Static))
            assert "example.com: no web server answered on ports 80 and 443 (network unreachable)" in warnings
            assert "api.example.com: certificate check failed (network unreachable)" in warnings
            assert "NewConnectionError" not in warnings and "Errno" not in warnings
            assert app.result["skipped_hosts"] == []
            assert app.query_one("#findings-table", DataTable).row_count > 0
            await pilot.press("q")

    asyncio.run(exercise())
    assert calls == [(kind, host) for host in ("example.com", "api.example.com", "www.example.com") for kind in ("http", "tls")]
    assert storage.load_scan(str(case.path))["assets"][1]["findings"]


@pytest.mark.parametrize("gate", [False, "broken"])
def test_confirm_cannot_bypass_changed_or_broken_scope(case, gate):
    def checker(host):
        if gate == "broken":
            raise PermissionError("Fake broken scope reader")
        return False

    case.stages.load_scope = lambda: checker

    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert case.calls == []
            assert set(app.rerun_states.values()) == {"failed"}
            assert "scope could not be verified; no requests sent" in text(app.query_one("#summary-notes", Static))
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("typed", ["wrong.example.com", "EXAMPLE.COM", "example.com ", " example.com", ""])
def test_plain_wrong_confirmation_adds_nothing(monkeypatch, case, isolated_user_scope, typed):
    remember_scan(case.result)
    monkeypatch.setattr("builtins.input", lambda prompt: typed)
    assert cli.main(["scope", "add", "example.com"]) == 1
    assert not isolated_user_scope.exists() and case.calls == []


def test_plain_scan_ends_with_hint_and_records_actual_skipped_hosts(monkeypatch, case, capsys):
    from exposureiq.tui.user_scope import last_scan

    case.stages.find_subdomains = lambda domain, **kwargs: {"fake": ["api.example.com", "www.example.com"]}
    case.stages.resolve_hosts = lambda hosts: [{"host": host, "ips": ["192.0.2.10"]} for host in hosts]
    case.stages.load_ports = lambda: (None, None)
    case.args.output = str(case.path)
    monkeypatch.setattr(cli, "_stages", lambda: case.stages)
    assert cli.main(["scan", "example.com", "--plain", "-o", str(case.path)]) == 0
    assert capsys.readouterr().out.rstrip().endswith("exposureiq scope add example.com")
    assert last_scan("example.com")["skipped_hosts"] == ["example.com", "api.example.com", "www.example.com"]


def test_plain_scope_has_no_confirmation_bypass_and_missing_scan_is_clean(case, capsys):
    assert cli.main(["scope", "add", "example.com"]) == 1
    assert "First run exposureiq scan" in capsys.readouterr().out
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args(["scope", "add", "example.com", "--yes"])
    assert error.value.code == 2


def test_scope_file_write_failure_starts_no_checks(monkeypatch, case, isolated_user_scope):
    def refused(*args):
        raise PermissionError("Fake user scope write denied")

    monkeypatch.setattr("exposureiq.tui.app.append_hosts", refused)
    initial = case.path.read_bytes()

    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert "Scope/web update failed" in text(app.query_one("#scan-status", Static))
            assert case.calls == [] and not app._rerunning
            await pilot.press("q")

    asyncio.run(exercise())
    assert case.path.read_bytes() == initial and not isolated_user_scope.exists()


def test_missing_runner_is_failed_not_out_of_scope(case):
    case.stages.load_checks = lambda: None

    async def exercise():
        app = await ready(case)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            assert app.result["skipped_hosts"] == []
            assert set(app.rerun_states.values()) == {"failed"} and case.calls == []
            assert "web checks are unavailable; no requests sent" in text(app.query_one("#summary-notes", Static))
            await pilot.press("q")

    asyncio.run(exercise())


def test_bad_runner_preserves_existing_names_ips_and_findings(case):
    from exposureiq.tui.rerun import rerun_hosts
    from exposureiq.tui.user_scope import append_hosts

    _, names = append_hosts("example.com", ["example.com"], "example.com")
    before = copy.deepcopy(case.result["assets"])
    case.stages.load_checks = lambda: lambda assets: [{"host": "outside.example.net", "ips": []}]
    events = []
    updated = rerun_hosts(case.result, names, case.stages, events.append, ScanControl())
    assert updated["assets"] == before
    assert updated["host_states"]["example.com"] == "failed: see warning"
    assert any(event.get("state") == "failed" for event in events)
    assert storage.load_scan(str(case.path))["assets"] == before


def test_plain_scope_list_missing_user_file_never_creates_it(case, isolated_user_scope, capsys):
    assert cli.main(["scope", "list"]) == 0
    printed = capsys.readouterr().out
    assert "Repository scope" in printed and "User scope" in printed and "missing; no entries" in printed
    assert not isolated_user_scope.exists() and case.calls == []


def test_last_scan_pointer_never_follows_a_predictable_temp_link(case, isolated_user_scope):
    before = case.repo.read_bytes()
    directory = isolated_user_scope.parent / "last-scans"
    directory.mkdir(parents=True)
    linked = directory / "example.com.tmp"
    linked.symlink_to(case.repo)
    remember_scan(case.result)
    assert case.repo.read_bytes() == before and linked.is_symlink()
    assert (directory / "example.com.json").exists()


@pytest.mark.parametrize("redirect", [False, True])
def test_existing_web_runner_uses_only_front_page_gets_and_unchanged_limits(monkeypatch, case, redirect):
    from exposureiq.fingerprint import runner, web
    from exposureiq.tui.rerun import rerun_hosts
    from exposureiq.tui.user_scope import append_hosts

    class Response:
        status_code = 301 if redirect else 200
        headers = {"server": "nginx/1.18.0", **({"location": "/must-not-be-fetched"} if redirect else {})}

        def iter_content(self, chunk_size):
            yield b"<html><title>Saved fake front page</title></html>"

        def close(self):
            transport.active -= 1

    class Transport:
        active = peak = 0

        def __init__(self):
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            self.active += 1
            self.peak = max(self.peak, self.active)
            assert scope.is_in_scope(urlparse(url).hostname)
            return Response()

    transport, tls_calls = Transport(), []
    monkeypatch.setattr(web, "requests", transport)
    monkeypatch.setattr(runner, "fetch_front_page", web.fetch_front_page)
    monkeypatch.setattr(runner, "check_https", lambda host, response: tls_calls.append(host) or [])
    case.stages.load_checks = lambda: runner.run_checks
    _, names = append_hosts("example.com", case.result["skipped_hosts"], "example.com")
    rerun_hosts(case.result, names, case.stages, lambda event: None, ScanControl())
    assert [url for url, _ in transport.calls] == [f"https://{host}/" for host in names]
    assert tls_calls == names and transport.peak == 1 and transport.active == 0
    for url, kwargs in transport.calls:
        assert urlparse(url).path == "/" and kwargs["allow_redirects"] is False
        assert kwargs["headers"]["User-Agent"] == web.USER_AGENT
        assert kwargs["timeout"] == 5.0 and kwargs["stream"] is True
    saved = storage.load_scan(str(case.path))
    assert all(asset["technologies"] and asset["findings"] for asset in saved["assets"])


async def export_scope_screens(directory: Path) -> list:
    sample = fake_case(directory / "fake")
    user_path = directory / "user-config" / "scope.txt"
    if user_path.exists():
        # This export's previous fake file only, never a real user scope.
        user_path.unlink()
    paths = []
    with patch.dict(os.environ, {"EXPOSUREIQUSERSCOPE": str(user_path)}), patch.object(scope, "SCOPE_FILE", sample.repo):
        app = await ready(sample)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            for filename, title in (("summary-with-button.svg", "ExposureIQ — skipped host names"),):
                path = directory / filename
                path.write_text(app.export_screenshot(title=title), encoding="utf-8")
                paths.append(path)
            await pilot.press("a")
            await pilot.pause()
            path = directory / "confirmation-disabled.svg"
            assert app.screen.query_one("#scope-confirm", Button).disabled
            path.write_text(app.export_screenshot(title="ExposureIQ — responsibility confirmation"), encoding="utf-8")
            paths.append(path)
            app.screen.query_one("#scope-domain-input", Input).value = "example.com"
            await pilot.pause()
            await pilot.click("#scope-confirm")
            await pilot.pause()
            await app.worker.wait()
            await pilot.pause()
            path = directory / "results-after-rerun.svg"
            path.write_text(app.export_screenshot(title="ExposureIQ — confirmed web checks complete"), encoding="utf-8")
            paths.append(path)
            await pilot.press("q")
    paths.append(user_path)
    return paths


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--export-screens"]:
        raise SystemExit("Use python tests/test_scope_flow.py --export-screens")
    for path in asyncio.run(export_scope_screens(Path("/tmp/opencode/exposureiq-s2-scope-screens"))):
        print(path)
