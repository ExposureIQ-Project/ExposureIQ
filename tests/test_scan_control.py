"""Cancel fake stages and harmless local children; never run scan binaries."""

import asyncio
import socket
import subprocess
import sys
import pytest

from exposureiq import cli
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.control import ScanCancelled, ScanControl, cancellable_checks, observe_checks, tracked_processes
from exposureiq.tui.scan import ScanStages, run_scan


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("cancellation tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    yield
    assert attempts == []


def test_control_pause_and_missing_stage_adapter_cancel_cleanly():
    control = ScanControl()
    control.cancel()
    with pytest.raises(ScanCancelled):
        control.pause(10)
    with tracked_processes(lambda: None, ScanControl()):
        pass


def test_tracked_run_keeps_the_standard_subprocess_contract():
    namespace = {"subprocess": subprocess}
    exec("def stage(command, **kwargs):\n    return subprocess.run(command, **kwargs)", namespace)
    stage = namespace["stage"]
    with tracked_processes(stage, ScanControl()):
        result = stage([sys.executable, "-c", "print('sample')"], capture_output=True, text=True, check=True)
        assert result.stdout == "sample\n" and result.returncode == 0
        with pytest.raises(subprocess.CalledProcessError) as info:
            stage([sys.executable, "-c", "raise SystemExit(3)"], capture_output=True, check=True)
        assert info.value.returncode == 3
        with pytest.raises(subprocess.TimeoutExpired):
            stage([sys.executable, "-c", "import time; time.sleep(10)"], capture_output=True, timeout=0.05)
    assert namespace["subprocess"] is subprocess


@pytest.mark.parametrize("key", ["q", "ctrl+c"])
def test_tui_cancel_stops_discovery_child_and_restores_adapter(key):
    children = []

    class FakeSubprocess:
        """Use Python sleeping locally instead of Subfinder or Nmap."""

        def __getattr__(self, name):
            return getattr(subprocess, name)

        def Popen(self, *args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            children.append(process)
            return process

    original = FakeSubprocess()
    namespace = {"subprocess": original, "executable": sys.executable}
    exec("def find(domain, **kwargs):\n"
         "    subprocess.run([executable, '-c', 'import time; time.sleep(30)'], capture_output=True)\n"
         "    return {'subfinder': [], 'crtsh': []}", namespace)
    stages = ScanStages(namespace["find"], lambda hosts: [], None, None,
                        lambda: lambda target: True, lambda: lambda assets: assets,
                        lambda: (None, None), lambda: False, lambda target: False)
    args = cli.build_parser().parse_args(["scan", "example.com", "--no-save"])

    async def exercise():
        app = ExposureIQApp(args, stages=stages)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            assert children and children[0].poll() is None
            await pilot.press(key)
        assert app.return_value == 130 and app.control.cancelled.is_set()

    try:
        asyncio.run(exercise())
        assert children[0].wait(timeout=2) != 0
        assert namespace["subprocess"] is original
    finally:
        for process in children:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)


def test_cancel_between_hosts_sends_no_later_checks_or_ports():
    control, calls = ScanControl(), []

    def checks(assets):
        calls.append(assets[0]["host"])
        control.cancel()
        return assets

    def ports():
        raise AssertionError("ports must not start after cancellation")

    stages = ScanStages(lambda *a, **k: {"subfinder": ["api.example.com"], "crtsh": []},
                        lambda hosts: [{"host": host, "ips": ["192.0.2.10"]} for host in hosts],
                        None, None, lambda: lambda target: True, lambda: checks,
                        ports, lambda: False, lambda target: False)
    args = cli.build_parser().parse_args(["scan", "example.com", "--no-save"])
    with pytest.raises(ScanCancelled):
        run_scan(args, stages, lambda event: None, control)
    assert calls == ["example.com"]


def test_cancel_child_registration_race_kills_only_that_child():
    class Child:
        killed = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

    child, control = Child(), ScanControl()
    control.cancel()
    with pytest.raises(ScanCancelled):
        control.register(child, False)
    assert child.killed


def test_cancel_during_front_page_prevents_later_tls_and_restores_runner(monkeypatch):
    from exposureiq.fingerprint import runner

    control, calls = ScanControl(), []

    def fetch(host):
        calls.append("http")
        control.cancel()
        return None

    def tls(*args):
        calls.append("tls")
        return []

    monkeypatch.setattr(runner, "is_in_scope", lambda host: True)
    monkeypatch.setattr(runner, "fetch_front_page", fetch)
    monkeypatch.setattr(runner, "check_https", tls)
    previous_limit = runner.web.MAX_REDIRECTS
    with pytest.raises(ScanCancelled):
        with cancellable_checks(runner.run_checks, control):
            runner.run_checks([{"host": "example.com", "ips": []}])
    assert calls == ["http"]
    assert runner.fetch_front_page is fetch and runner.check_https is tls
    assert runner.web.MAX_REDIRECTS == previous_limit


def test_cancel_after_https_request_failure_prevents_http_fallback(monkeypatch):
    from requests.exceptions import ConnectionError
    from exposureiq.fingerprint import runner, web

    control, calls = ScanControl(), []

    def get_once(url, timeout):
        calls.append(url)
        control.cancel()
        raise ConnectionError("Fake failed HTTPS request")

    monkeypatch.setattr(runner, "is_in_scope", lambda host: True)
    monkeypatch.setattr(runner, "fetch_front_page", web.fetch_front_page)
    monkeypatch.setattr(web, "is_in_scope", lambda host: True)
    monkeypatch.setattr(web, "_get_once", get_once)
    original = runner.fetch_front_page
    with pytest.raises(ScanCancelled):
        with observe_checks(runner.run_checks), cancellable_checks(runner.run_checks, control):
            runner.run_checks([{"host": "example.com", "ips": []}])
    assert calls == ["https://example.com/"]
    assert runner.fetch_front_page is original and web._get_once is get_once


def test_cancel_after_strict_tls_failure_prevents_relaxed_handshake(monkeypatch):
    import ssl
    from exposureiq.fingerprint import https_checks, runner

    control, calls = ScanControl(), []

    def handshake(host, port, timeout, context):
        calls.append(host)
        control.cancel()
        raise ssl.SSLCertVerificationError("Fake unverified certificate")

    monkeypatch.setattr(runner, "is_in_scope", lambda host: True)
    monkeypatch.setattr(runner, "fetch_front_page", lambda host: None)
    monkeypatch.setattr(runner, "check_https", https_checks.check_https)
    monkeypatch.setattr(https_checks, "is_in_scope", lambda host: True)
    monkeypatch.setattr(https_checks, "_handshake", handshake)
    original = runner.check_https
    with pytest.raises(ScanCancelled):
        with cancellable_checks(runner.run_checks, control):
            runner.run_checks([{"host": "example.com", "ips": []}])
    assert calls == ["example.com"]
    assert runner.check_https is original and https_checks._handshake is handshake
