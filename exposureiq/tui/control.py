"""Cooperative cancellation and child-process cleanup for one scan.

The discovery/port modules are unchanged. A small subprocess adapter tracks
only processes they launch during this job, not unrelated system processes.
"""

import os
import logging
import signal
import subprocess
from contextlib import contextmanager
from functools import wraps
from inspect import unwrap
from threading import Event, Lock, get_ident


class ScanCancelled(BaseException):
    """Not a network error: do not let a stage swallow cancellation and retry."""


class ScanControl:
    def __init__(self):
        self.cancelled = Event()
        self._lock = Lock()
        self._processes = {}

    def check(self) -> None:
        if self.cancelled.is_set():
            raise ScanCancelled()

    def pause(self, seconds: float) -> None:
        """A short DEMO pause that wakes immediately on cancellation."""
        self.cancelled.wait(seconds)
        self.check()

    def register(self, process, own_group: bool) -> None:
        with self._lock:
            self._processes[process] = own_group
        if self.cancelled.is_set():
            self.stop(process, own_group)
            try:
                process.wait(timeout=1)
            except (AttributeError, subprocess.TimeoutExpired):
                pass
            self.forget(process)
            self.check()

    def forget(self, process) -> None:
        with self._lock:
            self._processes.pop(process, None)

    def stop_child(self, process) -> None:
        with self._lock:
            own_group = self._processes.get(process, False)
        self.stop(process, own_group)

    @staticmethod
    def stop(process, own_group: bool = False) -> None:
        if process.poll() is not None:
            return
        try:
            if own_group and os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, OSError):
            # The child may have exited between poll() and the signal.
            pass

    def cancel(self) -> None:
        self.cancelled.set()
        with self._lock:
            children = list(self._processes.items())
        for process, own_group in children:
            self.stop(process, own_group)


class _TrackedSubprocess:
    def __init__(self, original, control: ScanControl):
        self.original, self.control = original, control

    def __getattr__(self, name):
        return getattr(self.original, name)

    def Popen(self, *args, **kwargs):
        self.control.check()
        own_group = os.name == "posix" and kwargs.get("process_group") in (None, -1)
        if own_group:
            kwargs["start_new_session"] = True
        process = self.original.Popen(*args, **kwargs)
        self.control.register(process, own_group)
        return process

    def run(self, *args, input=None, capture_output=False, timeout=None, check=False, **kwargs):
        """The standard run() contract, using our tracked Popen()."""
        if input is not None:
            if "stdin" in kwargs:
                raise ValueError("stdin and input cannot be used together")
            kwargs["stdin"] = subprocess.PIPE
        if capture_output:
            if "stdout" in kwargs or "stderr" in kwargs:
                raise ValueError("stdout/stderr and capture_output cannot be used together")
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process = self.Popen(*args, **kwargs)
        try:
            with process:
                try:
                    stdout, stderr = process.communicate(input, timeout=timeout)
                except subprocess.TimeoutExpired:
                    self.control.stop_child(process)
                    stdout, stderr = process.communicate()
                    self.control.check()
                    raise subprocess.TimeoutExpired(process.args, timeout, output=stdout, stderr=stderr)
                except BaseException:
                    self.control.stop_child(process)
                    raise
                self.control.check()
                if check and process.returncode:
                    raise subprocess.CalledProcessError(process.returncode, process.args,
                                                        output=stdout, stderr=stderr)
                return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        finally:
            self.control.forget(process)


@contextmanager
def tracked_processes(stage, control: ScanControl):
    """Replace only this stage's subprocess reference and restore it afterward."""
    namespace = getattr(stage, "__globals__", {})
    original = namespace.get("subprocess")
    if original is None:
        yield
        return
    adapter = _TrackedSubprocess(original, control)
    namespace["subprocess"] = adapter
    try:
        yield
    finally:
        if namespace.get("subprocess") is adapter:
            namespace["subprocess"] = original


@contextmanager
def cancellable_checks(stage, control: ScanControl):
    """Check cancellation between the runner's existing HTTP and TLS calls.

    The fetcher and runner files stay unchanged. Raising ScanCancelled after an
    in-flight front-page fetch prevents the runner from then starting TLS.
    """
    namespace = getattr(stage, "__globals__", {})
    replacements = []

    def guard(function):
        @wraps(function)
        def checked(*args, **kwargs):
            control.check()
            result = function(*args, **kwargs)
            control.check()
            return result
        return checked

    def replace(owner, name):
        original = owner.get(name)
        if callable(original):
            wrapped = guard(original)
            owner[name] = wrapped
            replacements.append((owner, name, original, wrapped))

    for name, inner_name in (("fetch_front_page", "_get_once"), ("check_https", "_handshake")):
        original = namespace.get(name)
        if callable(original):
            # Check between the existing HTTPS/HTTP attempts and strict/relaxed
            # certificate handshakes, not only between whole host checks.
            inner = getattr(unwrap(original), "__globals__", {})
            replace(inner, inner_name)
            replace(namespace, name)
    try:
        yield
    finally:
        for owner, name, original, wrapped in reversed(replacements):
            if owner.get(name) is wrapped:
                owner[name] = original


@contextmanager
def observe_checks(checks):
    """Observe the existing fetch and its warnings, without adding requests."""
    namespace = getattr(checks, "__globals__", {})
    original = namespace.get("fetch_front_page")
    observation = {"attempted": False, "answered": None, "warnings": []}
    thread = get_ident()

    class HostWarnings(logging.Handler):
        def emit(self, record):
            if record.thread == thread:
                observation["warnings"].append(record.getMessage())

    warnings = HostWarnings(logging.WARNING)
    root = logging.getLogger()
    root.addHandler(warnings)

    def fetch(*args, **kwargs):
        observation["attempted"] = True
        response = original(*args, **kwargs)
        observation["answered"] = response is not None
        return response

    if callable(original):
        fetch = wraps(original)(fetch)
        namespace["fetch_front_page"] = fetch
    try:
        yield observation
    finally:
        if callable(original) and namespace.get("fetch_front_page") is fetch:
            namespace["fetch_front_page"] = original
        root.removeHandler(warnings)
