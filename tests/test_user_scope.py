"""User-scope reader/writer tests, without changing the protected safety tests."""

import ipaddress
from pathlib import Path

import pytest

from exposureiq.discovery import scope
from exposureiq.tui import user_scope


@pytest.fixture
def repo_scope(monkeypatch, tmp_path):
    path = tmp_path / "repo" / "scope.txt"
    path.parent.mkdir()
    path.write_text("# Repo authorization\nrepo.example.com\n", encoding="utf-8")
    monkeypatch.setattr(scope, "SCOPE_FILE", path)
    return path


def test_user_file_allows_exact_names_and_is_read_on_every_call(repo_scope, isolated_user_scope):
    path, names = user_scope.append_hosts("example.com", ["api.example.com"], "example.com")
    assert names == ["api.example.com"] and path == isolated_user_scope
    assert scope.is_in_scope("api.example.com") is True
    assert scope.is_in_scope("repo.example.com") is True
    for target in ("example.com", "other.example.com", "example.net", "192.0.2.10", "api.example.com.evil.net"):
        assert scope.is_in_scope(target) is False
    path.write_text("www.example.com\n", encoding="utf-8")
    assert scope.is_in_scope("api.example.com") is False
    assert scope.is_in_scope("www.example.com") is True


def test_confirm_appends_only_safe_names_and_comment_never_repo_or_ips(repo_scope, isolated_user_scope):
    before = repo_scope.read_bytes()
    path, names = user_scope.append_hosts("example.com", [
        "example.com", "api.example.com", "outside.example.net", "192.0.2.10",
        "notexample.com", "example.com.evil.net", "bad\nexample.com", "api.example.com", "*.example.com",
    ], "example.com")
    assert names == ["example.com", "api.example.com"]
    contents = path.read_text(encoding="utf-8")
    assert contents.startswith("# added ")
    assert "Z for example.com (confirmed by user)\n" in contents
    assert contents.splitlines()[1:] == names
    for line in contents.splitlines()[1:]:
        with pytest.raises(ValueError):
            ipaddress.ip_address(line)
    assert repo_scope.read_bytes() == before
    assert not contents.startswith("\ufeff") and "\r" not in contents


@pytest.mark.parametrize("typed", ["wrong.example.com", "EXAMPLE.COM", "example.com ", " example.com", ""])
def test_wrong_exact_confirmation_writes_nothing(repo_scope, isolated_user_scope, typed):
    with pytest.raises(ValueError, match="exactly"):
        user_scope.append_hosts("example.com", ["api.example.com"], typed)
    assert not isolated_user_scope.exists()


def test_confirm_caps_hosts_at_50(repo_scope):
    hosts = [f"h{index:02}.example.com" for index in range(60)]
    path, names = user_scope.append_hosts("example.com", hosts, "example.com")
    assert names == hosts[:50]
    assert path.read_text(encoding="utf-8").splitlines()[1:] == hosts[:50]


def test_duplicate_existing_names_are_not_readded(repo_scope):
    user_scope.append_hosts("example.com", ["api.example.com"], "example.com")
    path, names = user_scope.append_hosts("example.com", ["api.example.com", "www.example.com"], "example.com")
    assert names == ["www.example.com"]
    assert path.read_text(encoding="utf-8").count("\napi.example.com\n") == 1


def test_missing_or_unreadable_repo_still_fails_closed(monkeypatch, repo_scope, isolated_user_scope):
    isolated_user_scope.parent.mkdir(parents=True)
    isolated_user_scope.write_text("api.example.com\n", encoding="utf-8")
    repo_scope.unlink()
    assert scope.is_in_scope("api.example.com") is False
    with pytest.raises(FileNotFoundError):
        user_scope.append_hosts("example.com", ["new.example.com"], "example.com")
    original = Path.read_text

    def unreadable(path, *args, **kwargs):
        if path == repo_scope:
            raise PermissionError("fake unreadable repo")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable)
    assert scope.is_in_scope("api.example.com") is False


def test_unreadable_user_file_is_ignored_and_warned(monkeypatch, repo_scope, isolated_user_scope, caplog):
    original = Path.read_text

    def unreadable(path, *args, **kwargs):
        if path == isolated_user_scope:
            raise PermissionError("fake unreadable user file")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable)
    assert scope.is_in_scope("api.example.com") is False
    assert scope.is_in_scope("repo.example.com") is True
    assert "User scope file is unreadable" in caplog.text


def test_user_scope_path_uses_override_xdg_or_home(monkeypatch, tmp_path):
    monkeypatch.setenv("EXPOSUREIQUSERSCOPE", str(tmp_path / "override.txt"))
    assert user_scope.user_scope_path() == tmp_path / "override.txt"
    monkeypatch.delenv("EXPOSUREIQUSERSCOPE")
    monkeypatch.setenv("XDGCONFIGHOME", str(tmp_path / "xdg"))
    assert user_scope.user_scope_path() == tmp_path / "xdg" / "exposureiq" / "scope.txt"
    monkeypatch.delenv("XDGCONFIGHOME")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    assert user_scope.user_scope_path() == tmp_path / "home" / ".config" / "exposureiq" / "scope.txt"


def test_user_scope_override_inside_repo_is_rejected(monkeypatch, repo_scope):
    monkeypatch.setenv("EXPOSUREIQUSERSCOPE", str(repo_scope))
    before = repo_scope.read_bytes()
    with pytest.raises(ValueError, match="outside the repository"):
        user_scope.append_hosts("example.com", ["api.example.com"], "example.com")
    assert repo_scope.read_bytes() == before


def test_unreadable_user_scope_is_not_overwritten(monkeypatch, repo_scope, isolated_user_scope):
    original = Path.read_text

    def unreadable(path, *args, **kwargs):
        if path == isolated_user_scope:
            raise PermissionError("fake unreadable user file")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", unreadable)
    with pytest.raises(PermissionError):
        user_scope.append_hosts("example.com", ["api.example.com"], "example.com")
    assert not isolated_user_scope.exists()


def test_scope_link_to_repo_is_never_written(repo_scope, isolated_user_scope):
    before = repo_scope.read_bytes()
    isolated_user_scope.parent.mkdir(parents=True)
    isolated_user_scope.symlink_to(repo_scope)
    with pytest.raises(ValueError):
        user_scope.append_hosts("example.com", ["api.example.com"], "example.com")
    assert repo_scope.read_bytes() == before


def test_missing_user_file_does_not_add_scope_and_invalid_utf8_is_ignored(repo_scope, isolated_user_scope, caplog):
    assert scope.is_in_scope("api.example.com") is False
    isolated_user_scope.parent.mkdir(parents=True)
    isolated_user_scope.write_bytes(b"api.example.com\n\xff\n")
    assert scope.is_in_scope("api.example.com") is False
    assert scope.is_in_scope("repo.example.com") is True
    assert "User scope file is unreadable" in caplog.text
