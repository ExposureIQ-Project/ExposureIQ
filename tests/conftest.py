"""Keep every test away from the developer's real user authorization file."""

import pytest


@pytest.fixture(autouse=True)
def isolated_user_scope(monkeypatch, tmp_path):
    path = tmp_path / "user-config" / "scope.txt"
    monkeypatch.setenv("EXPOSUREIQUSERSCOPE", str(path))
    return path
