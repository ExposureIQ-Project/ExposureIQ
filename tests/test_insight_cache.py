from exposureiq import storage
from exposureiq.insight import cache
import json


def test_scan_cache_hit_miss_and_content_hash(tmp_path, monkeypatch, ai_scan_factory):
    path = tmp_path / "scan.json"
    storage.save_scan(ai_scan_factory(), str(path))
    first = cache.cached_scan_digest(path)
    first_hash = cache.file_hash(path)
    assert cache.cache_directory().is_relative_to(tmp_path)
    original = storage.load_scan
    calls = []
    monkeypatch.setattr(storage, "load_scan", lambda name: calls.append(name) or original(name))
    assert cache.cached_scan_digest(path) == first
    assert calls == []
    storage.save_scan(ai_scan_factory(1, rules=[]), str(path))
    assert cache.file_hash(path) != first_hash
    assert cache.cached_scan_digest(path)["risk"]["high"] == 0
    assert len(calls) == 1


def test_private_summary_cache_and_key_dimensions():
    key = cache.summary_key("history-a", "fake", "v1")
    assert key != cache.summary_key("history-a", "fake", "v2")
    assert key != cache.summary_key("history-b", "fake", "v1")
    assert key != cache.summary_key("history-a", "other", "v1")
    secret = "FAKE-TEST-KEY-ONLY-1234"
    assert cache.get_cached("summary", key) is None
    assert cache.put_cached("summary", key, {"text": secret, "api_key": secret}, secrets=(secret,))
    assert cache.get_cached("summary", key) == {"text": "[redacted]"}
    path = cache._path("summary", key)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    path.write_text("bad JSON", encoding="utf-8")
    assert cache.get_cached("summary", key) is None


def test_digest_cache_checksum_detects_corruption(tmp_path, ai_scan_factory):
    path = tmp_path / "scan.json"
    storage.save_scan(ai_scan_factory(), str(path))
    expected = cache.cached_scan_digest(path)
    cache_path = cache._path("digest", cache.file_hash(path))
    envelope = json.loads(cache_path.read_text(encoding="utf-8"))
    envelope["digest"]["risk"]["high"] = 999
    cache_path.write_text(json.dumps(envelope), encoding="utf-8")
    assert cache.cached_scan_digest(path) == expected


def test_cache_inside_project_or_public_cache_is_ignored(monkeypatch, tmp_path):
    from exposureiq.ai import locations

    key = cache.summary_key("input", "fake", "v1")
    assert cache.put_cached("summary", key, {"text": "fixture"})
    path = cache._path("summary", key)
    path.chmod(0o644)
    assert cache.get_cached("summary", key) is None
    monkeypatch.setattr(locations, "PROJECT_ROOT", tmp_path)
    assert not cache.put_cached("summary", key, {"text": "fixture"})
    assert cache.get_cached("summary", key) is None
