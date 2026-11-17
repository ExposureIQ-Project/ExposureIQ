import json
from dataclasses import replace

import pytest

from exposureiq.ai.config import (AIConfig, ConfigError, confirm_remote, consent_message, config_path,
                                  load_config, mask_key, public_config, save_config, validate_config)

FAKE_KEY = "FAKE-UNIT-TEST-NOT-A-REAL-KEY-1234"


def remote():
    return AIConfig(mode="remote", base_url="https://ai.example.com/v1", model="fake/model", api_key=FAKE_KEY)


def test_permissions_masking_environment_override_and_repr(monkeypatch):
    config = confirm_remote(remote(), accepted=True)
    save_config(config)
    path = config_path()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert FAKE_KEY not in repr(config)
    assert FAKE_KEY not in json.dumps(public_config(config))
    assert public_config(config)["key_mask"].endswith("1234")
    monkeypatch.setenv("EXPOSUREIQ_AI_KEY", "FAKE-ENV-OVERRIDE-5678")
    loaded = load_config()
    assert loaded.key == "FAKE-ENV-OVERRIDE-5678" and loaded.api_key == FAKE_KEY
    save_config(loaded)
    assert "FAKE-ENV-OVERRIDE" not in path.read_text(encoding="utf-8")
    assert public_config(loaded)["env_override"]
    assert mask_key("short") == "••••" and mask_key("") == "not set"


def test_remote_opt_in_names_host_and_url_changes_revoke_it():
    config = remote()
    assert not config.ready
    assert consent_message(config) == "Scan summaries (host names, findings) will be sent to ai.example.com"
    with pytest.raises(ConfigError):
        save_config(config)
    with pytest.raises(ConfigError):
        confirm_remote(config, accepted=False)
    accepted = confirm_remote(config, accepted=True)
    assert accepted.ready
    assert not replace(accepted, base_url="https://other.example.com/v1").ready


@pytest.mark.parametrize("url", ["http://ai.example.com/v1", "https://user:pass@ai.example.com/v1",
                                  "https://ai.example.com/v1?key=secret", "file:///etc/passwd",
                                  "https://ai.example.com/v1#key", "https://ai.example.com/../v1",
                                  "https://ai.example.com:99999/v1"])
def test_unsafe_remote_urls_fail_closed_without_echoing(url):
    with pytest.raises(ConfigError) as error:
        validate_config(replace(remote(), base_url=url))
    assert url not in str(error.value) and FAKE_KEY not in str(error.value)


def test_local_mode_is_loopback_only_and_has_no_key(monkeypatch):
    monkeypatch.setenv("EXPOSUREIQ_AI_KEY", FAKE_KEY)
    config = validate_config(AIConfig(mode="local", base_url="http://localhost:11434/v1", model="fake", api_key=FAKE_KEY))
    assert config.ready and not config.key and not config.api_key
    assert config.base_url == "http://127.0.0.1:11434/v1"
    save_config(config)
    assert FAKE_KEY not in config_path().read_text(encoding="utf-8")
    with pytest.raises(ConfigError):
        validate_config(replace(config, base_url="http://example.com/v1"))


def test_bad_json_and_insecure_config_never_echo_a_key():
    path = config_path()
    path.parent.mkdir(parents=True)
    path.write_text("invalid " + FAKE_KEY, encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ConfigError) as error:
        load_config()
    assert FAKE_KEY not in str(error.value)
    save_config(AIConfig(mode="demo"))
    path.chmod(0o644)
    with pytest.raises(ConfigError):
        load_config()


def test_private_settings_cannot_be_redirected_inside_project(monkeypatch, tmp_path):
    from exposureiq.ai import locations

    monkeypatch.setattr(locations, "PROJECT_ROOT", tmp_path)
    with pytest.raises(ConfigError, match="outside the project"):
        save_config(AIConfig(mode="demo"))
    with pytest.raises(ConfigError, match="outside the project"):
        load_config()


def test_remote_http_localhost_is_pinned_before_consent():
    config = confirm_remote(AIConfig(mode="remote", base_url="http://localhost:1234/v1", model="fake", api_key=FAKE_KEY), accepted=True)
    assert config.base_url == config.consent_base == "http://127.0.0.1:1234/v1"


def test_oversized_environment_key_is_rejected_without_echo(monkeypatch):
    monkeypatch.setenv("EXPOSUREIQ_AI_KEY", "FAKE" * 1025)
    with pytest.raises(ConfigError, match="invalid format"):
        validate_config(remote())


def test_developer_preference_defaults_off_is_private_and_does_not_enable_ai():
    assert not load_config().developer_mode and public_config(load_config())["state"] == "off"
    saved = save_config(AIConfig(developer_mode=True, api_key=FAKE_KEY))
    loaded = load_config()
    assert saved == loaded and loaded.developer_mode and loaded.mode == "off" and not loaded.ready
    assert FAKE_KEY not in config_path().read_text(encoding="utf-8")
    assert public_config(loaded)["developer_mode"] is True
    with pytest.raises(ConfigError, match="on or off"):
        validate_config(AIConfig(developer_mode="yes"))


def test_old_demo_preferences_migrate_to_off_without_rewriting_or_network():
    path = config_path()
    path.parent.mkdir(parents=True)
    original = '{"mode":"demo","api_key":"FAKE-LEGACY-ONLY"}\n'
    path.write_text(original, encoding="utf-8")
    path.chmod(0o600)
    loaded = load_config()
    assert loaded.mode == "off" and not loaded.key and not loaded.ready
    assert not loaded.developer_mode and path.read_text(encoding="utf-8") == original
    assert save_config(AIConfig(mode="demo")).mode == "off"


def test_private_settings_without_new_developer_field_still_load():
    path = config_path()
    path.parent.mkdir(parents=True)
    path.write_text('{"mode":"off"}', encoding="utf-8")
    path.chmod(0o600)
    assert load_config() == AIConfig()
