"""Config fail-fast tests (S2)."""

import pytest

from demo_server.config import ConfigError, load_config

BASE = {
    "CYBERGUARD_PROJECT_SLUG": "demo",
    "CYBERGUARD_MASTER_KEY": "cg_org_secret_value_123",
}


def test_defaults_applied():
    cfg = load_config(dict(BASE))
    assert cfg.gateway_url == "http://localhost:8000/api/v1"
    assert cfg.ship_timeout_s == 10
    assert cfg.ship_max_retries == 3
    assert cfg.demo_port == 8020
    assert cfg.store_path == "data/responses.db"
    assert cfg.gateway_endpoint == "http://localhost:8000/api/v1/p/demo/gateway"


def test_missing_slug_fails_fast():
    env = {k: v for k, v in BASE.items() if k != "CYBERGUARD_PROJECT_SLUG"}
    with pytest.raises(ConfigError, match="CYBERGUARD_PROJECT_SLUG"):
        load_config(env)


def test_missing_key_fails_fast():
    env = {k: v for k, v in BASE.items() if k != "CYBERGUARD_MASTER_KEY"}
    with pytest.raises(ConfigError, match="gateway key is required"):
        load_config(env)


def test_both_key_sources_fails_fast():
    env = dict(BASE, CYBERGUARD_KEY_FILE="/tmp/key.txt")
    with pytest.raises(ConfigError, match="only one"):
        load_config(env)


def test_key_file_read(tmp_path):
    kf = tmp_path / "gateway.key"
    kf.write_text("cg_org_from_file\n")
    env = {"CYBERGUARD_PROJECT_SLUG": "demo", "CYBERGUARD_KEY_FILE": str(kf)}
    cfg = load_config(env)
    assert cfg.master_key == "cg_org_from_file"


def test_key_file_missing_fails_fast():
    env = {"CYBERGUARD_PROJECT_SLUG": "demo", "CYBERGUARD_KEY_FILE": "/nonexistent/key"}
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(env)


def test_key_file_empty_fails_fast(tmp_path):
    kf = tmp_path / "empty.key"
    kf.write_text("   \n")
    env = {"CYBERGUARD_PROJECT_SLUG": "demo", "CYBERGUARD_KEY_FILE": str(kf)}
    with pytest.raises(ConfigError, match="empty"):
        load_config(env)


@pytest.mark.parametrize(
    "var,value",
    [
        ("SHIP_TIMEOUT_S", "abc"),
        ("SHIP_MAX_RETRIES", "1.5"),
        ("DEMO_PORT", "eighty-twenty"),
    ],
)
def test_bad_int_vars_fail_fast(var, value):
    with pytest.raises(ConfigError, match=var):
        load_config(dict(BASE, **{var: value}))


def test_key_never_in_repr_or_describe():
    cfg = load_config(dict(BASE))
    assert "cg_org_secret_value_123" not in repr(cfg)
    assert "cg_org_secret_value_123" not in str(cfg)
    assert "cg_org_secret_value_123" not in str(cfg.describe())
    assert cfg.describe()["master_key"] == "***REDACTED***"
