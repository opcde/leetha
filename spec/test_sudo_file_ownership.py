"""Files written during a root session must be handed back to the user.

Capture needs root, so `sudo leetha` is normal. Anything written into the data
or cache directory as root stays root-owned, and the next unprivileged run
fails on it. LeethaApp fixes ownership recursively at *startup*, which does
nothing for files created later in the session -- settings.json was found
root-owned on a live install for exactly that reason.
"""

import os

import pytest

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")


@pytest.fixture
def under_sudo(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")


@pytest.fixture
def chowned(monkeypatch):
    """Record chown targets rather than performing them (tests are not root)."""
    seen = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: seen.append(str(p)))
    return seen


def test_save_config_chowns_settings_json(tmp_path, under_sudo, chowned):
    """Verified live: changing a setting under sudo left settings.json root-owned."""
    from leetha.config import LeethaConfig, save_config

    cfg = LeethaConfig(data_dir=tmp_path)
    save_config(cfg)

    assert str(tmp_path / "settings.json") in chowned


def test_save_config_still_writes_valid_json(tmp_path, under_sudo, chowned):
    import json

    from leetha.config import LeethaConfig, save_config

    cfg = LeethaConfig(data_dir=tmp_path)
    cfg.baseline_quiet_period_minutes = 42
    save_config(cfg)

    data = json.loads((tmp_path / "settings.json").read_text())
    assert data["baseline_quiet_period_minutes"] == 42


def test_saved_adapters_are_chowned(tmp_path, under_sudo, chowned):
    """The operator's interface selection must stay editable without sudo."""
    from leetha.capture.interfaces import AdapterConfig, save_interface_config

    save_interface_config(tmp_path, [AdapterConfig(name="eth0")])

    assert any(p.endswith(".json") for p in chowned), chowned


def test_credential_key_is_chowned(tmp_path, under_sudo, chowned):
    """Losing access to secrets.key locks the operator out of stored credentials."""
    from leetha.inventory import credentials

    credentials._load_or_create_key(tmp_path)

    assert str(tmp_path / "secrets.key") in chowned


def test_nothing_chowned_outside_sudo(tmp_path, monkeypatch, chowned):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    from leetha.config import LeethaConfig, save_config

    save_config(LeethaConfig(data_dir=tmp_path))
    assert chowned == []
