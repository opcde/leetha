"""CA and TLS material written under sudo must be chowned back.

leetha needs root for capture and generates its web TLS cert on first start,
so a `sudo leetha` run leaves ca/web.key and ca/web.crt owned by root inside
the user's data directory. Fixing this in the low-level writers covers every
call site -- init_ca, issue_cert, ensure_web_cert -- and any added later.
"""

import os

import pytest

from leetha.capture.remote.ca import init_ca, ensure_web_cert, issue_cert


@pytest.fixture
def under_sudo(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")


@pytest.fixture
def chowned(monkeypatch):
    """Record chown targets instead of performing them (tests are not root)."""
    seen = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: seen.append(str(p)))
    return seen


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")


def test_init_ca_chowns_key_and_cert(tmp_path, under_sudo, chowned):
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir)
    assert str(ca_dir / "ca.key") in chowned
    assert str(ca_dir / "ca.crt") in chowned


def test_ensure_web_cert_chowns_the_tls_material(tmp_path, under_sudo, chowned):
    """The exact files left root-owned by a live `sudo leetha` run."""
    ca_dir = tmp_path / "ca"
    cert_path, key_path = ensure_web_cert(ca_dir)
    assert str(key_path) in chowned
    assert str(cert_path) in chowned


def test_issue_cert_chowns_sensor_certs(tmp_path, under_sudo, chowned):
    ca_dir = tmp_path / "ca"
    init_ca(ca_dir)
    out = tmp_path / "out"
    out.mkdir()
    cert_path, key_path = issue_cert(ca_dir, "sensor-1", out)
    assert str(key_path) in chowned
    assert str(cert_path) in chowned


def test_no_chown_when_not_under_sudo(tmp_path, monkeypatch, chowned):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    ensure_web_cert(tmp_path / "ca")
    assert chowned == []


def test_material_is_still_written_correctly(tmp_path, under_sudo, chowned):
    """Ownership handling must not disturb the actual output."""
    cert_path, key_path = ensure_web_cert(tmp_path / "ca")
    assert cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY" in key_path.read_bytes()
