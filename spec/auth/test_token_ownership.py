"""Files written under sudo must be chowned back to the invoking user.

leetha needs root for packet capture, so `sudo leetha` is a normal way to run
it. Anything it writes into the user's data directory as root stays root-owned,
and every later unprivileged command that touches those files dies with
PermissionError. The data dir, cache dir, log and database already call
fix_ownership; the admin token and CA directory did not.
"""

import os

import pytest

from leetha.auth.tokens import generate_token, save_admin_token


@pytest.fixture
def under_sudo(monkeypatch):
    """Pretend we were launched via sudo by a uid-1000 user."""
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")


@pytest.fixture
def chowned(monkeypatch):
    """Record every path handed to fix_ownership instead of chowning it."""
    seen = []
    import leetha.platform as platform
    monkeypatch.setattr(platform, "fix_ownership", lambda p: seen.append(str(p)))
    return seen


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")
def test_save_admin_token_chowns_the_token_file(tmp_path, under_sudo, chowned):
    save_admin_token(generate_token(), tmp_path)
    assert str(tmp_path / "admin-token") in chowned


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")
def test_save_admin_token_chowns_the_containing_dir(tmp_path, under_sudo, chowned):
    """The directory is created with parents=True, so it can be root-owned too."""
    target = tmp_path / "fresh" / ".leetha"
    save_admin_token(generate_token(), target)
    assert str(target) in chowned


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")
def test_token_is_still_written_and_readable(tmp_path, under_sudo, chowned):
    """Ownership handling must not disturb the actual write."""
    raw = generate_token()
    path = save_admin_token(raw, tmp_path)
    assert path.read_text().strip() == raw


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")
def test_no_chown_when_not_under_sudo(tmp_path, monkeypatch):
    """Outside sudo there is nothing to correct — stay a no-op.

    save_admin_token calls fix_ownership unconditionally (as config.py and
    store.py do); the sudo guard lives inside the helper, so that is what has
    to be exercised here.
    """
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    calls = []
    monkeypatch.setattr(os, "chown", lambda *a, **kw: calls.append(a))

    save_admin_token(generate_token(), tmp_path)
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership only")
def test_permission_error_is_reported_not_raised_raw(tmp_path, monkeypatch):
    """A root-owned token file must produce a clear error, not a traceback.

    Existing installs already have root-owned tokens; they need to be told what
    to do rather than shown a stack trace from pathlib.
    """
    from leetha.auth.tokens import TokenWriteError

    def _boom(*a, **kw):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("pathlib.Path.write_text", _boom)

    with pytest.raises(TokenWriteError) as exc:
        save_admin_token(generate_token(), tmp_path)
    assert "chown" in str(exc.value)
