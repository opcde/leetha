"""Token generation and hashing utilities."""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

TOKEN_PREFIX = "ltk_"
_TOKEN_BYTES = 24  # 24 bytes = 48 hex chars
_TOKEN_FILENAME = "admin-token"


def _token_dir() -> Path:
    """Directory holding the admin token -- the configured data directory.

    This must follow ``LEETHA_DATA_DIR``. Hard-coding ``~/.leetha`` broke
    service deployments: a systemd unit that points its data directory at
    /var/lib/leetha while running with ``ProtectHome=`` would write the
    token into an inaccessible (or tmpfs-backed, therefore ephemeral) home,
    regenerating the admin token on every restart.

    For a default install ``data_dir`` *is* ``~/.leetha``, so nothing moves.
    """
    try:
        from leetha.config import get_config
        return Path(get_config().data_dir)
    except Exception:
        # Config unavailable (very early startup) -- fall back to the
        # historical location so token lookup still works.
        from leetha.config import _real_home
        return _real_home() / ".leetha"


def generate_token() -> str:
    """Generate a new API token with the ltk_ prefix."""
    return TOKEN_PREFIX + secrets.token_hex(_TOKEN_BYTES)


def hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest of a raw token string."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def save_admin_token(raw_token: str, leetha_dir: Path | None = None) -> Path:
    """Write the raw admin token into the data directory, mode 0600."""
    if leetha_dir is None:
        leetha_dir = _token_dir()
    leetha_dir.mkdir(parents=True, exist_ok=True)
    token_file = leetha_dir / _TOKEN_FILENAME
    token_file.write_text(raw_token + "\n")
    try:
        leetha_dir.chmod(0o700)
        token_file.chmod(0o600)
    except OSError:
        pass  # Windows: Unix permission bits not supported
    return token_file


def _read_token_file(path: Path) -> str | None:
    """Read a token file, treating any I/O problem as "not present".

    Every filesystem error here has to be swallowed. ``Path.exists()``
    raises ``PermissionError`` rather than returning False when a parent
    directory is unreadable, which is exactly what a hardened systemd unit
    produces: ``ProtectHome=`` makes the service user's home unreadable, and
    an escaping error killed the whole backend event loop -- taking packet
    capture down while the web server stayed up.
    """
    try:
        return path.read_text().strip() or None
    except (OSError, ValueError):
        return None


def load_admin_token(leetha_dir: Path | None = None) -> str | None:
    """Read the raw admin token from the data directory, or None if absent.

    Falls back to the legacy ``~/.leetha`` location so an existing token
    keeps working after an upgrade that moves the data directory.
    """
    if leetha_dir is not None:
        return _read_token_file(leetha_dir / _TOKEN_FILENAME)

    try:
        primary = _token_dir() / _TOKEN_FILENAME
    except Exception:
        primary = None
    if primary is not None:
        token = _read_token_file(primary)
        if token:
            return token

    try:
        from leetha.config import _real_home
        legacy = _real_home() / ".leetha" / _TOKEN_FILENAME
    except Exception:
        return None
    return _read_token_file(legacy)
