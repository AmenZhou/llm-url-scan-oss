"""Secrets: key files read by the service process only, and the generated secrets (salt, X25519 pair, caller token) under <data dir>/secrets/.
Nothing here prints or returns a secret except the functions whose job is to hand it to the process."""
import hashlib
import hmac
import json
import os
import secrets as _rand
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class KeyError_(Exception):
    """A key or secret file is missing or malformed; the text is ours, never file content."""


def read_env_value(path, var):
    """Value of `var` in a KEY=value file (also `export KEY=value`). Raises KeyError_ without echoing anything."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        raise KeyError_("key file unreadable") from None
    hits = [l for l in lines if l.startswith(var + "=") or l.startswith("export " + var + "=")]
    if len(hits) != 1:
        raise KeyError_("key file shape wrong")
    v = hits[0].split("=", 1)[1].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    if len(v) < 8:
        raise KeyError_("key file shape wrong")
    return v


def _write_secret(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)


def init_secrets(data_dir):
    """Create the data dir (0700) and the generated secrets (0600). Never overwrites. Prints nothing; returns the new salt version."""
    d = Path(data_dir)
    sec = d / "secrets"
    sec.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    os.chmod(sec, 0o700)
    ver = max([int(p.name.split(".")[1]) for p in sec.glob("hid_salt.*")] or [0]) + 1
    _write_secret(sec / ("hid_salt.%d" % ver), _rand.token_bytes(32).hex())
    if not (sec / "recheck_public.key").exists():
        priv = X25519PrivateKey.generate()
        _write_secret(sec / "recheck_private.key", priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
        _write_secret(sec / "recheck_public.key", priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    if not (sec / "callers.json").exists():
        hashes_ = {}
        for label in ("owner", "scheduler"):       # the scheduler token opens only /internal/recheck6
            token = _rand.token_hex(32)
            _write_secret(sec / ("caller_token_" + label), token)
            hashes_[label] = hashlib.sha256(token.encode()).hexdigest()
        _write_secret(sec / "callers.json", json.dumps(hashes_))
    return ver


def load_salt(data_dir):
    """-> (version, 32 bytes) of the newest salt file."""
    files = sorted(Path(data_dir, "secrets").glob("hid_salt.*"), key=lambda p: int(p.name.split(".")[1]))
    if not files:
        raise KeyError_("no active salt")
    return int(files[-1].name.split(".")[1]), bytes.fromhex(files[-1].read_text().strip())


def load_public_key(data_dir):
    return bytes.fromhex(Path(data_dir, "secrets", "recheck_public.key").read_text().strip())


def load_private_key(data_dir):
    return bytes.fromhex(Path(data_dir, "secrets", "recheck_private.key").read_text().strip())


def load_callers(data_dir):
    """label -> sha256 hex of the caller token."""
    return json.loads(Path(data_dir, "secrets", "callers.json").read_text())


def caller_for(token, callers):
    """Constant-time check of a bearer token against every stored hash. -> label or None."""
    h = hashlib.sha256((token or "").encode()).hexdigest()
    found = None
    for label, stored in callers.items():
        if hmac.compare_digest(h, stored):
            found = label
    return found
