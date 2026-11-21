"""Hashed ids and the sealed address store for the later rechecks.

The API holds only the public key and can insert; the scheduler holds the private key and can read and delete.
Each row: X25519 ephemeral key + AES-256-GCM, random 96-bit nonce, hid + salt_ver as associated data, PRAGMA secure_delete=ON.
"""
import hashlib
import hmac
import os
import sqlite3
import threading
from datetime import timedelta
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_FMT = "%Y-%m-%dT%H:%M:%SZ"


def canonical(url):
    """Scheme and host lower-cased, host in punycode, default port and fragment removed, path and query as given."""
    p = urlsplit(url.strip())
    host = (p.hostname or "").encode("idna").decode("ascii").lower()
    if ":" in host:
        host = "[" + host + "]"
    port = p.port
    if port is not None and not (port == 80 and p.scheme.lower() == "http" or port == 443 and p.scheme.lower() == "https"):
        host += ":%d" % port
    return "%s://%s%s%s" % (p.scheme.lower(), host, p.path, "?" + p.query if p.query else "")


def hid_of(salt, url):
    """HMAC-SHA256(salt, canonical address), 64 hex."""
    return hmac.new(salt, canonical(url).encode("utf-8"), hashlib.sha256).hexdigest()


def _key(shared, eph_pub):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"llm-url-scan recheck v1" + eph_pub).derive(shared)


def _aad(hid, salt_ver):
    return ("%s|%d" % (hid, salt_ver)).encode("ascii")


class RecheckStore:
    """public: 32 raw bytes (insert). private: 32 raw bytes (read, delete). One SQLite file, mode 0600."""

    def __init__(self, path, public=None, private=None):
        self.public, self.private = public, private
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS recheck (hid TEXT, salt_ver INTEGER, eph BLOB, nonce BLOB, url_enc BLOB, due_utc TEXT, "
                        "r6_due_utc TEXT, created_utc TEXT, tries INTEGER DEFAULT 0, PRIMARY KEY (hid, salt_ver))")
        self.db.commit()
        os.chmod(path, 0o600)

    def insert(self, hid, salt_ver, url, now, r6=False):
        """Seal the address; due in 7 days, and in 6 hours too when r6 (an unreadable or cannot-tell page)."""
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key = _key(eph.exchange(X25519PublicKey.from_public_bytes(self.public)), eph_pub)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, url.encode("utf-8"), _aad(hid, salt_ver))
        with self.lock:
            # A re-scan of the same address keeps the first row: day 7 counts from the first scan, and a pending 6 h look is not lost.
            self.db.execute("INSERT OR IGNORE INTO recheck (hid, salt_ver, eph, nonce, url_enc, due_utc, r6_due_utc, created_utc) VALUES (?,?,?,?,?,?,?,?)",
                            (hid, salt_ver, eph_pub, nonce, ct, (now + timedelta(days=7)).strftime(_FMT),
                             (now + timedelta(hours=6)).strftime(_FMT) if r6 else None, now.strftime(_FMT)))
            self.db.commit()

    def rows(self):
        """-> [(hid, salt_ver, due_utc, r6_due_utc, created_utc)] without any address."""
        with self.lock:
            return self.db.execute("SELECT hid, salt_ver, due_utc, r6_due_utc, created_utc FROM recheck ORDER BY created_utc").fetchall()

    def read(self, hid, salt_ver):
        """Decrypt one address (scheduler only). Raises on a wrong key or tampered row."""
        with self.lock:
            eph, nonce, ct = self.db.execute("SELECT eph, nonce, url_enc FROM recheck WHERE hid=? AND salt_ver=?", (hid, salt_ver)).fetchone()
        shared = X25519PrivateKey.from_private_bytes(self.private).exchange(X25519PublicKey.from_public_bytes(eph))
        return AESGCM(_key(shared, eph)).decrypt(nonce, ct, _aad(hid, salt_ver)).decode("utf-8")

    def clear_r6(self, hid, salt_ver):
        with self.lock:
            self.db.execute("UPDATE recheck SET r6_due_utc=NULL WHERE hid=? AND salt_ver=?", (hid, salt_ver))
            self.db.commit()

    def delete(self, hid, salt_ver):
        with self.lock:
            self.db.execute("DELETE FROM recheck WHERE hid=? AND salt_ver=?", (hid, salt_ver))
            self.db.commit()

    def purge_older(self, now, days=10):
        """Hard delete of every row older than `days`; -> the (hid, salt_ver) pairs removed."""
        cut = (now - timedelta(days=days)).strftime(_FMT)
        with self.lock:
            gone = self.db.execute("SELECT hid, salt_ver FROM recheck WHERE created_utc < ?", (cut,)).fetchall()
            self.db.execute("DELETE FROM recheck WHERE created_utc < ?", (cut,))
            self.db.commit()
        return gone
