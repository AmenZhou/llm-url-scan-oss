"""Address validation and the no-DNS classifier. Nothing here resolves a name; the egress proxy decides about resolved addresses.
The classifier covers address literals and name suffixes only and is meant to agree with the egress proxy's classifier (proxy/), which also checks
resolved addresses."""
import ipaddress
import re
from urllib.parse import urlsplit

MAX_URL = 2048
LOCAL_SUFFIXES = ("localhost", "local", "localdomain", "lan", "home", "corp", "intranet", "private", "internal", "test", "invalid", "home.arpa", "svc",
                  "cluster.local")
_EXTRA_V4 = [ipaddress.ip_network(n) for n in ("192.88.99.0/24", "100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "224.0.0.0/4")]
_EXTRA_V6 = [ipaddress.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/23", "2001:db8::/32")]
_GLOBAL_V6 = ipaddress.ip_network("2000::/3")
_NUMERIC = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*", re.I)


class UrlRejected(Exception):
    """The address failed validation (422 url_not_allowed). Carries no text."""


def internal_host(host):
    """True when the host is, by its spelling alone, not a public name or address."""
    h = host.lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version == 4:
            return not ip.is_global or any(ip in n for n in _EXTRA_V4)
        if ip.ipv4_mapped is not None:
            return True
        return not ip.is_global or ip not in _GLOBAL_V6 or any(ip in n for n in _EXTRA_V6)
    if _NUMERIC.fullmatch(h):       # non-canonical numeric host (decimal, hex, short forms)
        return True
    if "." not in h:                # single-label name
        return True
    return any(h == s or h.endswith("." + s) for s in LOCAL_SUFFIXES)


def validate_url(url):
    """-> the address unchanged, or raises UrlRejected. Syntax only, plus the no-DNS internal-target classifier."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL:
        raise UrlRejected()
    if "\\" in url or re.search(r"[\s\x00-\x1f\x7f]", url):
        raise UrlRejected()
    try:
        p = urlsplit(url)
        host, port = p.hostname, p.port
    except ValueError:
        raise UrlRejected() from None
    if p.scheme not in ("http", "https") or not host or p.username is not None or p.password is not None:
        raise UrlRejected()
    try:
        host.encode("idna")
    except UnicodeError:
        raise UrlRejected() from None
    # the host must survive a parse round trip: what we classify is what the browser will use
    netloc = p.netloc.rsplit("@", 1)[-1]
    shown = ("[" + host + "]" if ":" in host else host) + (":%d" % port if port is not None else "")
    if netloc.lower() != shown.lower() and not (port is None and netloc.lower().rstrip(":") == shown.lower()):
        raise UrlRejected()
    if internal_host(host):
        raise UrlRejected()
    return url
