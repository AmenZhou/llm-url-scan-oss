"""Pattern flags P05, P12, P13, P15. The word lists are frozen; do not tune them.
Each function returns a bool or a member of a fixed enum, never page text, an address or a host."""
import re
from urllib.parse import urlsplit

SHORT_CHARS = 1000
UNDER_CHARS = 40
FREE_HOSTING = ("blogspot", "github.io", "wixsite", "weebly", "netlify.app", "pages.dev", "vercel.app")

_SIGNIN = re.compile(r"\b(please (sign|log)[ -]?in|(sign|log)[ -]?in (is )?(required|needed)|you (must|need to|have to) (sign|log)[ -]?in|"
                     r"(sign|log)[ -]?in (to (continue|proceed|your account|my account|verify|confirm|access your|view your|secure|unlock|restore|reactivate|update)|with your)|"
                     r"(verify|confirm) your (account|identity|e-?mail|password|information|details|payment|card|phone|billing)|"
                     r"update your (account|password|payment|billing|information|details|card)|enter your (password|pin|credentials|login|passcode)|"
                     r"(user ?name|e-?mail) and password|"
                     r"enter the (verification|security|one-time) code|re-?authenticate)\b", re.I)
_LURE = re.compile(r"\b(your (account|card|payment method|profile) (has been |was |is |will be )?(suspended|locked|limited|disabled|restricted|compromised|closed)|"
                   r"unusual (sign-?in )?activity (was |has been )?(detected|noticed|found)|unauthori[sz]ed (access|sign-?in|login|transaction|activity)|"
                   r"security (alert|warning)(?=\s*[:!])|"
                   r"you have won|you've won|you (have|'ve) been selected (to receive|as (a|the) (lucky )?winner|for a (free|prize|reward|gift))|claim your (prize|reward|gift|refund)|"
                   r"(parcel|package|shipment|delivery) (could not|couldn't|cannot|can't|was not|wasn't|has not|hasn't) (be )?(delivered|collected|released)|"
                   r"(parcel|package|shipment|delivery) (is on hold|on hold|has been held|is held)|"
                   r"pay (a |the )?(small )?(re-?delivery|customs|shipping|delivery) fee|(re-?delivery|customs) (fee|charge|duty) (is |are )?(due|unpaid|required|needed|outstanding)|"
                   r"pay (with|using|by) (a )?(gift cards?|voucher codes?|bitcoin|crypto)|"
                   r"payment (is )?(overdue|past due)|overdue invoice|"
                   r"your (subscription|plan|membership) (has )?(expired|been (suspended|cancelled|canceled)))\b", re.I)


def _addr(sec):
    """The final address when there is one, else the input address (kept in memory, never returned)."""
    f = (sec.get("final_url") or "").strip()
    return f if f and f.lower() != "none" else (sec.get("url") or "").strip()


def _split(addr):
    a = addr.strip()
    if "://" not in a:
        a = "http://" + a
    try:
        return urlsplit(a)
    except ValueError:
        return urlsplit("http://invalid.invalid")


def host_of(addr):
    try:
        h = (_split(addr).hostname or "").lower()
    except ValueError:
        h = ""
    return h[4:] if h.startswith("www.") else h


def is_free_host(host):
    return any(f in host for f in FREE_HOSTING)


def P05(sec):
    """Free hosting or free site-builder parent domain."""
    return is_free_host(host_of(_addr(sec)))


def P12(sec):
    """Sign-in or verification wording. TEXT ONLY: ignores the address line."""
    return bool(_SIGNIN.search(sec.get("page_text") or ""))


def P13(sec):
    """Social-engineering lure text."""
    return bool(_LURE.search(sec.get("page_text") or ""))


def P15(text_chars):
    """Thin or script-shell page: under 40, at most 1,000 (SHORT), longer."""
    return "under40" if text_chars < UNDER_CHARS else ("thin" if text_chars <= SHORT_CHARS else "longer")
