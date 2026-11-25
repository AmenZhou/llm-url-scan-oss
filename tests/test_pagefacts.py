"""The could-not-scan detector and the shop signal, on made-up pages only."""
import pytest

from llm_url_scan.pagefacts import could_not_scan_reason, shop_signal

LOGIN = "form 1 action=/signin method=post\n  field: type=text name=user\n  field: type=password name=pw\nbuttons: Sign in"
HIDDEN = "form 1 action=/x method=post\n  field: type=hidden name=csrf"
SEARCH = "form 1 action=/s method=get\n  field: type=search name=q"


def sec(text="", forms="", title=""):
    return {"page_meta": ("title: " + title) if title else "", "page_text": text, "page_forms": forms}


@pytest.mark.parametrize("s, want", [
    (sec(), "page_empty"),
    (sec("   \n "), "page_empty"),
    (sec("", HIDDEN), None),                                                # a form block means the judge has something to read
    (sec("Just a moment while we check your browser."), "page_bot_wall"),
    (sec("Please wait", title="Attention Required"), "page_bot_wall"),
    (sec("Sign in to continue", LOGIN, title="Just a moment..."), "page_bot_wall"),      # title rule applies even with fields
    (sec("This domain is for sale. Buy this domain today."), "page_parked"),
    (sec("Sorry, the page not found here."), "page_error"),
    (sec("Welcome", SEARCH, title="Page Not Found"), "page_error"),         # a search box is not a visible field
    (sec("Error 404 - nothing here", HIDDEN), "page_error"),                # hidden-only fields do not count
    (sec("Es ist ein Fehler. Seite nicht gefunden."), "page_error"),
])
def test_detector_flags(s, want):
    assert could_not_scan_reason(s) == want


@pytest.mark.parametrize("s", [
    sec("Sign in. An error here would be shown in red.", LOGIN),            # short real login with the word error
    sec("Sign in. This domain is for sale elsewhere.", LOGIN),              # wording rules need no visible field
    sec("Please verify you are a human", LOGIN),
    sec("Welcome to our shop. We ship worldwide. See 404 items.", ""),     # bare number is not enough
    sec("Short ordinary page about gardening tips and soil care."),
    sec("x" * 1500 + " page not found"),                                    # long pages skip the wording rules
])
def test_detector_leaves_real_pages_alone(s):
    assert could_not_scan_reason(s) is None


def test_the_1000_character_boundary():
    pad = "a" * 960
    assert could_not_scan_reason(sec(pad + " page not found")) == "page_error"          # 975 chars
    assert could_not_scan_reason(sec(pad + "z" * 100 + " page not found")) is None      # over 1,000 chars


@pytest.mark.parametrize("text, want", [
    ("Wireless mouse $19.99 - Add to cart", True),
    ("Only 25 USD today. Free shipping on all orders", True),
    ("Price 20.00 EUR. Proceed to checkout", True),
    ("Wireless mouse $19.99 and a long story about mice", False),            # amount alone
    ("Add to cart or buy now, prices on request", False),                    # phrase alone
    ("A plain page about the weather", False),
    ("", False),
])
def test_shop_signal(text, want):
    assert shop_signal(sec(text)) is want
