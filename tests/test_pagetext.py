"""pagetext: visible text, forms block, buttons and the state table. Everything here is made up (BrandX, *.example.invalid); no browser, network or docker."""
import pytest

from llm_url_scan import pagetext as pt
from llm_url_scan.judge import build_message

FILLER = "<p>This is made up filler sentence number %d for the BrandX test page.</p>"
NORMAL = ("<html><head><title>BrandX Home</title><meta charset=utf-8></head><body><h1>Welcome to BrandX</h1>" + "".join(FILLER % i for i in range(40)) +
          '<form action="https://forms.example.invalid/post" method="POST"><label for=e>Email address</label><input id=e name=email type=text>'
          '<button type=submit>Subscribe</button></form></body></html>')
LOGIN = ('<html><head><title>BrandX Sign in</title></head><body><h1>BrandX</h1>'
         '<form action="https://collect.example.invalid/p?token=SECRET" method=post>'
         '<label>User <input type=text name=user placeholder="Online ID"></label>'
         '<input type=password name=pw placeholder="Password" autocomplete=current-password value="hunter2-typed">'
         '<input type=submit value="Verify now"></form></body></html>')


def test_normal_page_text_and_scan():
    text = pt.html_to_text(NORMAL)
    assert len(text) > 1000 and text.startswith("Welcome to BrandX\nThis is made up filler")
    assert "BrandX Home" not in text          # the title is metadata, not visible text
    s = pt.scan_page(NORMAL)
    assert s["title"] == "BrandX Home" and s["form_count"] == 1 and s["loose_fields"] == []
    f = s["forms"][0]
    assert f["method"] == "post" and f["action"].startswith("https://forms.example.invalid/")
    assert f["fields"][0]["label"] == "Email address" and f["fields"][0]["name"] == "email"
    assert pt.extract_buttons(NORMAL) == ["Subscribe"]


def test_login_form_facts_and_no_values():
    s = pt.scan_page(LOGIN)
    types = [f["type"] for f in s["forms"][0]["fields"]]
    assert types == ["text", "password"]
    assert s["forms"][0]["fields"][0]["label"] == "User"
    built = pt.build_page("http://login.example.invalid/", "http://login.example.invalid/", 200, 0, s["title"], pt.html_to_text(LOGIN), s, pt.extract_buttons(LOGIN), None)
    forms = built["sections"]["page_forms"]
    assert "type=password" in forms and "hint=\"Password\"" in forms and "autocomplete=current-password" in forms
    assert "buttons: Verify now" in forms
    assert "hunter2" not in forms and "SECRET" not in forms          # no field value, no query string
    assert "action=https://collect.example.invalid/p " in forms


def test_hidden_fields_and_loose_fields_are_reported():
    html = ('<body><form action=/go><input type=hidden name=csrf value=abc123><input type=hidden name=redirect_to value=x></form>'
            '<input type=email name=loose placeholder="Mail"></body>')
    s = pt.scan_page(html)
    assert [f["type"] for f in s["forms"][0]["fields"]] == ["hidden", "hidden"] and len(s["loose_fields"]) == 1
    block = pt.build_page("u", "u", 200, 0, "", "", s, [], None)["sections"]["page_forms"]
    assert "type=hidden name=csrf" in block and "loose fields" in block and "abc123" not in block and "action=/go" in block


def test_script_style_noscript_template_and_head_are_dropped():
    html = ("<html><head><title>T</title><style>.x{color:red}</style><script>var secret=1</script></head><body>"
            "<script>document.write('evil')</script><style>p{}</style><noscript>enable js</noscript><template><p>tmpl</p></template>"
            "<div style='display:none'>still visible, css is not interpreted</div><p>Hello</p><p>World</p></body></html>")
    text = pt.html_to_text(html)
    assert text == "still visible, css is not interpreted\nHello\nWorld"


def test_whitespace_collapses_and_blocks_become_newlines():
    assert pt.html_to_text("<p>a   b\t c</p>\n\n<div>d<br>e</div>  <ul><li>x</li><li>y</li></ul>") == "a b c\nd\ne\nx\ny"
    assert pt.html_to_text("") == "" and pt.html_to_text("   \n ") == ""


def test_unicode_text_is_kept_and_counts_characters():
    text = pt.html_to_text("<p>Zahlung für BrandX &ndash; 请验证您的账户 &#x1F512; café&nbsp;ok</p>")
    assert text == "Zahlung für BrandX – 请验证您的账户 \U0001F512 café ok"
    assert len(pt.html_to_text("<p>\U0001F512\U0001F512</p>")) == 2


def test_buttons_are_deduplicated_capped_and_include_link_buttons():
    html = ("<button>Go</button><button> Go </button><input type=button value=Next><a class='btn btn-primary' href=/x>Sign <b>in</b></a><a href=/plain>plain link</a>"
            + "".join("<button>b%d</button>" % i for i in range(30)) + "<button>%s</button>" % ("x" * 100))
    out = pt.extract_buttons(html)
    assert out[:3] == ["Go", "Next", "Sign in"] and "plain link" not in out and len(out) == pt.MAX_BUTTONS
    assert pt.extract_buttons("<button>" + "y" * 100 + "</button>") == ["y" * pt.BUTTON_CAP]


def test_sections_feed_the_judge():
    s = pt.scan_page(NORMAL)
    built = pt.build_page("http://a.example.invalid/", "http://b.example.invalid/x", 200, 1, s["title"], pt.html_to_text(NORMAL), s, pt.extract_buttons(NORMAL), (".exe", 0))
    sec = built["sections"]
    assert set(sec) == {"final_url", "page_meta", "page_text", "page_forms"} and all(isinstance(v, str) for v in sec.values())
    assert sec["page_meta"] == "title: BrandX Home\nhttp_status: 200\nredirects: 1\ndownload: yes (.exe)"
    msg, info, _ = build_message(dict(sec, url="http://a.example.invalid/"))
    assert "<final_url>http://b.example.invalid/x</final_url>" in msg and not info["empty_page"] and info["text_chars"] > 1000
    same = pt.build_page("http://a.example.invalid/", "http://a.example.invalid/", None, 0, "", "", s, [], None)["sections"]
    assert same["final_url"] == "" and same["page_meta"] == "title: \nredirects: 0"


def test_form_count_for_the_worker_is_forms_plus_loose_fields():
    s = pt.scan_page("<form></form><input name=a>")
    assert len(s["forms"]) + len(s["loose_fields"]) == 2
    assert pt.scan_page("<p>no forms</p>") == {"title": "", "forms": [], "loose_fields": [], "form_count": 0}


# ---- the state table: (kind, err_text, hops, text, forms, deny_reason, downloaded) -> (state, detail)
OK_HOP = [(200, None)]
LONG = "Real content. " * 100
PARKED = "This domain is for sale. Buy this domain today."
SUSPENDED_LURE = "Your account has been suspended. Sign in to restore access."
WALL = "Just a moment... Checking your browser before accessing the site."
TABLE = [
    (("timeout", "", [], None, 0, None, False), ("timed out", None)),
    (("error", "net::ERR_NAME_NOT_RESOLVED", [(None, "net::ERR_NAME_NOT_RESOLVED")], None, 0, None, False), ("gone", "dns")),
    (("error", "net::ERR_CONNECTION_REFUSED", [], None, 0, None, False), ("gone", "refused")),
    (("error", "net::ERR_CONNECTION_TIMED_OUT", [], None, 0, None, False), ("gone", "unreachable")),
    (("error", "", [(None, "net::ERR_CONNECTION_RESET")], None, 0, None, False), ("gone", "unreachable")),
    (("error", "something else entirely", [], None, 0, None, False), ("blocked", "unclassified")),
    (("error", "", OK_HOP, "x", 0, None, False), ("blocked", "unclassified")),
    ((None, "", OK_HOP, LONG, 1, "name-blocked", False), ("blocked", "proxy-denied")),
    ((None, "", OK_HOP, LONG, 1, "no-address", False), ("gone", "dns")),
    ((None, "", [(404, None)], LONG, 1, None, False), ("gone", "http-404")),
    ((None, "", [(302, None), (410, None)], "x", 0, None, False), ("gone", "http-410")),
    ((None, "", [(403, None)], "No", 0, None, False), ("blocked", "http-4xx")),
    ((None, "", [(403, None)], LONG, 1, None, False), ("ok", None)),             # a 4xx page with real content is still read
    ((None, "", [(403, None)], "Access denied", 1, None, False), ("ok", None)),
    ((None, "", [(500, None)], LONG, 0, None, False), ("ok", None)),
    ((None, "", OK_HOP, None, 0, None, False), ("blocked", "unclassified")),
    ((None, "", OK_HOP, None, 0, None, True), ("ok", None)),
    ((None, "", OK_HOP, LONG, 1, None, False), ("ok", None)),
    ((None, "", OK_HOP, "", 0, None, False), ("ok", None)),                      # empty page: the judge answers cannot_tell
    ((None, "", OK_HOP, PARKED, 0, None, False), ("gone", "parked")),
    ((None, "", OK_HOP, PARKED, 1, None, False), ("ok", None)),                  # a parked needs no form
    ((None, "", OK_HOP, SUSPENDED_LURE, 1, None, False), ("ok", None)),          # short lure with a login form reaches the judge
    ((None, "", OK_HOP, PARKED + " " + LONG, 0, None, False), ("ok", None)),  # long text is never parked
    ((None, "", OK_HOP, WALL, 0, None, False), ("blocked", "bot-wall")),
    ((None, "", OK_HOP, WALL, 1, None, False), ("ok", None)),
    ((None, "", OK_HOP, WALL + LONG, 0, None, False), ("ok", None)),
]


@pytest.mark.parametrize("args,want", TABLE, ids=[str(i) for i in range(len(TABLE))])
def test_state_table(args, want):
    assert pt.classify_state(*args) == want


def test_short_lure_with_a_form_is_not_parked_from_real_html():
    html = "<body><p>Your BrandX account has been suspended.</p><form><input type=password name=pw></form></body>"
    text, scan = pt.html_to_text(html), pt.scan_page(html)
    forms = len(scan["forms"]) + len(scan["loose_fields"])
    assert pt.classify_state(None, "", OK_HOP, text, forms) == ("ok", None)
    assert pt.classify_state(None, "", OK_HOP, text, 0) == ("gone", "parked")


def test_states_and_details_fit_the_worker_vocabulary():
    from llm_url_scan.capture_worker import STATE_DETAIL
    details = {a[1] for _, a in [(None, w) for _, w in TABLE] if a[0] in ("gone", "blocked")} - {"proxy-denied", "unclassified"}
    assert details <= set(STATE_DETAIL)
    assert set(STATE_DETAIL) == {"http-404", "http-410", "dns", "refused", "unreachable", "parked", "http-4xx", "bot-wall"}
