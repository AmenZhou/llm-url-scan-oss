"""Page text, forms block and page-state rules for the capture worker (stdlib only: the capture image holds this file, capture_worker.py and playwright).

Four entry points, all pure functions over strings:
  html_to_text(html)        visible text, block boundaries kept as newlines
  scan_page(html)           {"title", "forms", "loose_fields", "form_count"}
  extract_buttons(html)     button labels
  classify_state(...)       (state, detail) from the capture facts
  build_page(...)           {"sections": {"final_url", "page_meta", "page_text", "page_forms"}} for judge.build_message

Privacy: nothing here prints, logs or returns an error message, and field values typed or preset by the page are never read into the result
(a field is described by type, name, placeholder and label only). All lengths count Python characters. CSS is never interpreted.
"""
import re
from html.parser import HTMLParser

TITLE_CAP, ACTION_CAP, HINT_CAP, BUTTON_CAP = 200, 200, 80, 40
MAX_FORMS, MAX_FIELDS, MAX_BUTTONS = 10, 30, 12
SHORT_STATE_CHARS = 500       # parked and bot-wall pages are short: a longer page is real content

_DROP = {"script", "style", "noscript", "template"}
_BLOCK = {"p", "div", "br", "hr", "li", "ul", "ol", "tr", "table", "section", "article", "header", "footer", "nav", "main", "aside", "form", "fieldset",
          "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "dl", "dt", "dd", "figure", "figcaption", "details", "summary", "address", "option", "legend"}
_BUTTON_INPUTS = {"submit", "button", "reset", "image"}
_BTN_CLASS = re.compile(r"(^|[\s_-])(btn|button)([\s_-]|$)", re.I)


def _squash(s):
    return re.sub(r"\s+", " ", s).strip()


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.drop, self.head = [], {}, False

    def _nl(self):
        self.out.append("\n")

    def handle_starttag(self, tag, attrs):
        if tag == "body":
            self.head = False
        elif tag == "head":
            self.head = True
        elif tag == "title":
            self.drop["title"] = self.drop.get("title", 0) + 1
        elif tag in _DROP:
            self.drop[tag] = self.drop.get(tag, 0) + 1
        if tag in _BLOCK:
            self._nl()

    def handle_startendtag(self, tag, attrs):
        if tag in _BLOCK:
            self._nl()

    def handle_endtag(self, tag):
        if tag == "head":
            self.head = False
        elif (tag in _DROP or tag == "title") and self.drop.get(tag):
            self.drop[tag] -= 1
        if tag in _BLOCK:
            self._nl()

    def handle_data(self, data):
        if not self.head and not any(self.drop.values()):
            self.out.append(data)


def html_to_text(html):
    """Visible text only: scripts, styles, noscript, templates, the head and the title are dropped; whitespace is collapsed; block boundaries are newlines."""
    p = _Text()
    p.feed(html)
    p.close()
    lines = (re.sub(r"[^\S\n]+", " ", ln).strip() for ln in "".join(p.out).split("\n"))
    return "\n".join(ln for ln in lines if ln)


class _Scan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts, self.in_title = [], False
        self.forms, self.loose, self.buttons = [], [], []
        self.form = None
        self.drop = 0
        self.label = None          # open <label>: {"for", "text", "fields"}
        self.labels_for = {}
        self.btn = None            # open <button> or button-like link: list of text parts
        self.btn_tag = None
        self.all_fields = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in _DROP:
            self.drop += 1
        if self.drop:
            return
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self.form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "fields": []}
            self.forms.append(self.form)
        elif tag == "label":
            self.label = {"for": a.get("for", ""), "text": [], "fields": []}
        elif tag in ("input", "textarea", "select"):
            self._field(tag, a)
        elif tag == "button":
            self.btn, self.btn_tag = [], "button"
        elif tag == "a" and (a.get("role", "").lower() == "button" or _BTN_CLASS.search(a.get("class", ""))):
            self.btn, self.btn_tag = [], "a"

    def _field(self, tag, a):
        ftype = (a.get("type") or "text").lower() if tag == "input" else tag
        if tag == "input" and ftype in _BUTTON_INPUTS:
            self.buttons.append(a.get("value") or a.get("alt") or "submit")
            return
        f = {"type": ftype, "name": a.get("name", ""), "placeholder": a.get("placeholder", ""), "id": a.get("id", ""),
             "autocomplete": a.get("autocomplete", ""), "label": a.get("aria-label", "")}
        (self.form["fields"] if self.form is not None else self.loose).append(f)
        self.all_fields.append(f)
        if self.label is not None:
            self.label["fields"].append(f)

    def handle_endtag(self, tag):
        if tag in _DROP:
            self.drop = max(0, self.drop - 1)
            return
        if self.drop:
            return
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self.form = None
        elif tag == "label" and self.label is not None:
            txt = _squash(" ".join(self.label["text"]))
            if self.label["for"]:
                self.labels_for[self.label["for"]] = txt
            for f in self.label["fields"]:
                f["label"] = f["label"] or txt
            self.label = None
        elif tag == self.btn_tag and self.btn is not None:
            self.buttons.append(" ".join(self.btn))
            self.btn, self.btn_tag = None, None

    def handle_data(self, data):
        if self.drop:
            return
        if self.in_title:
            self.title_parts.append(data)
        if self.label is not None:
            self.label["text"].append(data)
        if self.btn is not None:
            self.btn.append(data)

    def finish(self):
        for f in self.all_fields:
            f["label"] = f["label"] or self.labels_for.get(f["id"], "")


def _scan(html):
    p = _Scan()
    p.feed(html)
    p.close()
    p.finish()
    return p


def scan_page(html):
    """Title, forms (action, method, fields) and fields outside any form. A field is {type, name, placeholder, label, id, autocomplete}; no value is ever read."""
    p = _scan(html)
    return {"title": _squash(" ".join(p.title_parts))[:TITLE_CAP], "forms": p.forms, "loose_fields": p.loose, "form_count": len(p.forms)}


def extract_buttons(html):
    """Labels of buttons, submit/button inputs and links styled or marked as buttons: squashed, cut, de-duplicated, at most MAX_BUTTONS."""
    out = []
    for b in _scan(html).buttons:
        b = _squash(b)[:BUTTON_CAP]
        if b and b not in out:
            out.append(b)
    return out[:MAX_BUTTONS]


# ---------------------------------------------------------------- state rules
_UNREACHABLE = ("ERR_CONNECTION_TIMED_OUT", "ERR_CONNECTION_RESET", "ERR_CONNECTION_CLOSED", "ERR_ADDRESS_UNREACHABLE", "ERR_NETWORK_UNREACHABLE",
                "ERR_EMPTY_RESPONSE", "ERR_TIMED_OUT", "ERR_INTERNET_DISCONNECTED")
_PARKED = re.compile(r"(domain (name )?(is |may be |might be )?(for sale|available|parked)|buy this domain|this domain is parked|domain parking|"
                     r"(is|be) (now )?for sale|this (web)?site (is|has been) (suspended|disabled)|(this )?account (has been )?suspended|"
                     r"default (web )?(server )?page|future home of)", re.I)
_BOT_WALL = re.compile(r"(just a moment|checking your browser|verify(ing)? (that )?you are (a )?human|are you a robot|attention required|"
                       r"enable javascript and cookies to continue|ddos protection|security check|complete the captcha|solve the captcha|"
                       r"press (&|and) hold|access denied)", re.I)


def classify_state(kind, err_text, hops, text, forms, deny_reason=None, downloaded=False):
    """Decide the page state from the capture facts. -> (state, detail), details being the keys of capture_worker.STATE_DETAIL.

    kind         None, "timeout", "error" or "crash" (as the worker records it)
    err_text     browser error text, read here in memory only, never returned
    hops         [(http status or None, failure text or None)], one per main-frame navigation event
    text         visible page text, or None when no page was read
    forms        number of forms plus loose fields
    deny_reason  the egress proxy's reason when it refused the request, else None
    downloaded   the navigation turned into a file download

    States: "ok" (detail None), "timed out", "gone", "blocked" (detail "proxy-denied", a STATE_DETAIL key, or "unclassified").
    'parked' needs short text AND no form: a short lure page with a login form is "ok" and reaches the judge. The bot wall and a bare 4xx wall follow the same rule.
    """
    if kind == "timeout":
        return "timed out", None
    if deny_reason:
        return ("gone", "dns") if deny_reason == "no-address" else ("blocked", "proxy-denied")
    if kind == "error":
        err = (err_text or "") + " " + " ".join(h[1] or "" for h in hops)
        if "ERR_NAME_NOT_RESOLVED" in err:
            return "gone", "dns"
        if "ERR_CONNECTION_REFUSED" in err:
            return "gone", "refused"
        if any(e in err for e in _UNREACHABLE):
            return "gone", "unreachable"
        return "blocked", "unclassified"
    statuses = [h[0] for h in hops if h[0] is not None]
    status = statuses[-1] if statuses else None
    if status == 404:
        return "gone", "http-404"
    if status == 410:
        return "gone", "http-410"
    if downloaded and not text:
        return "ok", None
    if text is None:
        return "blocked", "unclassified"
    if len(text) <= SHORT_STATE_CHARS and not forms:
        if status is not None and 400 <= status < 500:      # a bare error wall; a 4xx page with real content or a form still goes to the judge
            return "blocked", "http-4xx"
        if _BOT_WALL.search(text):
            return "blocked", "bot-wall"
        if _PARKED.search(text):
            return "gone", "parked"
    return "ok", None


# ---------------------------------------------------------------- the sections for the judge
def _token(s, cap):
    """One whitespace-free token: spaces become underscores."""
    return re.sub(r"\s+", "_", s.strip())[:cap]


def _action(a):
    """Action without query or fragment (they can carry tokens), no whitespace; empty means the form posts to its own page."""
    a = _token(a.split("#")[0].split("?")[0], ACTION_CAP)
    return a or "self"


def _field_line(f):
    hint = _squash(" / ".join(x for x in (f["label"], f["placeholder"]) if x.strip()))[:HINT_CAP].replace('"', "'")
    parts = ["field: type=%s" % (_token(f["type"], 20) or "text"), "name=%s" % (_token(f["name"], 60) or "none")]
    if hint:
        parts.append('hint="%s"' % hint)
    if f["id"].strip():
        parts.append("id=%s" % _token(f["id"], 40))
    if f["autocomplete"].strip():
        parts.append("autocomplete=%s" % _token(f["autocomplete"], 30))
    return "  " + " ".join(parts)


def _forms_block(scan, buttons):
    lines = []
    for i, form in enumerate(scan["forms"][:MAX_FORMS], 1):
        lines.append("form %d action=%s method=%s" % (i, _action(form["action"]), _token(form["method"], 10) or "get"))
        lines += [_field_line(f) for f in form["fields"][:MAX_FIELDS]]
        if len(form["fields"]) > MAX_FIELDS:
            lines.append("  +%d more fields" % (len(form["fields"]) - MAX_FIELDS))
    if scan["loose_fields"]:
        lines.append("loose fields")
        lines += [_field_line(f) for f in scan["loose_fields"][:MAX_FIELDS]]
    if buttons:
        lines.append("buttons: " + " | ".join(buttons))
    return "\n".join(lines)


def build_page(url, final_url, last_status, redirect_count, title, text, scan, buttons, download):
    """-> {"sections": {"final_url", "page_meta", "page_text", "page_forms"}}, all strings, in the shape judge.build_message reads.
    final_url is empty when it equals the input address (the judge then shows "none"). The caller adds "url" (cut query) itself.
    The judge adds the `truncated:` line and applies the caps."""
    final = (final_url or "").strip()
    if final == (url or "").strip():
        final = ""
    meta = ["title: %s" % _squash(title or "")[:TITLE_CAP]]
    if last_status is not None:
        meta.append("http_status: %d" % last_status)
    meta.append("redirects: %d" % redirect_count)
    if download is not None:
        ext = re.sub(r"[^A-Za-z0-9.]", "", download[0] or "")[:10]
        meta.append("download: yes%s" % (" (%s)" % ext if ext else ""))
    return {"sections": {"final_url": final, "page_meta": "\n".join(meta), "page_text": text, "page_forms": _forms_block(scan, buttons)}}
