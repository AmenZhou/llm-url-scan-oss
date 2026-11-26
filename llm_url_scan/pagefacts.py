"""Page-fact rules over the sections the service holds after capture (page_meta, page_text, page_forms). Pure functions, stdlib only.
could_not_scan_reason: a page that was read but shows nothing to judge (empty, bot wall, parked, error page). shop_signal: a price and a cart phrase."""
import re

from . import pagetext as PT
from .decide import SHORT_CHARS

_FIELD = re.compile(r"(?m)^\s*field: type=(\w+)")
_HAS_FORM = re.compile(r"(?mi)^\s*(form \d+|field:|loose fields|buttons:)")      # the judge's own empty_page definition
_WALL_EXTRA = re.compile(r"(not a bot|unusual traffic|one moment, we're checking|\bwaf\b)", re.I)
# a bare "error" or a bare number is NOT enough (it flagged good pages in the counts)
_ERROR = re.compile(r"(page not found|file not found|could not be found|can(?:no|')t be found|not be found|(?:error|http|status)[ :]*(?:code )?(?:404|403|500|502|503)\b|"
                    r"\b(?:404|403|500|502|503)\b[ :-]*(?:error|not found|forbidden|service unavailable)|an error (?:was|has|occurred|occured)|unable to load|"
                    r"service unavailable|temporarily unavailable|under maintenance|ページが見つかり|見つかりませんでした|找不到|頁面執行錯誤|页面不存在|"
                    r"страница не найдена|página no encontrada|seite nicht gefunden|page introuvable|pagina non trovata|sayfa bulunamad)", re.I)
_ERROR_TITLE = re.compile(r"(\b(?:404|403|500|502|503)\b|not found|\berror\b|forbidden|unavailable|ページが見つかり|見つかりませんでした|找不到|錯誤|错误|ошибка)", re.I)
_AMOUNT = re.compile(r"[$€£¥]\s?\d|\b\d+(?:[.,]\d{2})?\s?(?:usd|eur|gbp)\b", re.I)
_CART = re.compile(r"\b(?:add to cart|buy now|checkout|free shipping)\b", re.I)


def _title(meta):
    m = re.search(r"(?m)^title:[ \t]*(.*)$", meta)
    return m.group(1) if m else ""


def visible_fields(forms):
    """Field types a visitor could type into: not hidden, not a search box."""
    return [t for t in _FIELD.findall(forms) if t not in ("hidden", "search")]


def could_not_scan_reason(sec):
    """-> None | "page_download" | "page_empty" | "page_bot_wall" | "page_parked" | "page_error". Wording rules apply only to short pages; most also need no visible field."""
    text, forms, meta = (sec.get("page_text") or "").strip(), sec.get("page_forms") or "", sec.get("page_meta") or ""
    if not text and not _HAS_FORM.search(forms):
        return "page_download" if re.search(r"(?m)^download:", meta) else "page_empty"
    if len(text) > SHORT_CHARS:
        return None
    title, bare = _title(meta), not visible_fields(forms)
    if PT._BOT_WALL.search(title) or _WALL_EXTRA.search(title) or (bare and (PT._BOT_WALL.search(text) or _WALL_EXTRA.search(text))):
        return "page_bot_wall"
    if bare and PT._PARKED.search(text):
        return "page_parked"
    if _ERROR_TITLE.search(title) or (bare and _ERROR.search(text)):
        return "page_error"
    return None


def shop_signal(sec):
    """True when the text shows a price amount AND a cart/shop phrase."""
    t = sec.get("page_text") or ""
    return bool(_AMOUNT.search(t) and _CART.search(t))
