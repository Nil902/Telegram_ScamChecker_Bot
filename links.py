"""Static analysis of web links in a message. PARSING ONLY.

Nothing is ever fetched or opened — every signal below is derived from the
text of the URL itself, exactly like apk.py derives signals from a manifest
without running the app. The LLM never invents a finding; it only explains
the ones produced here.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from models import Finding, Severity

# ---------------------------------------------------------------- reference

_REF_PATH = Path(__file__).parent / "data" / "cambodian_apps.yaml"
_REF = yaml.safe_load(_REF_PATH.read_text(encoding="utf-8"))

# Global platforms scammers routinely impersonate ("free Telegram Premium",
# "your WhatsApp will be closed"), mapped to their genuine domains. Kept here
# rather than in the bank reference file because these are worldwide brands,
# not Cambodian institutions.
PLATFORM_DOMAINS: dict[str, set[str]] = {
    "telegram":  {"telegram.org", "t.me", "telegram.me", "telegram.dog"},
    "whatsapp":  {"whatsapp.com", "wa.me"},
    "facebook":  {"facebook.com", "fb.com", "fb.me"},
    "instagram": {"instagram.com"},
    "tiktok":    {"tiktok.com"},
    "google":    {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple":     {"apple.com", "icloud.com"},
    "paypal":    {"paypal.com"},
    "binance":   {"binance.com"},
    "coinbase":  {"coinbase.com"},
}

# Every brand we detect impersonation of: Cambodian banks plus the platforms.
BRAND_KEYWORDS: set[str] = (
    {k.lower() for k in _REF["brand_keywords"]} | set(PLATFORM_DOMAINS)
)

# The REAL websites. A host that ends in one of these is the genuine site and
# must never be flagged as impersonation.
OFFICIAL_DOMAINS: set[str] = {
    d.lower()
    for inst in _REF["institutions"]
    for d in inst.get("domains", [])
} | {d for domains in PLATFORM_DOMAINS.values() for d in domains}

# ---------------------------------------------------------------- signatures

# Link shorteners hide the real destination until it is too late to judge it.
SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "bl.ink",
    "shorturl.com", "s.id", "v.gd", "tiny.cc",
}

# Top-level domains disproportionately used for phishing and malware. Kept
# deliberately short and high-signal to avoid false alarms on normal sites.
SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "click",
    "link", "zip", "review", "country", "kim", "cricket", "science", "party",
    "gdn", "loan", "mom", "lol", "rest", "quest", "sbs", "cyou",
}

# The TLDs of every known shortener (ly, gd, gl, ...). Derived from SHORTENERS
# so the two never drift apart. Without these a bare "bit.ly/win2026" — no
# http/www prefix — would not be recognised as a link at all, and the shortener
# warning would silently never fire.
_SHORTENER_TLDS: set[str] = {s.rsplit(".", 1)[-1] for s in SHORTENERS}

# TLDs we will treat as a link even without an http/www prefix. Common ones,
# the suspicious set, and every shortener's TLD, so a bare "aba-kh.xyz/verify"
# or "bit.ly/win2026" is still caught while "score_apk.py" or "com.aba.update"
# is not mistaken for a URL.
_BARE_TLDS: set[str] = {
    "com", "net", "org", "info", "biz", "co", "io", "me", "app", "kh",
    "online", "site", "live", "vip", "cc", "shop", "store", "pro",
} | SUSPICIOUS_TLDS | _SHORTENER_TLDS

# High-signal reward/urgency phrases from prize- and account-suspension scams.
# Each is a multi-word phrase (or a distinctive Khmer phrase) so ordinary
# messages do not trip it — a single "free" or "gift" is not enough. A finding
# fires only when TWO different lures appear alongside a link, which is the
# unmistakable "claim your prize, click here now" pattern.
LURE_PHRASES: tuple[str, ...] = (
    # --- prize / account-suspension scams (English) ---
    "cash prize", "lucky draw", "you have been selected",
    "you've been selected", "has been selected", "claim your reward",
    "claim your prize", "claim your gift", "free premium",
    "verify your phone", "verify your account", "account may be suspended",
    "account suspension", "will be suspended", "temporary account",
    "valid for 24 hours", "24 hours only", "you have won", "you won a",
    "gift card", "congratulations you",
    # --- fake part-time / "order grabbing" job scams (English) ---
    "part-time", "part time", "order grabbing", "grab orders", "grab order",
    "no experience required", "no experience needed", "limited slots",
    "trial bonus", "work from home", "daily income", "easy work",
    "boost store", "increase product orders", "increase orders",
    "per day", "commission per",
    # --- Khmer ---
    "ត្រូវបានជ្រើសរើស",       # "has been selected"
    "ចាប់ឆ្នោត",              # "lucky draw"
    "រង្វាន់ជាសាច់ប្រាក់",    # "cash prize"
    "ដោយឥតគិតថ្លៃ",           # "for free"
    "ផ្ទៀងផ្ទាត់លេខទូរស័ព្ទ",   # "verify phone number"
    "ធ្វើការក្រៅម៉ោង",        # "part-time work"
    "ការងារពីផ្ទះ",           # "work from home"
    "បង្កើនការបញ្ជាទិញ",      # "increase orders"
    "ប្រាក់រង្វាន់សាកល្បង",   # "trial bonus"
    "មិនទាមទារបទពិសោធន៍",     # "no experience required"
    "បរិមាណមានកំណត់",         # "limited slots / limited quantity"
)

# ---------------------------------------------------------------- data types

@dataclass
class LinkAnalysis:
    findings: list[Finding] = field(default_factory=list)
    urls_checked: int = 0

    def to_dict(self) -> dict:
        return {
            "urls_checked": self.urls_checked,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------- extraction

# A URL is ASCII. Restrict matching to characters that may legally appear in
# one, so a link glued directly to Khmer text with no space (…kh.topបញ្ជាក់)
# stops at the domain instead of swallowing the sentence into the host.
_URL_BODY = r"[A-Za-z0-9\-._~:/?#\[\]@!$&*+,;=%]"
_SCHEME_RE = re.compile(rf"(?:https?://|www\.){_URL_BODY}+", re.IGNORECASE)
_BARE_RE = re.compile(
    rf"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{{2,}}(?:/{_URL_BODY}*)?",
    re.IGNORECASE,
)
# Trailing sentence punctuation is not part of the URL.
_TRAILING = "'\".,!?)]}>:;"


def extract_urls(text: str) -> list[str]:
    """Pull candidate links out of free text, in first-seen order.

    Matches http(s):// and www. links, plus bare host/path tokens whose final
    label is a known TLD (so ordinary words with dots are not mistaken for
    links). Duplicates are removed while preserving order.
    """
    if not text:
        return []

    found: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        url = raw.rstrip(_TRAILING)
        if url and url.lower() not in seen:
            seen.add(url.lower())
            found.append(url)

    spans: list[tuple[int, int]] = []
    for m in _SCHEME_RE.finditer(text):
        spans.append(m.span())
        _add(m.group(0))

    for m in _BARE_RE.finditer(text):
        # Skip anything already covered by a scheme/www match.
        if any(s <= m.start() < e for s, e in spans):
            continue
        candidate = m.group(0).rstrip(_TRAILING)
        tld = candidate.split("/", 1)[0].rsplit(".", 1)[-1].lower()
        if tld in _BARE_TLDS:
            _add(candidate)

    return found


def _host(url: str) -> tuple[str, str | None]:
    """Return (hostname, userinfo) for a URL, adding a scheme if it is bare."""
    normalised = url if "://" in url else "http://" + url
    parts = urlsplit(normalised)
    host = (parts.hostname or "").lower()
    # Keep only characters valid in a hostname. Belt-and-suspenders against
    # any non-ASCII text (e.g. Khmer) that slipped in glued to the domain,
    # which would otherwise corrupt the TLD and defeat every check.
    host = re.match(r"[a-z0-9.\-]*", host).group(0)
    return host, parts.username


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_official(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in OFFICIAL_DOMAINS)


# ---------------------------------------------------------------- scoring

def analyze_url(url: str) -> list[Finding]:
    """Interpret a single URL. Pure function — unit-testable in isolation."""
    findings: list[Finding] = []
    host, userinfo = _host(url)
    if not host:
        return findings

    display = host if len(host) <= 60 else host[:57] + "..."

    # A userinfo '@' hides the true host: http://ababank.com@evil.tld opens
    # evil.tld, not the bank. urlsplit already resolved host to the real one.
    if userinfo:
        findings.append(Finding(
            code="LINK_AT_OBFUSCATION",
            severity=Severity.HIGH,
            explanation=(f"This link is built to trick you. It looks like one "
                         f"website but actually opens '{display}'."),
            params={"host": display},
        ))

    # A numeric address instead of a real site name. Banks never do this.
    if _is_ip(host):
        findings.append(Finding(
            code="LINK_IP_ADDRESS",
            severity=Severity.HIGH,
            explanation=("This link goes to a numbered address instead of a "
                         "real website name. Real banks and companies never "
                         "send links like this."),
            params={"host": display},
        ))
        return findings   # an IP host cannot also be a brand/TLD match

    # Punycode: hidden non-Latin letters dressed up as a familiar name.
    if "xn--" in host:
        findings.append(Finding(
            code="LINK_PUNYCODE",
            severity=Severity.HIGH,
            explanation=("This link uses hidden letters to look like a real "
                         "website while actually being a fake copy."),
            params={"host": display},
        ))

    # Brand impersonation: a bank/wallet name appears as a label in the host,
    # but the host is not that company's real website. Exact-token matching
    # (split on '.' and '-') keeps ordinary words like 'wingstop' from firing.
    if not _is_official(host):
        tokens = set(re.split(r"[.\-]", host))
        brand = next((b for b in BRAND_KEYWORDS if b in tokens), None)
        if brand:
            findings.append(Finding(
                code="LINK_BRAND_IMPERSONATION",
                # A host impersonating a real brand is never legitimate, so
                # this is CRITICAL (-> DANGEROUS), not merely suspicious.
                severity=Severity.CRITICAL,
                explanation=(f"This link uses the name '{brand}', but the "
                             f"website '{display}' is not the official "
                             f"'{brand}' website. It is an imitation."),
                params={"brand": brand, "host": display},
            ))

    # Shortener: destination hidden behind a redirect.
    bare_host = host[4:] if host.startswith("www.") else host
    if bare_host in SHORTENERS:
        findings.append(Finding(
            code="LINK_SHORTENER",
            severity=Severity.MEDIUM,
            explanation=("This link hides where it really goes. You cannot see "
                         "the real website until after you have opened it."),
            params={"host": display},
        ))

    # Suspicious top-level domain.
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding(
            code="LINK_SUSPICIOUS_TLD",
            severity=Severity.MEDIUM,
            explanation=("This link uses a web-address ending that is very "
                         "often used for scams."),
            params={"host": display, "tld": tld},
        ))

    return findings


def _lure_hits(text: str) -> list[str]:
    """Distinct reward/urgency lure phrases present in the message."""
    low = text.lower()
    return [p for p in LURE_PHRASES if p.lower() in low]


def analyze_text(text: str) -> LinkAnalysis:
    """Extract every link in a message and score it, plus the message itself.

    Per-link findings are de-duplicated by code (evidence would collapse them
    anyway), so one message with several bad links produces one clear warning
    per problem. A message-level reward/urgency lure is added when a link is
    present alongside at least two lure phrases — the "claim your prize, click
    now" pattern that carries a scam even when the domain itself looks clean.
    """
    urls = extract_urls(text)
    by_code: dict[str, Finding] = {}
    for url in urls:
        for f in analyze_url(url):
            by_code.setdefault(f.code, f)

    lures = _lure_hits(text)
    if urls and len(lures) >= 2:
        by_code.setdefault("LINK_REWARD_LURE", Finding(
            code="LINK_REWARD_LURE",
            # A too-good-to-be-true offer pushing a link is a scam, not a maybe.
            severity=Severity.CRITICAL,
            explanation=("This message offers easy money, a prize, or a "
                         "part-time job that pays a lot for little work, and "
                         "pushes you to click a link. Offers like 'order "
                         "grabbing' jobs or guaranteed daily income are a "
                         "common scam. Do not click the link or pay any money."),
            params={},
        ))

    return LinkAnalysis(findings=list(by_code.values()), urls_checked=len(urls))
