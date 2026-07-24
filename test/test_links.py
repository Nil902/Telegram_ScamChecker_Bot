import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from links import extract_urls, analyze_url, analyze_text


def _codes(url):
    return {f.code for f in analyze_url(url)}


# ----------------------------------------------------------------- extraction

def test_extract_scheme_and_www_and_strips_punctuation():
    urls = extract_urls("See https://a.com and www.b.org, please.")
    assert urls == ["https://a.com", "www.b.org"]


def test_extract_bare_domain_with_known_tld():
    assert extract_urls("go to aba-kh.xyz/verify now") == ["aba-kh.xyz/verify"]


def test_extract_ignores_non_url_dotted_tokens():
    # A filename and a package name must not be mistaken for links.
    assert extract_urls("open score_apk.py and com.aba.update") == []


def test_extract_deduplicates_case_insensitively():
    assert extract_urls("A.com a.COM") == ["A.com"]


def test_extract_empty():
    assert extract_urls("") == []
    assert extract_urls("no links here at all") == []


# --------------------------------------------------------------- each signal

def test_ip_address_flagged():
    assert "LINK_IP_ADDRESS" in _codes("http://192.168.0.5/login")


def test_at_sign_obfuscation_flagged():
    codes = _codes("http://ababank.com@evil.tk/login")
    assert "LINK_AT_OBFUSCATION" in codes


def test_punycode_flagged():
    assert "LINK_PUNYCODE" in _codes("http://xn--80ak6aa92e.com")


def test_brand_impersonation_flagged():
    codes = _codes("https://aba-login.xyz/verify")
    assert "LINK_BRAND_IMPERSONATION" in codes


def test_shortener_flagged():
    assert "LINK_SHORTENER" in _codes("https://bit.ly/abc123")


def test_bare_shortener_is_extracted_and_flagged():
    """A shortener written without http/www (bit.ly/win2026) must still be
    recognised as a link — its ccTLD (.ly) is not an ordinary bare TLD."""
    assert extract_urls("Claim at bit.ly/win2026") == ["bit.ly/win2026"]
    assert "LINK_SHORTENER" in _codes("bit.ly/win2026")


def test_suspicious_tld_flagged():
    assert "LINK_SUSPICIOUS_TLD" in _codes("http://random-site.top")


def test_brand_impersonation_carries_params():
    finding = next(f for f in analyze_url("https://wing-money.xyz")
                   if f.code == "LINK_BRAND_IMPERSONATION")
    assert finding.params["brand"] == "wing"
    assert "wing-money.xyz" in finding.params["host"]


# ------------------------------------------------------- false-positive guards

def test_official_bank_site_not_flagged():
    assert analyze_url("https://www.ababank.com/login") == []


def test_brand_substring_is_not_a_token_match():
    """'wingstop' contains 'wing' but is a different word — must not fire."""
    assert _codes("https://wingstop.com") == set()


def test_ordinary_site_stays_quiet():
    assert analyze_url("https://www.wikipedia.org/wiki/Cambodia") == []


# ------------------------------------------------------------- text-level

def test_analyze_text_counts_and_dedupes():
    text = ("first aba-secure.top and second acleda-verify.top — both fake")
    analysis = analyze_text(text)
    assert analysis.urls_checked == 2
    # Two suspicious-TLD links collapse to ONE finding per code.
    tld_findings = [f for f in analysis.findings
                    if f.code == "LINK_SUSPICIOUS_TLD"]
    assert len(tld_findings) == 1


def test_analyze_text_no_links_is_empty():
    analysis = analyze_text("hello how are you today")
    assert analysis.urls_checked == 0
    assert analysis.findings == []


# -------------------------------------------------- platform impersonation

def test_telegram_impersonation_flagged():
    """Scammers impersonate Telegram itself, not only banks."""
    codes = _codes("https://telegram-premium-kh.com")
    assert "LINK_BRAND_IMPERSONATION" in codes


def test_official_telegram_domain_not_flagged():
    assert analyze_url("https://telegram.org/faq") == []
    assert analyze_url("https://t.me/durov") == []


# ---------------------------------------------------------- reward lure

def test_reward_lure_with_link_flagged():
    """The exact reported scam: prize + verify-or-suspend urgency + a link."""
    text = (
        "CONGRATULATIONS! Your account has been selected to receive 1-Year "
        "Free Telegram Premium and a $500 cash prize from our monthly lucky "
        "draw! Click the link below to verify your phone number and claim "
        "your reward immediately: https://telegram-premium-kh.com Note: valid "
        "for 24 hours only. Failure to verify may result in temporary account "
        "suspension."
    )
    analysis = analyze_text(text)
    codes = {f.code for f in analysis.findings}
    assert "LINK_REWARD_LURE" in codes            # the lure pattern
    assert "LINK_BRAND_IMPERSONATION" in codes     # telegram impersonation


def test_lure_without_link_does_not_fire():
    """No link means nothing to click — the lure alone is not actioned here."""
    analysis = analyze_text(
        "Congratulations, you have been selected for a cash prize lucky draw!")
    assert analysis.urls_checked == 0
    assert all(f.code != "LINK_REWARD_LURE" for f in analysis.findings)


def test_single_lure_phrase_is_not_enough():
    """One benign-ish phrase plus a normal link must not raise the lure."""
    analysis = analyze_text("Here is a gift card idea: https://www.wikipedia.org")
    assert all(f.code != "LINK_REWARD_LURE" for f in analysis.findings)


# ------------------------------------------------- URL boundary / non-ASCII

def test_url_glued_to_khmer_text_is_isolated():
    """A link with no space before the following Khmer must not swallow it —
    the host (and its TLD) must stay clean so the checks still fire."""
    text = "ចុចទីនេះ https://aeon-shop-kh.topបញ្ជាក់៖ មិនទាមទារ"
    urls = extract_urls(text)
    assert urls == ["https://aeon-shop-kh.top"]
    assert "LINK_SUSPICIOUS_TLD" in _codes(urls[0])


def test_bare_domain_glued_to_khmer_is_isolated():
    urls = extract_urls("សូមចូល aeon-shop-kh.topឥឡូវនេះ")
    assert urls == ["aeon-shop-kh.top"]


# ------------------------------------------------------- job / order scam

def test_order_grabbing_job_scam_flagged():
    """The reported AEON 'order grabbing' part-time job scam."""
    text = (
        "AEON Mall Cambodia is looking for part-time online workers. Easy "
        "work: just help increase product orders (order grabbing) to boost "
        "store rankings. Income: $30-$100 per day. Register for free to get a "
        "trial bonus immediately: https://aeon-shop-kh.top No experience "
        "required. Limited slots available!"
    )
    analysis = analyze_text(text)
    codes = {f.code for f in analysis.findings}
    assert "LINK_REWARD_LURE" in codes         # the job-scam lure
    assert "LINK_SUSPICIOUS_TLD" in codes       # .top domain
