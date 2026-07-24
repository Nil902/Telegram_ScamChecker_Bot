# tests/test_khmer.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence
import strings_km as km
from models import Finding, Severity
from formatter import format_reply, _khmer_reason
from verdict import FinalVerdict


def test_every_verdict_has_a_label():
    for v in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
        assert v in km.VERDICT_LABEL
        assert v in km.NEXT_STEP


def test_khmer_reason_for_known_code():
    evidence.start_run()
    evidence.record("inspect_apk", [Finding(
        "APK_OTP_THEFT_SIGNATURE", Severity.CRITICAL, "english text")])
    out = _khmer_reason(["APK_OTP_THEFT_SIGNATURE"])
    assert out == km.FINDING_KM["APK_OTP_THEFT_SIGNATURE"]
    assert "SMS" not in out or "លេខកូដ" in out    # it is Khmer, not English


def test_template_params_are_filled():
    evidence.start_run()
    evidence.record("inspect_apk", [Finding(
        "APK_REMOTE_ACCESS_TOOL", Severity.HIGH, "english",
        params={"name": "AnyDesk"})])
    out = _khmer_reason(["APK_REMOTE_ACCESS_TOOL"])
    assert "AnyDesk" in out
    assert "{name}" not in out


def test_missing_translation_falls_back_to_english():
    """An untranslated warning is better than no warning."""
    evidence.start_run()
    evidence.record("t", [Finding(
        "BRAND_NEW_CODE", Severity.HIGH, "This is the English fallback.")])
    assert _khmer_reason(["BRAND_NEW_CODE"]) == "This is the English fallback."


def test_no_findings_gives_safe_message():
    evidence.start_run()
    assert _khmer_reason([]) == km.NO_DANGER_FOUND


def test_full_card_renders():
    evidence.start_run()
    finding = Finding(
        "APK_REMOTE_ACCESS_TOOL", Severity.HIGH, "AnyDesk is real but risky.",
        params={"name": "AnyDesk"})
    evidence.record("inspect_apk", [finding])
    result = FinalVerdict(
        verdict="SUSPICIOUS", reason="AnyDesk is real but risky.",
        next_step="Do not install it.", evidence_codes=["APK_REMOTE_ACCESS_TOOL"],
        findings={"APK_REMOTE_ACCESS_TOOL": finding})
    card = format_reply(result)
    assert "🟡" in card
    assert "AnyDesk" in card
    assert "─────────────" in card


def test_card_uses_carried_findings_not_thread_local():
    """Regression for the cross-thread bug: the bot formats the reply on a
    different thread than the analysis ran on, so the thread-local evidence
    registry is EMPTY at render time. The Khmer text must come from the
    verdict's own carried findings — otherwise a real warning renders as the
    'nothing dangerous' message."""
    evidence.start_run()          # simulate the render thread: registry empty
    assert evidence.all_findings() == {}
    result = FinalVerdict(
        verdict="SUSPICIOUS",
        reason="English remote-access warning.",
        next_step="Be careful.",
        evidence_codes=["APK_REMOTE_ACCESS_TOOL"],
        findings={"APK_REMOTE_ACCESS_TOOL": Finding(
            "APK_REMOTE_ACCESS_TOOL", Severity.HIGH, "en",
            params={"name": "AnyDesk"})},
    )
    card = format_reply(result)
    expected_km = km.FINDING_KM["APK_REMOTE_ACCESS_TOOL"].format(name="AnyDesk")
    assert km.NO_DANGER_FOUND not in card     # must NOT claim "nothing dangerous"
    assert "AnyDesk" in card                   # {name} filled from carried data
    assert expected_km in card                 # full Khmer warning rendered