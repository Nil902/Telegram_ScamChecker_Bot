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


def test_service_failure_shows_try_again_not_be_careful():
    """When the analysis could not RUN (rate-limit / empty AI response), the
    reply must say 'could not check, try again' rather than the SUSPICIOUS
    'Be careful' card, because the file was never actually judged."""
    failed = Finding("ANALYSIS_FAILED", Severity.HIGH, "could not finish")
    result = FinalVerdict(
        verdict="SUSPICIOUS", reason="", next_step="",
        evidence_codes=["ANALYSIS_FAILED", "VT_SCAN_UNAVAILABLE"],
        findings={"ANALYSIS_FAILED": failed,
                  "VT_SCAN_UNAVAILABLE": Finding(
                      "VT_SCAN_UNAVAILABLE", Severity.LOW, "vt gap")},
    )
    card = format_reply(result)
    assert km.VERDICT_LABEL_UNAVAILABLE_EN in card       # "COULD NOT CHECK ..."
    assert km.SERVICE_UNAVAILABLE_EN in card             # "I am busy ... try again"
    assert km.VERDICT_LABEL_EN["SUSPICIOUS"] not in card  # NOT "BE CAREFUL"


def test_real_danger_before_failure_still_warns():
    """Fail-closed must survive: a CRITICAL found before the agent died still
    renders as DANGEROUS, never softened into the 'could not check' message."""
    result = FinalVerdict(
        verdict="DANGEROUS", reason="It is actually a program.",
        next_step="Delete it.",
        evidence_codes=["TYPE_DISGUISED_EXECUTABLE", "ANALYSIS_FAILED"],
        findings={
            "TYPE_DISGUISED_EXECUTABLE": Finding(
                "TYPE_DISGUISED_EXECUTABLE", Severity.CRITICAL, "a program"),
            "ANALYSIS_FAILED": Finding("ANALYSIS_FAILED", Severity.HIGH, "failed"),
        },
    )
    card = format_reply(result)
    assert "🔴" in card
    assert km.VERDICT_LABEL_UNAVAILABLE_EN not in card    # not the failure message


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