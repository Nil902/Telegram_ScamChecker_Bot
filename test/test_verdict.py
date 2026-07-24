import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import evidence
from models import Finding, Severity
from verdict import finalise, _extract_json
 
 
def test_no_findings_forces_safe():
    """The AnyDesk .apkm bug: agent claimed SUSPICIOUS with zero evidence."""
    evidence.start_run()
    out = finalise('{"verdict":"SUSPICIOUS","reason":"name looks unusual",'
                   '"next_step":"be careful","evidence_codes":["WEIRD_NAME"]}')
    assert out.verdict == "SAFE"
    assert out.fabricated_codes == ["WEIRD_NAME"]
    assert out.disagreed
 
 
def test_critical_finding_forces_dangerous():
    """The guard corrects UNDER-warning too, not just over-warning."""
    evidence.start_run()
    evidence.record("check_filename_rules", [Finding(
        code="FILENAME_EXECUTABLE", severity=Severity.CRITICAL,
        explanation="This is an Android app installer.")])
    out = finalise('{"verdict":"SAFE","reason":"looks fine","next_step":"ok",'
                   '"evidence_codes":[]}')
    assert out.verdict == "DANGEROUS"
    assert out.disagreed
 
 
def test_remote_access_maps_to_suspicious():
    evidence.start_run()
    evidence.record("inspect_apk", [Finding(
        code="APK_REMOTE_ACCESS_TOOL", severity=Severity.HIGH,
        explanation="AnyDesk is a real app but lets others control your phone.")])
    out = finalise('{"verdict":"SUSPICIOUS","reason":"real app, risky use",'
                   '"next_step":"do not install if a stranger asked you to",'
                   '"evidence_codes":["APK_REMOTE_ACCESS_TOOL"]}')
    assert out.verdict == "SUSPICIOUS"
    assert not out.disagreed
    assert out.fabricated_codes == []
 
 
def test_unparseable_output_still_answers():
    """Graceful degradation: the bot answers even if the LLM fails."""
    evidence.start_run()
    evidence.record("inspect_apk", [Finding(
        code="APK_OTP_THEFT_SIGNATURE", severity=Severity.CRITICAL,
        explanation="This app can read your screen and your SMS messages.")])
    out = finalise("I think this file is probably fine, honestly.")
    assert out.parse_failed
    assert out.verdict == "DANGEROUS"
    assert "screen" in out.reason
 
 
def test_fenced_json_is_parsed():
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}
 
 
def test_json_with_preamble_is_parsed():
    assert _extract_json('Here is my analysis: {"a": 1}') == {"a": 1}
 
 
def test_garbage_returns_none():
    assert _extract_json("no json here at all") is None
 
 
def test_highest_severity_wins():
    evidence.start_run()
    evidence.record("t", [Finding("LOW_ONE", Severity.LOW, "minor")])
    evidence.record("t", [Finding("CRIT_ONE", Severity.CRITICAL, "serious")])
    assert evidence.derive_verdict() == "DANGEROUS"
 
 
def test_duplicate_findings_deduplicated():
    evidence.start_run()
    f = Finding("SAME", Severity.HIGH, "x")
    evidence.record("t", [f])
    evidence.record("t", [f])
    assert len(evidence.all_findings()) == 1
    assert len(evidence.tool_calls()) == 2


def test_tool_failure_never_yields_safe():
    """A crashed analyser recorded an ANALYSIS_FAILED finding: never SAFE."""
    evidence.start_run()
    evidence.record("inspect_apk", [Finding(
        code="ANALYSIS_FAILED", severity=Severity.HIGH,
        explanation="I could not finish checking this file.")])
    assert evidence.derive_verdict() == "SUSPICIOUS"


def test_safe_verdict_discards_contradicting_reason():
    """A DANGEROUS claim with zero evidence must not leave alarming prose
    sitting above a derived SAFE verdict."""
    evidence.start_run()
    out = finalise('{"verdict":"DANGEROUS","reason":"This is a scam app.",'
                   '"next_step":"Delete it","evidence_codes":[]}')
    assert out.verdict == "SAFE"
    assert "scam" not in out.reason.lower()
    assert out.disagreed
 