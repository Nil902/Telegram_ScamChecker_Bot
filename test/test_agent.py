import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence
import agent


def test_llm_failure_degrades_to_non_safe_verdict(monkeypatch):
    """The incident: Gemini returned an empty response and Crew.kickoff()
    raised. inspect_file must NOT propagate the crash, and must NOT fall open
    to SAFE — an aborted analysis is 'could not check', i.e. SUSPICIOUS."""

    class _BoomCrew:
        def __init__(self, *a, **k):
            pass

        def kickoff(self):
            raise ValueError("Invalid response from LLM call - None or empty.")

    monkeypatch.setattr(agent, "Crew", _BoomCrew)

    result = agent.inspect_file(filename="virus.apkm", message_text="",
                                file_url="")

    assert result.verdict == "SUSPICIOUS"          # never SAFE on a failed run
    assert "ANALYSIS_FAILED" in result.evidence_codes
    assert result.reason                            # a real, grounded message


def test_llm_failure_keeps_findings_already_collected(monkeypatch):
    """If a tool recorded a CRITICAL finding before the LLM died, the verdict
    must still reflect it — the failure only floors the severity, never lowers
    what the tools already found."""
    from models import Finding, Severity

    class _BoomCrew:
        def __init__(self, *a, **k):
            pass

        def kickoff(self):
            # Simulate a tool having run and recorded evidence first.
            evidence.record("inspect_apk", [Finding(
                code="APK_OTP_THEFT_SIGNATURE", severity=Severity.CRITICAL,
                explanation="reads your screen and your SMS")])
            raise ValueError("Invalid response from LLM call - None or empty.")

    monkeypatch.setattr(agent, "Crew", _BoomCrew)

    result = agent.inspect_file(filename="fake_bank.apk", file_url="")
    assert result.verdict == "DANGEROUS"
