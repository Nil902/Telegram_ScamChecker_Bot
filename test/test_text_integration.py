"""End-to-end grounding tests for the plain-text (link) analysis path.

These exercise the real deterministic pipeline WITHOUT the LLM:
    message string -> links.analyze_text -> evidence.record
                   -> evidence.derive_verdict / verdict.grounded_verdict

That is exactly the path inspect_text() runs in agent.py, so a regression in
extraction, scoring, severity mapping, or verdict derivation is caught here
even though no model is ever called.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence
from links import analyze_text
from models import Finding, Severity
from verdict import grounded_verdict


def _run(message: str):
    """Mirror inspect_text(): fresh run, analyse, record, ground a verdict."""
    evidence.start_run()
    analysis = analyze_text(message)
    evidence.record("inspect_links", analysis.findings)
    return analysis, grounded_verdict()


def test_bank_link_scam_derives_dangerous():
    """A fake-bank link (brand impersonation on a throwaway TLD) is DANGEROUS.

    The scam reads as a bank SMS asking for an OTP; the deterministic signal is
    the link, which impersonates ABA on a .tk domain — CRITICAL, so DANGEROUS.
    """
    _, result = _run(
        "ABA Bank: Your account is locked. Send the 6-digit OTP code to "
        "unlock at http://aba-secure.tk"
    )
    assert evidence.derive_verdict() == "DANGEROUS"
    assert result.verdict == "DANGEROUS"
    assert "LINK_BRAND_IMPERSONATION" in result.evidence_codes


def test_legitimate_bank_notification_derives_safe():
    """THE FALSE-POSITIVE GUARD. Real banks send balance notifications; a
    genuine one carries no link and no lure, so it must derive SAFE. Flagging
    this would teach users to ignore real warnings."""
    analysis, result = _run(
        "ABA Bank: You received 50.00 USD from SOK DARA. Balance 320.15 USD."
    )
    assert analysis.findings == []
    assert evidence.derive_verdict() == "SAFE"
    assert result.verdict == "SAFE"


def test_text_tool_failure_is_not_safe():
    """Fail closed: if the analyser records ANALYSIS_FAILED, the run must never
    come out SAFE, even though no real scam signal was found."""
    evidence.start_run()
    evidence.record("inspect_links", [Finding(
        code="ANALYSIS_FAILED", severity=Severity.HIGH,
        explanation="I could not finish checking this message.")])
    assert evidence.derive_verdict() != "SAFE"
    assert grounded_verdict().verdict != "SAFE"
