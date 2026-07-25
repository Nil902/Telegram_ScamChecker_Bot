"""The 'unknown file type' tier.

The property under test is not really about one finding code. It is that
"we checked and found nothing" and "we had no way to check" must never again
collapse into the same green SAFE.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence
import formatter
import strings_km as km
from models import Finding, Severity
from verdict import grounded_verdict


def test_unknown_extension_records_the_finding():
    evidence.start_run()
    evidence.note_coverage("archive.qqq")
    assert evidence.UNKNOWN_FILE_TYPE in evidence.all_findings()


def test_known_extension_stays_silent():
    """A .jpg we understand and found nothing in is genuinely clean."""
    evidence.start_run()
    evidence.note_coverage("family.jpg")
    assert evidence.all_findings() == {}


def test_identified_contents_count_as_coverage():
    """No rule for '.qqq', but the bytes were read and understood."""
    evidence.start_run()
    evidence.note_coverage("mystery.qqq", real_type="pdf")
    assert evidence.all_findings() == {}


def test_unknown_type_alone_still_derives_safe():
    """LOW must not inflate the verdict — the tier changes wording only."""
    evidence.start_run()
    evidence.note_coverage("thing.qqq")
    assert evidence.derive_verdict() == "SAFE"


def test_never_outranks_a_real_finding():
    """The whole point: this tier can only ever fill a vacuum."""
    evidence.start_run()
    evidence.record("check_filename_rules", [Finding(
        code="FILENAME_EXECUTABLE",
        severity=Severity.CRITICAL,
        explanation="program",
    )])
    evidence.note_coverage("payload.qqq")

    assert evidence.UNKNOWN_FILE_TYPE not in evidence.all_findings()
    assert evidence.derive_verdict() == "DANGEROUS"


def test_does_not_displace_even_a_low_finding():
    evidence.start_run()
    evidence.record("some_tool", [Finding(
        code="SOMETHING_MILD", severity=Severity.LOW, explanation="mild",
    )])
    evidence.note_coverage("thing.qqq")
    assert evidence.UNKNOWN_FILE_TYPE not in evidence.all_findings()


# --- rendering ---------------------------------------------------------

def test_reply_is_not_labelled_green_safe():
    evidence.start_run()
    evidence.note_coverage("thing.qqq")
    reply = formatter.format_reply(grounded_verdict())

    assert km.VERDICT_LABEL_UNVERIFIED_EN in reply
    assert km.VERDICT_LABEL_UNVERIFIED in reply
    # The reassuring green label and its "you can open this" step must be gone.
    assert km.VERDICT_LABEL["SAFE"] not in reply
    assert km.NEXT_STEP_EN["SAFE"] not in reply


def test_genuinely_clean_file_keeps_the_green_label():
    evidence.start_run()
    evidence.note_coverage("family.jpg")
    reply = formatter.format_reply(grounded_verdict())

    assert km.VERDICT_LABEL["SAFE"] in reply
    assert km.VERDICT_LABEL_UNVERIFIED_EN not in reply


def test_dangerous_file_is_unaffected_by_the_new_tier():
    evidence.start_run()
    evidence.record("check_filename_rules", [Finding(
        code="FILENAME_EXECUTABLE",
        severity=Severity.CRITICAL,
        explanation="program",
    )])
    evidence.note_coverage("payload.qqq")
    reply = formatter.format_reply(grounded_verdict())

    assert km.VERDICT_LABEL["DANGEROUS"] in reply
    assert km.VERDICT_LABEL_UNVERIFIED_EN not in reply


def test_english_half_does_not_contradict_the_khmer_half():
    """The model is told nothing fired, so it writes something reassuring.
    That must not end up printed under a 'not fully checked' heading."""
    from verdict import finalise
    import json

    evidence.start_run()
    evidence.note_coverage("thing.qqq")
    result = finalise(json.dumps({
        "verdict": "SAFE",
        "reason": "This looks like a normal software installer.",
        "next_step": "You can open this.",
        "evidence_codes": [],
    }))

    reply = formatter.format_reply(result)
    assert "normal software installer" not in reply
    assert "not have a way to fully check" in reply


def test_msi_is_covered_not_unknown():
    """Regression guard for the bug that started this: an .msi must reach a
    real rule, never fall through to the unverified tier."""
    assert evidence.is_covered("setup.msi")
