import threading
 
from models import Finding, Severity
 
_local = threading.local()
 
 
def start_run() -> None:
    """Reset state at the beginning of one analysis."""
    _local.findings = {}      # code -> Finding (dict deduplicates)
    _local.tool_calls = []
 
 
def _ensure() -> None:
    """A fresh thread has no attributes yet. Initialise on first touch."""
    if not hasattr(_local, "findings"):
        start_run()
 
 
def record(tool_name: str, findings: list[Finding]) -> None:
    """Called by every tool wrapper after it produces findings."""
    _ensure()
    _local.tool_calls.append(tool_name)
    for f in findings:
        _local.findings[f.code] = f
 
 
def all_findings() -> dict[str, Finding]:
    _ensure()
    return dict(_local.findings)
 
 
def tool_calls() -> list[str]:
    _ensure()
    return list(_local.tool_calls)


# --- coverage: "clean" vs "never actually checked" -----------------------

# Zero findings used to mean SAFE unconditionally. That conflates two very
# different situations:
#
#   (a) we ran a rule that understands this file type and it found nothing
#   (b) we have no rule for this file type at all, so nothing could fire
#
# (b) is how a file can collect a green light purely because we were not
# looking. Everything below exists to tell the two apart and to say so out
# loud in case (b), rather than defaulting to reassurance.

UNKNOWN_FILE_TYPE = "UNKNOWN_FILE_TYPE"
VT_SCAN_UNAVAILABLE = "VT_SCAN_UNAVAILABLE"

# Codes that describe a GAP IN OUR CHECKING rather than a property of the
# file. They are all LOW, so they never move the verdict, but a reply whose
# entire content is one of these must not be dressed up as a green SAFE —
# nothing was actually established. The formatter keys the "not fully
# checked" label off this set.
UNVERIFIED_CODES = {UNKNOWN_FILE_TYPE, VT_SCAN_UNAVAILABLE}


def has_substantive_finding() -> bool:
    """True if anything beyond a we-could-not-check note was recorded."""
    _ensure()
    return any(code not in UNVERIFIED_CODES for code in _local.findings)


def _known_extensions() -> set[str]:
    """Every extension some deterministic check actually understands.

    Imported lazily so this module stays importable on its own and so the
    set can never drift from the rule tables it is derived from.
    """
    from rules import (
        EXECUTABLE_EXT, SHORTCUT_EXT, SYSTEM_MODIFIER_EXT, DISK_IMAGE_EXT,
        MACRO_EXT, ARCHIVE_EXT, BUNDLE_EXT, DOCUMENT_EXT, SAFE_LOOKING_EXT,
    )
    from magic import EXPECTED_TYPES
    return (EXECUTABLE_EXT | SHORTCUT_EXT | SYSTEM_MODIFIER_EXT
            | DISK_IMAGE_EXT | MACRO_EXT | ARCHIVE_EXT | BUNDLE_EXT
            | DOCUMENT_EXT | SAFE_LOOKING_EXT | set(EXPECTED_TYPES))


def is_covered(filename: str, real_type: str | None = None) -> bool:
    """True when some check understood this file well enough to clear it."""
    ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext in _known_extensions():
        return True
    # The name told us nothing, but a magic-byte read identified the
    # contents — that is a real check, so the file counts as covered.
    return bool(real_type) and real_type not in ("unknown", "zip_container")


def note_coverage(filename: str, real_type: str | None = None) -> None:
    """Record UNKNOWN_FILE_TYPE if nothing was ever able to check this file.

    Call once, at the END of an analysis. Two guarantees hold by
    construction:

      - it never outranks a real finding: if anything at all was recorded,
        this returns immediately without adding anything
      - it is LOW, so even alone it cannot push the verdict past SAFE; the
        difference it makes is in the wording the user sees, not in the
        severity arithmetic
    """
    _ensure()
    if has_substantive_finding():
        return
    if is_covered(filename, real_type):
        return
    record("coverage_check", [Finding(
        code=UNKNOWN_FILE_TYPE,
        severity=Severity.LOW,
        explanation=("I found no known danger sign in this file, but I do "
                     "not have a way to fully check this type of file. "
                     "Treat it as unverified rather than confirmed safe."),
        params={"filename": filename},
    )])


# --- verdict derivation -------------------------------------------------
 
SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}
 
# Policy decision: HIGH maps to SUSPICIOUS, not DANGEROUS. A genuine remote
# access app is HIGH — telling a user to delete an app they installed for
# work would be a false positive. Only CRITICAL means "do not open this".
RANK_TO_VERDICT = {
    0: "SAFE",
    1: "SUSPICIOUS",
    2: "SUSPICIOUS",
    3: "DANGEROUS",
}
 
 
def derive_verdict() -> str:
    """The verdict is a function of the evidence. No model involved.
 
    No findings -> SAFE. Otherwise the highest severity decides; severities
    are never averaged, so one CRITICAL among mild findings still yields
    DANGEROUS.
    """
    findings = all_findings().values()
    if not findings:
        return "SAFE"
    top = max(SEVERITY_RANK[f.severity] for f in findings)
    return RANK_TO_VERDICT[top]
 