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
 