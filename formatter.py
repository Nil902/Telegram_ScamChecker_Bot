import evidence
import strings_km as km
from verdict import FinalVerdict


def _top_finding(codes: list[str], recorded: dict | None = None):
    """The highest-severity finding among `codes`, or None if there is none.

    This is the single finding the reply card speaks about, so both the reason
    and the next-move prediction must agree on it. See _khmer_reason for why
    `recorded` is passed in rather than read from the thread-local registry.
    """
    if recorded is None:
        recorded = evidence.all_findings()
    findings = [recorded[c] for c in codes if c in recorded]
    if not findings:
        return None
    return max(findings, key=lambda f: evidence.SEVERITY_RANK[f.severity])


def _khmer_reason(codes: list[str], recorded: dict | None = None) -> str:
    """Build the Khmer explanation from finding codes.

    Uses the highest-severity finding. Falls back to English if a code has
    no translation yet — an untranslated warning is better than none.

    `recorded` (code -> Finding) must be supplied by the caller from the
    verdict's own findings. It is thread-local state otherwise, and the reply
    is formatted on a different thread than the analysis ran on — reading the
    registry there returns nothing and silently produces the "no danger"
    message over a real warning. Defaults to the registry only for callers
    (unit tests) that run in the same thread as the analysis.
    """
    top = _top_finding(codes, recorded)
    if top is None:
        return km.NO_DANGER_FOUND

    template = km.FINDING_KM.get(top.code)
    if template is None:
        return top.explanation          # untranslated fallback

    try:
        return template.format(**top.params)
    except (KeyError, IndexError):
        return template                 # missing param — show raw template


def _next_move_block(codes: list[str], recorded: dict | None) -> str:
    """The 'what they will do next' section, or '' when we have no prediction.

    Predictions exist only for a curated set of finding codes; for anything
    else we say nothing rather than guess at the scammer's playbook.
    """
    top = _top_finding(codes, recorded)
    if top is None:
        return ""
    km_line = km.NEXT_MOVE_KM.get(top.code)
    en_line = km.NEXT_MOVE_EN.get(top.code)
    if not km_line:
        return ""
    block = (
        "⚠️ អ្វីដែលគេនឹងធ្វើបន្ទាប់ / What they will do next:\n"
        f"{km_line}"
    )
    if en_line:
        block += f"\n{en_line}"
    return block + "\n\n"


def format_reply(result: FinalVerdict) -> str:
    """The full bilingual message sent to the user."""
    label_km = km.VERDICT_LABEL.get(result.verdict, "⚪")
    label_en = km.VERDICT_LABEL_EN.get(result.verdict, result.verdict)

    reason_km = _khmer_reason(result.evidence_codes, result.findings)
    step_km = km.NEXT_STEP.get(result.verdict, "")
    step_en = km.NEXT_STEP_EN.get(result.verdict, "")

    reason_en = result.reason or km.NO_DANGER_FOUND_EN

    # Only shown when the top finding has a curated prediction; '' otherwise.
    next_move = _next_move_block(result.evidence_codes, result.findings)

    return (
        f"{label_km} / {label_en}\n"
        f"\n"
        f"{reason_km}\n"
        f"\n"
        f"{next_move}"
        f"👉 {step_km}\n"
        f"\n"
        f"─────────────\n"
        f"{reason_en}\n"
        f"{step_en}"
    )