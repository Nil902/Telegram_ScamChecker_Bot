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

    # The headline sentence must come from something we actually observed.
    # LLM-proposed findings are rendered separately by _llm_suggestion_block
    # under an "unconfirmed" header, so they are excluded here — otherwise a
    # MEDIUM guess would outrank the LOW "not fully checked" note and become
    # the main thing the reply says.
    deterministic = [f for f in findings if not f.code.startswith(LLM_PREFIX)]
    if deterministic:
        findings = deterministic

    if not findings:
        return None
    return max(findings, key=lambda f: evidence.SEVERITY_RANK[f.severity])


LLM_PREFIX = "LLM_SUGGESTED_"


def _llm_suggestion_block(codes: list[str], recorded: dict | None) -> str:
    """Render LLM-proposed findings under their own 'unconfirmed' header.

    Kept strictly separate from the main reason line. A deterministic finding
    is something we observed; one of these is something a model thought the
    metadata might mean. Presenting them in the same voice would let a guess
    borrow the authority of a measurement.
    """
    if recorded is None:
        recorded = evidence.all_findings()
    suggested = [recorded[c] for c in codes
                 if c in recorded and c.startswith(LLM_PREFIX)]
    if not suggested:
        return ""

    lines = []
    for f in sorted(suggested, key=lambda x: x.code):
        lines.append(km.FINDING_KM.get(f.code) or f.explanation)
    return km.LLM_SUGGESTED_HEADER + "\n" + "\n".join(lines) + "\n\n"


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


def _is_unverified(result: FinalVerdict) -> bool:
    """True when the ONLY thing recorded was 'no rule covers this type'.

    Deliberately strict: the moment any other finding exists, this is False
    and the normal verdict label is used. The unverified tier can therefore
    never mask or soften a real warning — it only replaces a green SAFE that
    would otherwise have been unearned.
    """
    if result.verdict != "SAFE":
        return False
    recorded = result.findings or {}
    if not recorded:
        return False
    return set(recorded) <= evidence.UNVERIFIED_CODES


def format_reply(result: FinalVerdict) -> str:
    """The full bilingual message sent to the user."""
    unverified = _is_unverified(result)

    if unverified:
        label_km = km.VERDICT_LABEL_UNVERIFIED
        label_en = km.VERDICT_LABEL_UNVERIFIED_EN
        step_km = km.NEXT_STEP_UNVERIFIED
        step_en = km.NEXT_STEP_UNVERIFIED_EN
    else:
        label_km = km.VERDICT_LABEL.get(result.verdict, "⚪")
        label_en = km.VERDICT_LABEL_EN.get(result.verdict, result.verdict)
        step_km = km.NEXT_STEP.get(result.verdict, "")
        step_en = km.NEXT_STEP_EN.get(result.verdict, "")

    reason_km = _khmer_reason(result.evidence_codes, result.findings)

    if unverified:
        # Never let the model's prose supply the English half here. It has
        # been told nothing fired, so it tends to write something reassuring
        # ("this looks like a normal installer") — which would sit directly
        # under a Khmer line saying the file could not be checked. Use the
        # finding's own hand-written English so both halves agree.
        top = _top_finding(result.evidence_codes, result.findings)
        reason_en = top.explanation if top else km.NO_DANGER_FOUND_EN
    else:
        reason_en = result.reason or km.NO_DANGER_FOUND_EN

    # Only shown when the top finding has a curated prediction; '' otherwise.
    next_move = _next_move_block(result.evidence_codes, result.findings)

    # Only present when the LLM triage path ran; '' otherwise.
    suggestions = _llm_suggestion_block(result.evidence_codes, result.findings)

    return (
        f"{label_km} / {label_en}\n"
        f"\n"
        f"{reason_km}\n"
        f"\n"
        f"{suggestions}"
        f"{next_move}"
        f"👉 {step_km}\n"
        f"\n"
        f"─────────────\n"
        f"{reason_en}\n"
        f"{step_en}"
    )