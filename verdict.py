import json
import logging
import re
from dataclasses import dataclass, field
 
import evidence
 
log = logging.getLogger(__name__)
 
VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "DANGEROUS"}
 
_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)
 
 
@dataclass
class FinalVerdict:
    verdict: str                       # authoritative, derived from evidence
    reason: str
    next_step: str
    evidence_codes: list[str]
    agent_verdict: str | None = None   # what the model claimed
    disagreed: bool = False
    fabricated_codes: list[str] = field(default_factory=list)
    parse_failed: bool = False
    # The findings the reply is rendered from, carried on the verdict itself.
    # The bot formats the reply on a different thread than the analysis ran on,
    # so the renderer must NOT reach back into the thread-local evidence
    # registry — it would be empty there. code -> Finding.
    findings: dict = field(default_factory=dict)
 
 
def _extract_json(raw: str) -> dict | None:
    """Models wrap JSON in fences or add a sentence before it. Handle both."""
    cleaned = _FENCE.sub("", raw).strip()
 
    # Attempt 1: already valid JSON
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
 
    # Attempt 2: grab the outermost {...} block
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None
 
 
def finalise(raw_output: str) -> FinalVerdict:
    """Reconcile the agent's answer with the evidence actually collected."""
    recorded = evidence.all_findings()
    derived = evidence.derive_verdict()
 
    parsed = _extract_json(raw_output)
 
    # Graceful degradation: if the model output is unusable we still answer,
    # using the wording carried by the highest-severity finding itself.
    if parsed is None:
        log.warning("Could not parse agent JSON: %r", raw_output[:200])
        return FinalVerdict(
            verdict=derived,
            reason=_fallback_reason(recorded),
            next_step=_fallback_step(derived),
            evidence_codes=list(recorded),
            parse_failed=True,
            findings=recorded,
        )
 
    agent_verdict = str(parsed.get("verdict", "")).upper().strip()
 
    claimed = parsed.get("evidence_codes") or []
    if not isinstance(claimed, list):
        claimed = []
 
    # Any code the tools never emitted is a fabrication.
    fabricated = [c for c in claimed if c not in recorded]
    valid = [c for c in claimed if c in recorded]
 
    if fabricated:
        log.warning("Agent fabricated evidence codes: %s", fabricated)
 
    disagreed = agent_verdict in VALID_VERDICTS and agent_verdict != derived
    if disagreed:
        log.info("Verdict disagreement: agent=%s derived=%s",
                 agent_verdict, derived)
 
    reason = str(parsed.get("reason", "")).strip()
    # Discard the model's prose whenever it contradicts the derived verdict —
    # a SAFE label above an alarming paragraph is worse than either alone.
    if not reason or (derived == "SAFE" and (fabricated or disagreed)):
        reason = _fallback_reason(recorded)
 
    return FinalVerdict(
        verdict=derived,                 # evidence wins, always
        reason=reason,
        next_step=str(parsed.get("next_step", "")).strip() or _fallback_step(derived),
        evidence_codes=valid or list(recorded),
        agent_verdict=agent_verdict or None,
        disagreed=disagreed,
        fabricated_codes=fabricated,
        findings=recorded,
    )
 
 
def grounded_verdict() -> FinalVerdict:
    """Build a verdict purely from recorded evidence, with no model output.

    Used by analysis paths that have no LLM step — link checking is entirely
    deterministic, and every finding already carries hand-written English and
    a Khmer translation, so no model is needed to phrase the reply.
    """
    recorded = evidence.all_findings()
    derived = evidence.derive_verdict()
    return FinalVerdict(
        verdict=derived,
        reason=_fallback_reason(recorded),
        next_step=_fallback_step(derived),
        evidence_codes=list(recorded),
        findings=recorded,
    )


def _fallback_reason(recorded: dict) -> str:
    """Every Finding carries hand-written plain English, so the bot can answer
    usefully even if the LLM fails completely."""
    if not recorded:
        return "I did not find anything dangerous in this file."
    top = max(recorded.values(), key=lambda f: evidence.SEVERITY_RANK[f.severity])
    return top.explanation
 
 
def _fallback_step(verdict: str) -> str:
    return {
        "SAFE": "You can open this.",
        "SUSPICIOUS": "Do not open this unless you are sure who sent it.",
        "DANGEROUS": "Do not open or click this. Delete it.",
    }[verdict]
 