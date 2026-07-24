import hashlib
import json
import os
import threading
from datetime import datetime, timezone
 
LOG_DIR = "logs"
LOG_PATH = os.path.join(LOG_DIR, "checks.jsonl")
 
# Appends from multiple threads must not interleave mid-line.
_write_lock = threading.Lock()
 
 
def _hash(value: str) -> str:
    """Short, stable, non-reversible identifier."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
 
 
def _extension(filename: str) -> str:
    return "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
 
 
def log_check(
    *,
    filename: str,
    result,                    # FinalVerdict
    tools_called: list[str],
    duration_ms: int,
    user_id: int | None = None,
    source: str = "telegram",
    label: str | None = None,  # ground truth, set only when running evaluation
) -> None:
    """Append one record. Never raises — logging must not break the bot."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
 
        # --- input (privacy-preserving) ---
        "file_hash": _hash(filename),
        "extension": _extension(filename),
        "user_hash": _hash(str(user_id)) if user_id is not None else None,
 
        # --- what the agent did ---
        "tools_called": tools_called,
        "tool_count": len(tools_called),
        "duration_ms": duration_ms,
 
        # --- the verdict, both versions ---
        "verdict": result.verdict,              # derived from evidence
        "agent_verdict": result.agent_verdict,  # what the model claimed
        "disagreed": result.disagreed,
 
        # --- grounding audit ---
        "evidence_codes": result.evidence_codes,
        "fabricated_codes": result.fabricated_codes,
        "fabrication_count": len(result.fabricated_codes),
        "parse_failed": result.parse_failed,
 
        # --- evaluation only ---
        "label": label,
    }
 
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False)
        with _write_lock:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        # Deliberate: a logging failure must never stop a user getting their
        # scam warning. Disk full is not a reason to withhold the answer.
        pass
 