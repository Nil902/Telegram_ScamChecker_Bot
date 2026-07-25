import logging
import os
import time
 
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, LLM
 
import audit
import evidence
from links import analyze_text as _analyze_links
from models import Finding, Severity
from rules import check_filename
from triage import extract_metadata, triage
from verdict import finalise, grounded_verdict, FinalVerdict
from tools import (
    check_filename_rules,
    download_file,
    verify_file_type_tool,
    inspect_apk,
    inspect_links,
    scan_with_virustotal,
    cleanup_downloads,
    last_real_type,
    last_download_path,
)
 
load_dotenv()
 
log = logging.getLogger(__name__)
 
llm = LLM(
    # Gemini 3 models require temperature=1.0 — LiteLLM warns that anything
    # lower causes infinite loops and degraded reasoning. We still get
    # consistent tool routing because the agent prompt and tool docstrings are
    # explicit; we do not rely on a low temperature to pin the routing down.
    #
    # KNOWN LIMITATION: as a thinking model, gemini-3.1-flash-lite can return
    # an empty final response through CrewAI's ReAct loop, which raises inside
    # kickoff(). inspect_file() catches that and degrades to a grounded
    # "could not check" verdict (SUSPICIOUS), so an empty response is safe but
    # yields no real analysis. Switch to gemini/gemini-2.0-flash if that
    # becomes a problem.
    model="gemini/gemini-3.1-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY"),
    temperature=1.0,
)
 
file_inspector = Agent(
    role="File Threat Inspector",
    goal=("Determine whether a file sent to a Cambodian user over Telegram is "
          "dangerous, using the minimum number of tools necessary."),
    backstory=(
        "You protect ordinary people in Cambodia from scams. You know banks "
        "such as ABA, ACLEDA, and Wing never distribute their apps as Telegram "
        "attachments. You are careful never to raise a false alarm on a "
        "legitimate file, because users who receive false alarms stop trusting "
        "warnings. You check filenames first because it is instant and needs "
        "no download. For Android app files the filename alone already tells "
        "you it is dangerous, but you still inspect the manifest when you can, "
        "because naming the exact permissions is what makes the warning "
        "convincing to a frightened user."
    ),
    tools=[check_filename_rules, download_file, verify_file_type_tool,
           inspect_apk, inspect_links, scan_with_virustotal],
    llm=llm,
    # verbose MUST stay False in production: CrewAI prints the full task
    # description to stdout, and that includes the Telegram file_url, which
    # embeds the bot token (https://api.telegram.org/file/bot<TOKEN>/...).
    # Turning this on leaks the token into the application logs.
    verbose=False,
    allow_delegation=False,
)
 
 
EXPECTED_OUTPUT = """Return ONLY a JSON object, with no markdown fences and
no text before or after it:
 
{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "reason": "one or two short sentences in simple English",
  "next_step": "what the user should do right now, one sentence",
  "evidence_codes": ["CODE_FROM_TOOL_OUTPUT", ...]
}
 
RULES:
- evidence_codes must contain ONLY 'code' values that appeared in the
  findings returned by your tools. Never invent a code.
- If every tool returned an empty findings list, then verdict must be
  "SAFE" and evidence_codes must be [].
- Never report a concern that no tool reported. If a tool could not read
  the file, say that plainly in 'reason' rather than guessing.
- Write 'reason' for someone with no computer training. No jargon, and no
  words like "executable", "manifest", or "permission".
"""
 
 
def _metadata_for_triage(filename: str, real_type: str | None) -> dict | None:
    """Extract triage metadata, but only if triage could possibly apply.

    Returns None unless BOTH hold: no deterministic tool found anything, and
    nothing understood this file type. That mirrors exactly the condition
    under which note_coverage() raises UNKNOWN_FILE_TYPE, so the LLM triage
    path cannot run on a file a real rule already has an opinion about.

    Must be called before cleanup_downloads() — it reads the temp file.
    """
    if evidence.has_substantive_finding():
        return None
    if evidence.is_covered(filename, real_type):
        return None

    path = last_download_path()
    if not path or not os.path.exists(path):
        return None
    try:
        return extract_metadata(path, filename)
    except Exception:
        log.exception("Could not extract triage metadata")
        return None


def inspect_file(filename: str,
                 message_text: str = "",
                 file_url: str = "",
                 user_id: int | None = None,
                 label: str | None = None,
                 source: str = "telegram") -> FinalVerdict:
    """Run one analysis end to end and return a grounded verdict.

    Args:
        filename: name as the user received it.
        message_text: any caption sent with the file.
        file_url: HTTPS URL the agent may download from, if it decides to.
        user_id: Telegram user id, hashed before logging.
        label: ground-truth verdict, set only when running the evaluation set.
        source: log tag for where this run came from (the evaluation harness
            overrides it so eval rows are separable from live traffic).
    """
    evidence.start_run()                       # reset registry per analysis
    started = time.monotonic()                 # monotonic: immune to clock changes

    # Filename rules run HERE, unconditionally, before the agent is given a
    # chance to route anything.
    #
    # They used to run only if the LLM chose to call check_filename_rules.
    # That made the model's tool-routing a silent input to the verdict: when
    # it skipped the call, nothing was recorded, and zero findings derived to
    # SAFE. A .msi handed out a green light that way despite .msi having been
    # a CRITICAL extension the whole time. Declining to look is not the same
    # as looking and finding nothing, and the model must not be able to
    # decide which of those happened. The tool stays registered so the agent
    # can still call it and reason about the output; record() is keyed by
    # finding code, so a second call simply overwrites with the same values.
    precheck = check_filename(filename, message_text)
    evidence.record("check_filename_rules", precheck.findings)

    task = Task(
        description=(
            f"A Telegram user in Cambodia received a file and wants to know "
            f"if it is safe.\n\n"
            f"Filename: {filename}\n"
            f"Message sent with it: {message_text or '(none)'}\n"
            f"Download URL (use only if you need the contents): {file_url}\n\n"
            f"Investigate with your tools, using as few as necessary. If the "
            f"message sent with the file contains a web link, check it too."
        ),
        expected_output=EXPECTED_OUTPUT,
        agent=file_inspector,
    )
 
    try:
        raw = str(Crew(agents=[file_inspector], tasks=[task],
                       verbose=False).kickoff())
    except Exception:
        # The agent's reasoning step itself failed — e.g. the LLM returned an
        # empty response. Tools that ran before the failure may already have
        # recorded findings; whatever we have, we must still answer, and we
        # must never fall open to SAFE. Record an explicit failure so an
        # aborted run derives to SUSPICIOUS at least, then let finalise() build
        # the reply from the evidence rather than from (absent) model JSON.
        log.exception("Agent run failed; degrading to a grounded verdict")
        evidence.record("agent", [Finding(
            code="ANALYSIS_FAILED",
            severity=Severity.HIGH,
            explanation=("I could not finish checking this file. Because I "
                         "could not check it, please do not open it unless "
                         "you are certain who sent it."),
            params={"tool": "agent"},
        )])
        raw = ""      # no model JSON; finalise() uses grounded fallbacks
    finally:
        # Read what we need off disk BEFORE the temp files are deleted.
        real_type = last_real_type()
        triage_metadata = _metadata_for_triage(filename, real_type)
        cleanup_downloads()   # always, even if the crew raises

    # Last word before the verdict is derived: if nothing fired AND nothing
    # here understood this file type, say so rather than defaulting to green.
    evidence.note_coverage(filename, real_type)

    # Only now, with UNKNOWN_FILE_TYPE already recorded, may the model add
    # anything of its own — and only ever by ADDING a capped-MEDIUM finding.
    if triage_metadata and evidence.UNKNOWN_FILE_TYPE in evidence.all_findings():
        evidence.record("llm_triage", triage(triage_metadata))

    result = finalise(raw)
    duration_ms = int((time.monotonic() - started) * 1000)
 
    audit.log_check(
        filename=filename,
        result=result,
        tools_called=evidence.tool_calls(),
        duration_ms=duration_ms,
        user_id=user_id,
        source=source,
        label=label,
    )

    log.info("verdict=%s tools=%s codes=%s fabricated=%s (%dms)",
             result.verdict, evidence.tool_calls(),
             result.evidence_codes, result.fabricated_codes, duration_ms)
    return result


def inspect_text(message_text: str,
                 user_id: int | None = None,
                 label: str | None = None,
                 source: str = "telegram_text") -> FinalVerdict:
    """Check a plain text message (its web links) and return a verdict.

    Link analysis is fully deterministic — every finding carries hand-written
    English and a Khmer translation — so this path does not go through the
    LLM at all. That keeps it reliable regardless of model availability, and
    still routes through the same evidence -> verdict -> reply pipeline as the
    file path.

    Args:
        message_text: the message the user forwarded.
        user_id: Telegram user id, hashed before logging.
        label: ground-truth verdict, set only when running the evaluation set.
        source: log tag for where this run came from; "telegram_text" for live
            traffic, overridden by the evaluation harness.
    """
    evidence.start_run()
    started = time.monotonic()

    analysis = _analyze_links(message_text)
    evidence.record("inspect_links", analysis.findings)

    result = grounded_verdict()
    duration_ms = int((time.monotonic() - started) * 1000)

    audit.log_check(
        filename="(text message)",
        result=result,
        tools_called=evidence.tool_calls(),
        duration_ms=duration_ms,
        user_id=user_id,
        source=source,
        label=label,
    )

    log.info("text verdict=%s links=%d codes=%s (%dms)",
             result.verdict, analysis.urls_checked,
             result.evidence_codes, duration_ms)
    return result
 
 
if __name__ == "__main__":
    # NOTE: file_url is fetched over HTTP, so a local path will not work here.
    # To test against local fixtures, serve them first:
    #     python -m http.server 8000
    # then pass  http://localhost:8000/fixtures/statement.pdf
    import sys
 
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
 
    name = sys.argv[1] if len(sys.argv) > 1 else "ABA_Mobile_Update.apk"
    text = sys.argv[2] if len(sys.argv) > 2 else "Update your ABA app now."
    url = sys.argv[3] if len(sys.argv) > 3 else ""
 
    outcome = inspect_file(name, text, url)
    print()
    print("verdict   :", outcome.verdict)
    print("reason    :", outcome.reason)
    print("next step :", outcome.next_step)
    print("evidence  :", outcome.evidence_codes)
    print("fabricated:", outcome.fabricated_codes)
 