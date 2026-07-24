"""Run the labelled evaluation set through the checker and log the results.

Two modes:

  --no-agent   Deterministic only. Calls the analysers directly (link parsing,
               filename rules, magic-byte type check, APK manifest parsing).
               NO LLM, and NOTHING is fetched over the network — no URL is ever
               opened, no model is ever called. This is the mode used to
               measure the deterministic core, and it runs fully offline.

  (default)    Agent mode. Routes text samples through inspect_text (still
               deterministic — link analysis has no LLM step) and file samples
               through inspect_file, which runs the CrewAI agent. File contents
               are served from a LOCAL http.server on 127.0.0.1 so the agent can
               download fixtures; no external host is contacted for the files.
               The agent's own LLM calls do go to Gemini, so this mode needs a
               network and an API key.

Every run appends to logs/checks.jsonl with the sample's ground-truth `label`,
so analyze_logs.py can compute accuracy, precision/recall, and the
dangerous-missed count afterwards.

Usage:
    python evaluate.py --no-agent           # offline, deterministic core
    python evaluate.py                       # agent mode (needs network + key)
    python evaluate.py --no-agent --kind text
    python evaluate.py --limit 5 --delay 3
    python evaluate.py --restart             # ignore saved progress, start over
"""
import argparse
import functools
import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
import time
from pathlib import Path

import yaml

import audit
import evidence
from verdict import grounded_verdict

ROOT = Path(__file__).parent
EVAL_PATH = ROOT / "data" / "eval_set.yaml"
PROGRESS_PATH = ROOT / "logs" / "eval_progress.json"

VERDICTS = ("SAFE", "SUSPICIOUS", "DANGEROUS")

# Benign content used to synthesise a stand-in file for filename-only samples
# in agent mode, so a legitimate-looking name is not spuriously flagged by the
# magic-byte check. Executables and archives are left empty — their filename
# rule is already conclusive, so their contents never change the verdict.
_STAGE_BYTES: dict[str, bytes] = {
    ".png":  b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    ".jpg":  b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01",
    ".jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01",
    ".mp4":  b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00",
    ".pdf":  b"%PDF-1.4\n%%EOF\n",
    ".txt":  b"hello world\n",
}


# ---------------------------------------------------------------- loading

def load_samples() -> list[dict]:
    data = yaml.safe_load(EVAL_PATH.read_text(encoding="utf-8"))
    return data["samples"]


def load_progress(restart: bool) -> set[str]:
    if restart or not PROGRESS_PATH.exists():
        return set()
    try:
        return set(json.loads(PROGRESS_PATH.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError):
        return set()


def save_progress(done: set[str]) -> None:
    try:
        PROGRESS_PATH.parent.mkdir(exist_ok=True)
        PROGRESS_PATH.write_text(json.dumps(sorted(done)), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------- no-agent core

def _log(filename: str, result, source: str, label: str, t0: float) -> None:
    audit.log_check(
        filename=filename,
        result=result,
        tools_called=evidence.tool_calls(),
        duration_ms=int((time.monotonic() - t0) * 1000),
        source=source,
        label=label,
    )


def eval_text_noagent(text: str, label: str):
    """Deterministic link analysis only — no LLM, no network."""
    from links import analyze_text
    evidence.start_run()
    t0 = time.monotonic()
    analysis = analyze_text(text)
    evidence.record("inspect_links", analysis.findings)
    result = grounded_verdict()
    _log("(text message)", result, "eval_text_noagent", label, t0)
    return result


def eval_file_noagent(sample: dict, label: str):
    """Deterministic file analysis: filename rules, then (if a real file is
    available on disk) the magic-byte type check and APK manifest parse. No
    network — a file is only ever read from a local fixture path."""
    from rules import check_filename, BUNDLE_EXT
    from magic import verify_file_type
    from apk import analyze_apk

    filename = sample["filename"]
    caption = sample.get("caption", "")
    rel = sample.get("path")

    evidence.start_run()
    t0 = time.monotonic()

    res = check_filename(filename, caption)
    evidence.record("check_filename_rules", res.findings)

    # Content inspection only runs when the sample points at a real fixture.
    # Filename-only samples never touch the disk or the network.
    disk = (ROOT / rel) if rel else None
    if disk and disk.exists():
        tr = verify_file_type(str(disk), filename)
        evidence.record("verify_file_type", tr.findings)

        ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        looks_android = (
            tr.real_type in ("android_apk", "android_bundle")
            or ext == ".apk" or ext in BUNDLE_EXT
        )
        if looks_android:
            apk = analyze_apk(str(disk))
            evidence.record("inspect_apk", apk.findings)

    result = grounded_verdict()
    _log(filename, result, "eval_file_noagent", label, t0)
    return result


# ---------------------------------------------------------------- agent mode

class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):   # silence per-request stderr spam
        pass


def start_file_server(directory: str) -> tuple[socketserver.TCPServer, str]:
    """Serve `directory` on a free localhost port. Returns (server, base_url)."""
    # The download tool only fetches from Telegram by default (SSRF guard).
    # This harness serves fixtures from loopback, so it opts into the local
    # exception. Only agent mode starts this server, so the deterministic path
    # never sets the flag.
    os.environ["SCANCHECK_ALLOW_LOCAL_DOWNLOADS"] = "1"
    handler = functools.partial(_QuietHandler, directory=directory)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}"


def stage_file(sample: dict, staging: Path) -> str:
    """Put a servable copy of the sample's file into `staging`.

    Real fixtures are copied verbatim. Filename-only samples get a stand-in
    whose bytes match the claimed extension when benign, else an empty file.
    Returns the staged basename to append to the server's base URL.
    """
    filename = sample["filename"]
    rel = sample.get("path")
    served = f"{sample['id']}__{filename}"
    dest = staging / served
    if rel and (ROOT / rel).exists():
        shutil.copyfile(ROOT / rel, dest)
    else:
        ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        dest.write_bytes(_STAGE_BYTES.get(ext, b""))
    return served


def _is_rate_limit(exc: Exception) -> bool:
    blob = f"{type(exc).__name__} {exc}".lower()
    return any(s in blob for s in ("429", "resource_exhausted", "rate limit",
                                   "ratelimit", "quota"))


def eval_text_agent(text: str, label: str):
    from agent import inspect_text
    return inspect_text(text, label=label, source="eval_text_agent")


def eval_file_agent(sample: dict, label: str, base_url: str, staging: Path):
    from agent import inspect_file
    served = stage_file(sample, staging)
    url = f"{base_url}/{served}"
    return inspect_file(
        sample["filename"], sample.get("caption", ""), url,
        label=label, source="eval_file_agent",
    )


# ---------------------------------------------------------------- driver

def run_sample(sample, no_agent, base_url, staging):
    """Dispatch one sample. Rate-limit errors get one retry after a pause;
    any other error is reported and swallowed so the run never aborts."""
    kind, label = sample["kind"], sample["label"]

    if no_agent:
        _call = (lambda: eval_text_noagent(sample["text"], label)) if kind == "text" \
            else (lambda: eval_file_noagent(sample, label))
    else:
        _call = (lambda: eval_text_agent(sample["text"], label)) if kind == "text" \
            else (lambda: eval_file_agent(sample, label, base_url, staging))

    try:
        return _call()
    except Exception as exc:
        if _is_rate_limit(exc):
            print("    rate limited — waiting 60s then retrying once...")
            time.sleep(60)
            try:
                return _call()
            except Exception as exc2:
                print(f"    ERROR after retry: {type(exc2).__name__}: {exc2}")
                return None
        print(f"    ERROR: {type(exc).__name__}: {exc}")
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the labelled evaluation set.")
    ap.add_argument("--no-agent", action="store_true",
                    help="Deterministic only; no LLM and no network.")
    ap.add_argument("--kind", choices=["text", "file"],
                    help="Only run samples of this kind.")
    ap.add_argument("--limit", type=int,
                    help="Run at most this many (pending) samples.")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="Seconds to sleep between samples (agent rate limits).")
    ap.add_argument("--restart", action="store_true",
                    help="Ignore saved progress and start from the beginning.")
    args = ap.parse_args()

    samples = load_samples()
    if args.kind:
        samples = [s for s in samples if s["kind"] == args.kind]

    done = load_progress(args.restart)
    pending = [s for s in samples if s["id"] not in done]
    if args.limit is not None:
        pending = pending[:args.limit]

    if not pending:
        print("Nothing to do — all selected samples are already done.")
        print("(Use --restart to run them again.)")
        return

    mode = "no-agent (offline, deterministic)" if args.no_agent else "agent (LLM)"
    print(f"Evaluating {len(pending)} sample(s) in {mode} mode.\n")

    # Agent mode needs a local file server + a staging dir for file samples.
    httpd = base_url = staging = tmpdir = None
    if not args.no_agent and any(s["kind"] == "file" for s in pending):
        tmpdir = tempfile.mkdtemp(prefix="eval_stage_")
        staging = Path(tmpdir)
        httpd, base_url = start_file_server(tmpdir)
        print(f"Serving file fixtures from {base_url}\n")

    results = []   # (sample, predicted_verdict)
    try:
        for i, sample in enumerate(pending, 1):
            print(f"[{i}/{len(pending)}] {sample['id']} "
                  f"(true={sample['label']})")
            result = run_sample(sample, args.no_agent, base_url, staging)
            pred = result.verdict if result else "ERROR"
            mark = "ok " if pred == sample["label"] else "MISS"
            lim = "  [known limitation]" if sample.get("limitation") else ""
            print(f"    -> {pred:<11} [{mark}]{lim}")

            results.append((sample, pred))
            done.add(sample["id"])
            save_progress(done)

            if args.delay and i < len(pending):
                time.sleep(args.delay)
    finally:
        if httpd:
            httpd.shutdown()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    _summary(results)
    print("\nLogged to logs/checks.jsonl. Run  python analyze_logs.py  for the "
          "full report.")


def _summary(results: list[tuple[dict, str]]) -> None:
    print("\n" + "=" * 52)
    print("RUN SUMMARY (this run only; see analyze_logs.py for all-time)")
    print("=" * 52)
    scored = [(s, p) for s, p in results if p != "ERROR"]
    errors = len(results) - len(scored)
    if not scored:
        print(f"No scored samples. Errors: {errors}")
        return

    correct = sum(1 for s, p in scored if p == s["label"])
    print(f"accuracy: {correct}/{len(scored)} ({correct / len(scored):.0%})")
    if errors:
        print(f"errors (not scored): {errors}")

    # The one error that matters most: a real danger called SAFE.
    missed = [s for s, p in scored if s["label"] == "DANGEROUS" and p == "SAFE"]
    real_missed = [s for s in missed if not s.get("limitation")]
    lim_missed = [s for s in missed if s.get("limitation")]
    print(f"\ndangerous rated SAFE: {len(missed)}")
    for s in real_missed:
        print(f"  !! UNEXPECTED: {s['id']}")
    for s in lim_missed:
        print(f"  (known limitation) {s['id']}")

    print("\nmismatches:")
    any_mm = False
    for s, p in scored:
        if p != s["label"]:
            any_mm = True
            tag = " [known limitation]" if s.get("limitation") else ""
            print(f"  {s['id']:<28} true={s['label']:<11} pred={p}{tag}")
    if not any_mm:
        print("  (none)")


if __name__ == "__main__":
    main()
