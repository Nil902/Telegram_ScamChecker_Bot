# ScamCheck — Architecture & QA Guide

A presentation / question-and-answer companion. It explains **what the system
does, how a check flows through it, what every file is for, and what every
function does** — in plain language.

---

## 1. The one idea to remember

> **Deterministic Python finds the problems. The AI only explains them.**

The AI (Gemini, via CrewAI) is **never** allowed to decide whether something is
a scam. Real code — parsing a URL, a filename, a file's bytes, an APK manifest —
produces every *finding*. The verdict is then a simple function of those
findings. If the AI ever claims a reason no tool found, that claim is thrown
away.

**Why this matters (likely QA question):** LLMs hallucinate. For a safety tool
that would mean inventing dangers (false alarms that make people ignore it) or
missing real ones. By making findings deterministic and the verdict a pure
function of them, the answer is **reproducible, auditable, and testable** — and
the AI's only job is wording, where a mistake is harmless.

---

## 2. The three verdicts

| Verdict | Meaning | Triggered by |
|---------|---------|--------------|
| 🟢 **SAFE** | Nothing suspicious found | no findings |
| 🟡 **SUSPICIOUS** | Be careful | highest finding is HIGH or MEDIUM |
| 🔴 **DANGEROUS** | Do not open | any CRITICAL finding |

Severity is **never averaged** — one CRITICAL among mild findings is still
DANGEROUS. (`evidence.py: derive_verdict`)

---

## 3. The pipeline (how one message is checked)

```
        Telegram user sends a file OR a message with a link
                              │
        ┌─────────────────────┴──────────────────────┐
        │ FILE                                        │ TEXT / LINK
        ▼                                             ▼
  agent.inspect_file()                        agent.inspect_text()
  (CrewAI agent + Gemini)                     (100% deterministic, no AI)
        │                                             │
  rules.check_filename() runs FIRST,          links.analyze_text()
  unconditionally, before the agent —           parses each URL, no fetch
  never gated on the AI's routing                    │
        │                                             │
  AI then chooses further tools:                     │
   1 check_filename_rules  (name only)               │
   2 download_file         (only if needed)          │
   3 verify_file_type      (magic bytes)             │
   4 inspect_apk           (manifest)                │
   5 scan_with_virustotal  (hash lookup)             │
        │                                             │
  evidence.note_coverage()                           │
  → UNKNOWN_FILE_TYPE (LOW) if nothing fired         │
    and no rule understood the type                  │
        │                                             │
  triage.triage()  ← ONLY if UNKNOWN_FILE_TYPE fired │
  adds LLM_SUGGESTED_* findings, capped MEDIUM       │
        │                                             │
        └───────────────► evidence registry ◄────────┘
                       (code → Finding, per run)
                              │
                    evidence.derive_verdict()   ← severity only, no AI
                              │
                    verdict.finalise / grounded_verdict
                    (discard any AI-invented codes; AI reason kept
                     only if it agrees with the evidence)
                              │
                    formatter.format_reply()
                    Khmer + English card + "what they'll do next"
                              │
                    audit.log_check()  →  logs/checks.jsonl
```

**Key safety property:** if any tool crashes, or the AI returns nothing, the
system **fails closed** — it records an `ANALYSIS_FAILED` finding (HIGH) so a
broken check can never come out SAFE. **Nothing is ever executed, and no
suspicious link is ever opened** — every signal comes from *parsing*.

**Corollary, learned the hard way:** *declining to look* is not the same as
*looking and finding nothing*, and the AI must not be able to decide which of
those happened. Filename rules used to run only when the model chose to call
them; when it skipped the call, zero findings were recorded and zero findings
derived to SAFE. An `.msi` was reported SAFE that way despite `.msi` having
been a CRITICAL extension the whole time. Two changes close that class of bug:
filename rules now run unconditionally, and `note_coverage()` makes an
unexamined file say so out loud.

---

## 4. What each file does (and its functions)

### Front-end

**`bot.py`** — the Telegram bot. Receives messages, calls the analysers, sends
back the reply.
- `main()` — start the bot; register the `/start`, `/help`, document, and text
  handlers plus the global error handler; begin polling Telegram.
- `start()` / `help_command()` — both reply with the same full message
  (greeting + victim-support guidance), built by `_full_message()` so the two
  commands can never drift apart. Every handler drops updates with no
  `.message` (edited messages, channel posts) before touching it.
- `handle_document()` — a file arrived: guard the 20 MB limit, get its Telegram
  URL, run `inspect_file` off the event loop, send the formatted reply.
- `handle_text()` — a message arrived: if it has no link, reply with the
  bilingual `NO_LINK_REPLY` guidance; otherwise run `inspect_text` and reply.
- `on_error()` — last-resort handler for anything a handler did not catch
  itself (a failing reply/edit, a library error). Logs the exception and
  best-effort tells the user "something went wrong", guarded so a failing
  notice cannot mask the original error.
- `_full_message()` — the greeting (`START_INTRO`) followed by the recovery
  help, shared by `/start` and `/help`.
- `_help_message()` — build the bilingual recovery text (reassure → call bank →
  keep evidence → report → no false promise).
- `_hotline_lines()` — build the "• Bank: number" lines from the reference file
  (skips banks with no hotline).

### Orchestration

**`agent.py`** — the two entry points that run one full analysis.
- `inspect_file(...)` — the **AI path**. Builds a CrewAI task, lets the agent
  pick tools, reconciles its answer with the evidence, logs, returns a verdict.
- `inspect_text(...)` — the **deterministic path**. Runs link analysis, derives
  a verdict, logs, returns. No AI at all.

**`tools.py`** — thin wrappers that expose the detectors to the CrewAI agent.
Each records its findings into the evidence registry and **fails closed** on
error.
- `check_filename_rules()` — tool: run filename rules (instant, no download).
- `download_file()` — tool: stream the file to a temp path (only when needed).
- `verify_file_type_tool()` — tool: read the bytes to find the true type.
- `inspect_apk()` — tool: parse an APK/bundle manifest.
- `inspect_links()` — tool: analyse links in the text/caption.
- `cleanup_downloads()` — delete every temp file fetched this run.
- `_record_failure()` — on a tool crash, record `ANALYSIS_FAILED` (HIGH) so the
  result can't be SAFE.
- `_paths()` — the thread's list of downloaded temp files.

### Detectors (all deterministic, parsing only)

**`links.py`** — static link/text analysis. **Never opens a URL.**
- `extract_urls()` — pull candidate links out of free text (http, www, and bare
  domains ending in a known TLD).
- `analyze_url()` — score one URL: `@`-obfuscation, IP host, punycode, brand
  impersonation, shortener, suspicious TLD.
- `analyze_text()` — score every URL in a message, plus the "reward lure"
  pattern (a link + 2 prize/job phrases).
- `_host()` — extract hostname + any userinfo from a URL.
- `_is_ip()` — is the host a raw IP address?
- `_is_official()` — does the host belong to a real bank/platform (never flag)?
- `_lure_hits()` — which prize/job lure phrases appear in the text.
- `class LinkAnalysis` — result: findings + count of URLs checked.

**`rules.py`** — filename rules (name only, no contents).
- `check_filename()` — apply every rule: hidden RTL-override character, double
  extension (`invoice.pdf.exe`), executable extension, shortcut, system
  modifier, disk image, macro-enabled Office doc, password-locked archive with
  the password in the message.
- `_extensions()` — list a filename's extensions in order.
- Extension tiers, each with its own finding code and severity:

  | Set | Code | Severity | Contents |
  |-----|------|----------|----------|
  | `EXECUTABLE_EXT` | `FILENAME_EXECUTABLE` | CRITICAL | `.apk .exe .scr .com .pif .bat .cmd .vbs .vbe .js .jse .wsf .hta .ps1 .jar .msi .msix .msp .cpl .gadget` |
  | `SHORTCUT_EXT` | `FILENAME_SHORTCUT` | CRITICAL | `.lnk .scf` |
  | `SYSTEM_MODIFIER_EXT` | `FILENAME_SYSTEM_MODIFIER` | HIGH | `.reg .dll` |
  | `DISK_IMAGE_EXT` | `FILENAME_DISK_IMAGE` | MEDIUM | `.iso .img` |

  `.msi`/`.msp`/`.msix` sit at CRITICAL with `.exe`, not in a milder tier: a
  Windows Installer package runs arbitrary custom actions with elevated
  rights at install time. `.dll` is HIGH because it needs a loader — it is a
  component of an attack, not the whole of one. `.iso`/`.img` are MEDIUM:
  inert themselves, but files opened from a mounted image skip the
  "downloaded from the internet" warning.

**`virustotal.py`** — SHA-256 lookup against VirusTotal. **Hash-first.**
- `check_file()` — look the digest computed during download up via
  `GET /files/{hash}`; map the engine detection count to a severity.
- `extract_metadata`-free by design: only a hash leaves the process unless
  `VIRUSTOTAL_ALLOW_UPLOAD` is explicitly enabled (default off — uploading
  would send a user's private file to a third party).
- Thresholds: 0 detections → no finding; 1–3 → `VT_SUSPECTED_MALWARE`
  (MEDIUM); 4+ → `VT_KNOWN_MALWARE` (CRITICAL). Engines are not independent
  and several are noisy on packed-but-legitimate installers, so a one- or
  two-engine hit is not treated as proof.
- Fails closed: a missing API key, timeout, rate limit, bad key, unknown hash
  or HTTP error all record `VT_SCAN_UNAVAILABLE` (LOW). There is no code path
  that returns silently, because silence becomes SAFE downstream.
- `class VirusTotalResult` — findings + detection stats + skip reason.

**`magic.py`** — magic-byte type check (catches disguised files).
- `detect_type()` — identify a file family from its first bytes.
- `refine_zip_container()` — a ZIP could be an APK, an Office doc, or a plain
  archive; look at the entry names to tell which.
- `verify_file_type()` — compare real type vs claimed extension; flag a program
  wearing a document/image name, or an APK hidden under a `.jpg`/`.pdf`.
- `class TypeCheckResult` — result: claimed ext, real type, mismatch, findings.

**`apk.py`** — static AndroidManifest analysis. **Never runs the app.**
- `parse_apk()` — read the manifest (package, label, permissions, SDK).
- `extract_base_apk()` — pull just `base.apk` out of an app bundle, with a
  zip-bomb size cap.
- `score_apk()` — interpret the facts: the OTP-theft permission combo, overlay
  attacks, dangerous permissions, bank-package impersonation / typosquats, and
  genuine remote-access tools (AnyDesk/TeamViewer) used in phone scams.
- `analyze_apk()` — convenience: parse then score.
- `_levenshtein()` — edit distance, used for typosquat detection.
- `class ApkFacts` / `class ApkAnalysis` — raw manifest facts / scored result.

### Verdict engine

**`evidence.py`** — the per-run finding registry (thread-local, so two users
can be checked at once without mixing).
- `start_run()` — reset the registry at the start of an analysis.
- `record()` — a tool adds its findings (deduplicated by code).
- `all_findings()` — the findings so far (code → Finding).
- `tool_calls()` — which tools ran, in order.
- `derive_verdict()` — the verdict from severity alone. **This is the rule.**
- `_ensure()` — lazily initialise a fresh thread's registry.
- `note_coverage()` — the "we checked" vs "we couldn't check" distinction.
  Call once at the END of an analysis. Records a LOW `UNKNOWN_FILE_TYPE` when
  nothing fired **and** no extension rule, magic-byte signature or APK check
  understood the file. Returns immediately if any substantive finding exists,
  so it can never outrank or mask a real warning.
- `is_covered()` — does any deterministic check understand this file type?
- `has_substantive_finding()` — is anything recorded beyond a
  we-could-not-check note?
- `UNVERIFIED_CODES` — `{UNKNOWN_FILE_TYPE, VT_SCAN_UNAVAILABLE}`. Findings
  that describe a gap in *our checking* rather than a property of the file.
  A reply whose entire content is one of these is labelled "not fully
  checked" instead of green.

**`triage.py`** — the single place a model may add a finding. Runs **only**
when `UNKNOWN_FILE_TYPE` would otherwise fire.
- `extract_metadata()` — bounded, sanitised summary of a file: extension,
  hex-encoded header, size, printable strings (capped in count and length,
  control characters stripped). Raw bytes never leave this function.
- `build_prompt()` — fences the extracted content in an explicit
  UNTRUSTED block and instructs the model to treat it as data, never
  instructions.
- `triage()` — asks the model which of `ALLOWED_CODES` the metadata supports.
  Severity and wording come from local tables; the model's only influence is
  which codes appear, and codes outside the menu are dropped.
- `ALLOWED_CODES` — the fixed menu, every entry `LLM_SUGGESTED_*` and every
  entry MEDIUM. This is the cap that stops this path ever reaching DANGEROUS.
- On any error, returns `[]` — `UNKNOWN_FILE_TYPE` is already recorded, so
  failure leaves the honest "not fully checked" answer rather than a green one.

**`verdict.py`** — reconcile the AI's answer with the real evidence.
- `finalise()` — parse the AI's JSON, discard any **fabricated** evidence codes,
  re-derive the verdict from evidence (evidence always wins), keep the AI's
  wording only if it agrees.
- `grounded_verdict()` — build a verdict purely from evidence, no AI (used by
  the text path and as a fallback).
- `_extract_json()` — pull JSON out of the model's reply (handles code fences).
- `_fallback_reason()` / `_fallback_step()` — plain wording taken from the
  findings themselves, so the bot answers even if the AI fails completely.
- `class FinalVerdict` — the final result object the bot renders.

**`models.py`** — shared data types.
- `class Severity` — LOW / MEDIUM / HIGH / CRITICAL.
- `class Finding` — one concrete, explainable fact (code, severity, plain
  English, `params` for the Khmer template).
- `class FileCheckResult` — findings + `conclusive` + `needs_inspection`.

### Output

**`formatter.py`** — build the bilingual reply card.
- `format_reply()` — assemble label + Khmer reason + "what they'll do next" +
  next step + English section.
- `_top_finding()` — the single highest-severity finding the card speaks about.
- `_khmer_reason()` — the Khmer explanation for that finding (English fallback
  if untranslated).
- `_next_move_block()` — the "what the scammer will do next" prediction, only
  for finding codes we have a curated prediction for.

**`strings_km.py`** — every user-facing **Khmer** string, written by hand and
keyed by finding code (the AI never writes Khmer). Holds `VERDICT_LABEL`,
`NEXT_STEP`, `FINDING_KM`, and the `NEXT_MOVE_KM` / `NEXT_MOVE_EN` predictions.
No functions — pure data.

### Support

**`audit.py`** — privacy-preserving logging.
- `log_check()` — append one JSON line to `logs/checks.jsonl` (verdict, codes,
  tools, timing, ground-truth label). Never raises — logging must not break the
  bot.
- `_hash()` — one-way hash of filename / user id (no raw content stored).
- `_extension()` — the file extension, for statistics.

**`download.py`** — safe file fetching.
- `download_to_temp()` — stream a file to a temp path with a **hard 20 MB cap**
  checked mid-transfer, chmod 0600 (never executable), caller deletes it.
- `cleanup()` — delete a temp file (safe to call twice).
- `class DownloadTooLarge` — raised when the cap is exceeded.

### Evaluation & review (not part of the live bot)

**`evaluate.py`** — run the labelled test set and log results.
- `main()` — parse flags, run pending samples, print a summary.
- `load_samples()` / `load_progress()` / `save_progress()` — load the eval set;
  make runs resumable.
- `eval_text_noagent()` / `eval_file_noagent()` — the **offline** deterministic
  paths (no AI, no network).
- `eval_text_agent()` / `eval_file_agent()` — the AI paths (agent mode).
- `start_file_server()` / `stage_file()` — serve fixtures from a **local**
  server so the agent can download them (no external host).
- `run_sample()` — dispatch one sample; retry once on a rate-limit; never let
  one failure abort the run.
- `_is_rate_limit()` — detect a 429 / quota error.
- `_log()` — write one eval result to the audit log with its label.
- `_summary()` — per-run accuracy, the dangerous-missed count, and mismatches.
- `class _QuietHandler` — a silent HTTP handler for the local file server.

**`analyze_logs.py`** — turn the log into a report.
- `main()` — print verdict distribution, the grounding layer (fabrications /
  disagreements), tool-routing efficiency, latency, and — for labelled rows —
  accuracy, confusion matrix, precision/recall/F1, the **DANGEROUS-rated-SAFE**
  count, accuracy by source, and every mismatch with its evidence codes.
- `load()` — read `logs/checks.jsonl`, tolerating a truncated last line.

**`review_khmer.py`** — print every Khmer string with its English source for a
native speaker to check, and flag any finding code missing a translation.

**`data/cambodian_apps.yaml`** — reference data: real bank package names,
official domains, brand keywords, and (UNVERIFIED) hotlines.

**`data/eval_set.yaml`** — 44 labelled samples used by `evaluate.py`.

**`fixtures/`** — real sample files (benign photos/PDFs and disguised files).

**`test/`** — unit and integration tests (73 total).

---

## 5. Likely QA questions — quick answers

**Q: How do you stop the AI from making up scams?**
Findings come only from deterministic code. The verdict is derived from those
findings. Any evidence code the AI returns that no tool produced is discarded as
a fabrication, and the log counts how often that happens. (`verdict.finalise`)

**Q: What if the AI or a tool crashes?**
Fail-closed: a HIGH `ANALYSIS_FAILED` finding is recorded, so the result becomes
SUSPICIOUS, never SAFE. (`tools._record_failure`, `agent.inspect_file`)

**Q: Do you ever open the suspicious link or run the file?**
No. Links are only *parsed* as text. Files are only read (magic bytes, APK
manifest) — never executed. Downloads have a 20 MB cap and are chmod 0600.

**Q: Why Khmer written by hand instead of translated by the AI?**
Safety-critical text must be correct and consistent. Hand-written Khmer keyed by
finding code guarantees that, costs no API calls, and adds no latency. Coverage
is checked automatically. (`strings_km.py`, `review_khmer.py`)

**Q: How accurate is it?**
On the 44-sample offline set: **43/44 (97.7%)**, **0 false positives**, **0
dangerous-rated-SAFE**. The one miss is a deliberately included limitation: a
pure-text OTP script with no link for the parser to see.

**Q: What can't it catch?**
Pure conversational social engineering and text lies with no link or file —
there is nothing to parse. This is stated honestly and measured, not hidden.

**Q: Why two verdict paths (AI for files, deterministic for links)?**
Link analysis needs no AI — parsing a URL is exact. Files benefit from the AI
deciding *which* cheap checks to run (e.g. skip the download when the name is
already conclusive), which saves time and bandwidth.

---

## 6. How to run it (for a live demo)

```bash
python -m pytest test/ -q          # 73 tests pass
python evaluate.py --no-agent      # offline accuracy run (no key, no network)
python analyze_logs.py             # the metrics report
python review_khmer.py             # every Khmer string + coverage check
python bot.py                      # the live bot (needs .env with tokens)
```
