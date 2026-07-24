# ScamCheck — a Telegram scam-checker for Cambodia

A Telegram bot that lets an ordinary person forward a **file** or a **message
with a link** and get a plain-language, Khmer-first answer: is this safe,
suspicious, or dangerous — and *why*.

It is built for the scams that actually target people in Cambodia: fake bank
`.apk` installers sent over Telegram, files disguised as photos or PDFs,
remote-access apps used in phone scams, brand-impersonation links, and
"claim your prize / part-time job" lures.

---

## The core design principle

> **The LLM never decides anything. It only explains.**

Every *finding* — every concrete reason a file or link might be a scam — is
produced by **deterministic Python** (`links.py`, `rules.py`, `magic.py`,
`apk.py`). Each finding carries a severity and a hand-written explanation.

The **verdict is a pure function of those findings** (`evidence.py`):

| Highest severity present | Verdict |
|--------------------------|-----------|
| CRITICAL                 | 🔴 DANGEROUS |
| HIGH or MEDIUM           | 🟡 SUSPICIOUS |
| nothing                  | 🟢 SAFE |

The language model (Gemini, via CrewAI) is used only on the **file path**, to
decide *which cheap checks to run* and to phrase the reason in simple words. It
is structurally prevented from inventing a verdict or a reason that no tool
supports: any evidence code it returns that no tool actually emitted is
discarded as a *fabrication* (`verdict.py`), and the verdict is always
re-derived from the real evidence. If the model fails or returns garbage, the
bot **fails closed** — a crashed check records a HIGH finding so a broken
analyser can never hand out a green light.

The **link/text path is fully deterministic** — no LLM at all — so it stays
reliable regardless of model availability.

Nothing is ever executed and **no suspicious URL is ever fetched**. Every
signal is derived by *parsing* — the URL string, the filename, the file's magic
bytes, the APK manifest.

---

## How a check flows

```
Telegram message
      │
      ├── has a file?  ── inspect_file() ── CrewAI agent ──┐
      │                     (LLM picks tools)              │
      │                   check_filename → download →      │
      │                   verify_file_type → inspect_apk   │
      │                                                    ▼
      └── has a link?  ── inspect_text() ── analyze_text ──┤
                            (deterministic)                │
                                                           ▼
                                              evidence registry
                                              (code → Finding)
                                                           │
                                              derive_verdict()  ← severity only
                                                           │
                                              grounded reply (Khmer + English,
                                              + "what they'll do next")
                                                           │
                                              audit log → logs/checks.jsonl
```

---

## Module map

| File | Responsibility |
|------|----------------|
| `bot.py` | Telegram front-end: `/start`, `/help`, file & text handlers |
| `agent.py` | `inspect_file` (LLM agent) and `inspect_text` (deterministic) |
| `tools.py` | CrewAI tool wrappers; each records findings, fails closed on error |
| `links.py` | Static link/text analysis → `LINK_*` findings (parsing only) |
| `rules.py` | Filename rules → `FILENAME_*`, `ARCHIVE_*` findings |
| `magic.py` | Magic-byte type check → `TYPE_*` findings (disguised files) |
| `apk.py` | Static AndroidManifest parsing → `APK_*` findings |
| `evidence.py` | Thread-local finding registry + severity→verdict derivation |
| `verdict.py` | Reconciles model output with evidence; grounded fallback |
| `models.py` | `Finding`, `Severity`, result dataclasses |
| `formatter.py` | Bilingual reply card + "what they will do next" section |
| `strings_km.py` | Hand-written Khmer strings, keyed by finding code |
| `audit.py` | Privacy-preserving JSONL logging (`logs/checks.jsonl`) |
| `download.py` | Streaming download with a hard 20 MB cap |
| `data/cambodian_apps.yaml` | Reference: real bank packages, domains, hotlines |
| `evaluate.py` | Run the labelled evaluation set (offline or agent mode) |
| `analyze_logs.py` | Accuracy / precision-recall-F1 / grounding report |
| `review_khmer.py` | Dump every Khmer string for native-speaker review |
| `data/eval_set.yaml` | 44 labelled samples (ground truth) |
| `test/` | Unit + integration tests |
| `fixtures/` | Sample benign and disguised files |

---

## Setup

Requires **Python 3.12** (crewai does not support 3.14).

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
TELEGRAM_BOT_TOKEN=your-bot-token-from-@BotFather
GEMINI_API_KEY=your-gemini-api-key
```

- `TELEGRAM_BOT_TOKEN` — needed to run the bot.
- `GEMINI_API_KEY` — needed only for the file-inspection (agent) path and for
  `evaluate.py` in agent mode. The link/text path and `evaluate.py --no-agent`
  need neither a key nor a network.

---

## Running the bot

```bash
python bot.py
```

Then message the bot on Telegram:

- **Forward a file** → it checks the name, and downloads/inspects contents only
  if needed.
- **Send a message with a link** → it checks the link (never opens it).
- **`/help`** → calm, bilingual guidance for someone who has *already* been
  scammed (call your bank now, keep evidence, report to police / Anti-Cyber
  Crime Department). It never promises the money can be recovered.

> ⚠️ **Before deployment:** the hotline numbers in `data/cambodian_apps.yaml`
> and the reporting channel in `/help` are **placeholders marked UNVERIFIED**.
> Confirm every number against the bank's official source first — a wrong
> emergency number is worse than none.

---

## Evaluating the system

The evaluation set (`data/eval_set.yaml`) has 44 samples whose labels are
honest human ground truth, not a copy of the tool's output.

**Offline, deterministic core (no LLM, no network):**

```bash
python evaluate.py --no-agent          # runs the deterministic detectors
python analyze_logs.py                 # prints the full report
```

**Agent mode (exercises the LLM; needs a key + network):**

```bash
python evaluate.py                     # serves fixtures on 127.0.0.1 locally
python evaluate.py --kind file --delay 3   # slower, to respect rate limits
```

Useful flags: `--kind text|file`, `--limit N`, `--delay SECONDS`, `--restart`
(ignore saved progress). Runs are resumable via `logs/eval_progress.json`, and
rate-limit errors get one automatic retry.

### Latest deterministic results (`--no-agent`)

```
accuracy: 43/44 (97.7%)
false positives:          0/16
DANGEROUS rated SAFE:     0/20        ← the worst error class; none
per-class F1:  SAFE 0.97 · SUSPICIOUS 0.93 · DANGEROUS 1.00
```

The single mismatch is a **deliberate known limitation**: a pure-text OTP
phishing script with no link and no lure phrase. The link analyser has nothing
to parse, so it returns SAFE. It is labelled `limitation: true` and reported
separately rather than hidden — false *negatives* of this kind are the honest
boundary of a parse-only design.

`analyze_logs.py` reports: verdict distribution, the grounding layer
(fabricated codes discarded, model/evidence disagreements), agent tool-routing
efficiency, latency, a confusion matrix, per-class precision/recall/F1, a
prominent **DANGEROUS-rated-SAFE** count, accuracy by source, and every
mismatch with the evidence codes that drove it.

---

## What it detects

**Links / text** (`LINK_*`): brand impersonation of Cambodian banks and global
platforms, `@`-obfuscation, IP-address hosts, punycode lookalikes, link
shorteners, high-risk TLDs, and prize/job "reward lure" patterns.

**Filenames** (`FILENAME_*`, `ARCHIVE_*`): executables (`.apk`, `.exe`, `.scr`,
`.js`, …), double extensions (`invoice.pdf.exe`), right-to-left override
disguises, macro-enabled Office docs, and password-locked archives with the
password in the message.

**File contents** (`TYPE_*`): a program disguised as a document/image, or an
APK disguised under a `.jpg`/`.pdf` name (magic-byte mismatch).

**Android apps** (`APK_*`): the OTP-theft permission combination (screen
control + SMS/screen capture), overlay-attack signature, dangerous individual
permissions, bank-package impersonation and typosquats, and genuine
remote-access tools (AnyDesk/TeamViewer) used in live phone scams.

**Known limitations:** pure-text lies with no link, and social-engineering
that lives entirely in conversation, are outside what static parsing can see.

---

## Testing & translation review

```bash
python -m pytest test/ -q      # 73 tests
python review_khmer.py         # dump all Khmer strings for a native speaker
```

`review_khmer.py` also reports any finding code that is missing a Khmer
translation, so no user-facing warning is ever untranslated.

---

## Privacy & safety notes

- Logs (`logs/checks.jsonl`) store **hashes** of filenames and user ids, never
  raw content.
- Downloads are streamed with a hard 20 MB cap, aborted mid-transfer if
  exceeded, and always cleaned up.
- APK and archive parsing refuse oversized members (zip-bomb guard) and never
  extract or run anything.
- The answer always ends with a reminder that the bot is not 100% accurate.
