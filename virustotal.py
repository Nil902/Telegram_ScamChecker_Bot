"""VirusTotal hash lookup — the first check here that consults the outside
world about a specific file rather than reasoning about its name or shape.

DESIGN NOTES

Hash-first, always. `download.py` already folds a SHA-256 over the bytes as
it streams them, so a lookup costs one HTTP request and reveals nothing
about the file except a digest that VirusTotal can only match if someone
else already submitted the same bytes.

Uploading is a different matter and is OFF by default — see ALLOW_UPLOAD.

Like every other tool here, this one fails closed: an outage, a timeout, a
missing API key, or a rate-limit all produce a finding. The one thing this
module must never do is return silently, because silence is indistinguishable
from "clean" once it reaches evidence.derive_verdict().
"""
import logging
import os

import httpx

from models import Finding, Severity

log = logging.getLogger(__name__)

API_ROOT = "https://www.virustotal.com/api/v3"
TIMEOUT = 20.0

# VirusTotal's public API accepts direct uploads up to 32 MB. download.py
# caps us at 20 MB anyway, so in practice every file we hold is eligible;
# the constant is kept explicit so the limit is visible rather than implied.
VT_UPLOAD_LIMIT_BYTES = 32 * 1024 * 1024

# Uploading sends the user's actual file to a third party, where it becomes
# retrievable by any VirusTotal customer with a paid subscription. People
# forward this bot bank statements, ID photos, and family pictures. Doing
# that to a private document silently would be a serious privacy breach, so
# a hash lookup is the default and upload requires deliberate opt-in.
ALLOW_UPLOAD = os.getenv("VIRUSTOTAL_ALLOW_UPLOAD", "").lower() in ("1", "true", "yes")


# --- detection thresholds ------------------------------------------------
# Mapping engine counts to severity, tuned for false-positive cost.
#
# VirusTotal runs ~70 engines. Their agreement is not independent: many
# license the same signature feeds, and several are notoriously noisy on
# packed-but-legitimate installers, keygens, and niche software.
#
#   0            -> no finding. Nothing to say.
#   1-3          -> MEDIUM (SUSPICIOUS). A one- or two-engine hit is more
#                   often a generic heuristic than real malware; flagging it
#                   as DANGEROUS would train users to ignore red warnings.
#   4 or more    -> CRITICAL (DANGEROUS). Four independent detections is the
#                   point where a generic-heuristic explanation stops being
#                   plausible. This matches the convention used by most SOC
#                   triage playbooks, which sit at 3-5.
#
# "malicious" and "suspicious" verdicts are summed: an engine calling
# something suspicious still spent a signature on it.
CRITICAL_THRESHOLD = 4
MEDIUM_THRESHOLD = 1


class VirusTotalResult:
    """Deliberately mirrors the shape the other analysers return."""

    def __init__(self, findings, stats=None, known=False, skipped_reason=None):
        self.findings = findings
        self.stats = stats or {}
        self.known = known                  # VT had a record for this hash
        self.skipped_reason = skipped_reason

    def to_dict(self) -> dict:
        return {
            "known_to_virustotal": self.known,
            "detection_stats": self.stats,
            "skipped_reason": self.skipped_reason,
            "findings": [f.to_dict() for f in self.findings],
        }


def _unavailable(reason: str) -> VirusTotalResult:
    """No scan happened. Say so — never let this read as 'clean'.

    LOW, not HIGH: an unreachable third-party service is not evidence about
    the file, and making every file SUSPICIOUS during a VirusTotal outage
    would flood users with warnings that carry no information. The severity
    stays out of the verdict arithmetic; the honesty lives in the wording,
    and evidence.UNVERIFIED_CODES stops the reply being labelled green.
    """
    log.warning("VirusTotal scan unavailable: %s", reason)
    return VirusTotalResult(
        findings=[Finding(
            code="VT_SCAN_UNAVAILABLE",
            severity=Severity.LOW,
            explanation=("I could not compare this file against the database "
                         "of known viruses, so it has not been fully checked."),
            params={"reason": reason},
        )],
        skipped_reason=reason,
    )


def _findings_for(malicious: int, total: int) -> list[Finding]:
    if malicious >= CRITICAL_THRESHOLD:
        return [Finding(
            code="VT_KNOWN_MALWARE",
            severity=Severity.CRITICAL,
            explanation=(f"{malicious} of {total} virus scanners recognise "
                         f"this exact file as harmful software."),
            params={"detections": malicious, "total": total},
        )]
    if malicious >= MEDIUM_THRESHOLD:
        return [Finding(
            code="VT_SUSPECTED_MALWARE",
            severity=Severity.MEDIUM,
            explanation=(f"{malicious} of {total} virus scanners flagged this "
                         f"file. That is a small number, so it may be a false "
                         f"alarm, but be careful."),
            params={"detections": malicious, "total": total},
        )]
    return []


def _stats_to_result(stats: dict) -> VirusTotalResult:
    malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    return VirusTotalResult(
        findings=_findings_for(malicious, total),
        stats={"malicious": malicious, "engines": total},
        known=True,
    )


def check_file(sha256: str, size_bytes: int = 0,
               file_path: str | None = None) -> VirusTotalResult:
    """Look a file up by hash; optionally upload it if VT has never seen it.

    Args:
        sha256: digest computed during download, not recomputed here.
        size_bytes: used only to decide upload eligibility.
        file_path: on-disk path, required only if an upload is attempted.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        # Not an error — the bot must run without a VT subscription. But it
        # is also not a clean bill of health, so it is recorded, not ignored.
        return _unavailable("no VIRUSTOTAL_API_KEY configured")

    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            resp = client.get(f"{API_ROOT}/files/{sha256}", headers=headers)

            if resp.status_code == 200:
                stats = (resp.json().get("data", {})
                         .get("attributes", {})
                         .get("last_analysis_stats", {}))
                return _stats_to_result(stats)

            if resp.status_code == 404:
                return _handle_unknown_hash(client, headers, size_bytes, file_path)

            if resp.status_code == 429:
                return _unavailable("VirusTotal rate limit reached")

            if resp.status_code in (401, 403):
                return _unavailable("VirusTotal rejected the API key")

            return _unavailable(f"VirusTotal returned HTTP {resp.status_code}")

    except httpx.TimeoutException:
        return _unavailable("VirusTotal timed out")
    except Exception as exc:                       # network error, bad JSON…
        return _unavailable(f"{type(exc).__name__}: {exc}")


def _handle_unknown_hash(client, headers, size_bytes, file_path):
    """VT has no record of this hash.

    An unknown hash is genuinely informative in both directions: most benign
    files people receive are also unknown, so it is NOT by itself suspicious
    and produces no finding of its own. But it does mean no scanner has
    vouched for the file, so the reply must not claim it was checked.
    """
    if not ALLOW_UPLOAD:
        return _unavailable("file unknown to VirusTotal and upload is disabled")

    if not file_path or not os.path.exists(file_path):
        return _unavailable("file unknown to VirusTotal and no file to upload")

    if size_bytes > VT_UPLOAD_LIMIT_BYTES:
        return _unavailable("file unknown to VirusTotal and too large to upload")

    try:
        with open(file_path, "rb") as fh:
            resp = client.post(f"{API_ROOT}/files", headers=headers,
                               files={"file": fh})
        if resp.status_code not in (200, 201):
            return _unavailable(f"VirusTotal upload failed "
                                f"(HTTP {resp.status_code})")
    except Exception as exc:
        return _unavailable(f"VirusTotal upload failed: {type(exc).__name__}")

    # An upload only queues an analysis; results take minutes. We do not
    # block a user's reply waiting for it, so this run stays unverified.
    return _unavailable("file submitted to VirusTotal; results not ready yet")
