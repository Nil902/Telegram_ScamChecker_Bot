import json
import logging
import os
import threading
from urllib.parse import urlsplit

from crewai.tools import tool

import evidence
from models import Finding, Severity
from rules import check_filename
from magic import verify_file_type as _verify_file_type
from apk import analyze_apk as _analyze_apk
from links import analyze_text as _analyze_links
from download import download_to_temp, cleanup

log = logging.getLogger(__name__)

# Only files served by the Telegram Bot API may be downloaded. The URL passed
# to download_file is chosen by the LLM, so a malicious caption or filename
# could prompt-inject it into fetching an arbitrary URL — an SSRF into the
# server's own network (e.g. cloud metadata at 169.254.169.254) or an internal
# service. Restricting the host to Telegram's file endpoint closes that door.
# Override TELEGRAM_API_HOST only when running a self-hosted Bot API server.
_ALLOWED_DOWNLOAD_HOST = os.getenv("TELEGRAM_API_HOST", "api.telegram.org").lower()


def _is_allowed_download_url(url: str) -> bool:
    """True only for an https URL whose host is the allowlisted Telegram host.

    The one exception is the offline evaluation harness (evaluate.py), which
    serves fixtures from a throwaway http server on loopback. It opts in via
    SCANCHECK_ALLOW_LOCAL_DOWNLOADS; that variable is never set in production,
    so live bot traffic can still only ever fetch from Telegram.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()

    if parts.scheme == "https" and (
        host == _ALLOWED_DOWNLOAD_HOST
        or host.endswith("." + _ALLOWED_DOWNLOAD_HOST)
    ):
        return True

    if os.getenv("SCANCHECK_ALLOW_LOCAL_DOWNLOADS") and host in (
        "127.0.0.1", "localhost", "::1"
    ):
        return True

    return False


def _record_failure(tool_name: str, exc: Exception) -> str:
    """A tool that crashed did NOT clear the file.

    Without this, an exception produces zero findings, and zero findings
    derive to SAFE — a crashing analyser would hand out green lights.
    """
    log.exception("%s failed", tool_name)
    evidence.record(tool_name, [Finding(
        code="ANALYSIS_FAILED",
        severity=Severity.HIGH,      # -> SUSPICIOUS, never SAFE
        explanation=("I could not finish checking this file. Because I "
                     "could not check it, please do not open it unless "
                     "you are certain who sent it."),
        params={"tool": tool_name},
    )])
    return json.dumps({
        "error": f"{type(exc).__name__}: {exc}",
        "findings": [],
        "analysis_incomplete": True,
    }, indent=2)
 
# Files fetched during one check. Thread-local for the same reason the
# evidence registry is: two users can be analysed concurrently, and a shared
# list would let one thread delete another thread's file mid-analysis.
_local = threading.local()
 
 
def _paths() -> list[str]:
    if not hasattr(_local, "downloaded"):
        _local.downloaded = []
    return _local.downloaded


def _needs_download_response(tool_name: str, file_path: str) -> str | None:
    """Guard content tools against being called before/without a download.

    Returns a corrective message (JSON) if `file_path` is not a file this run
    actually downloaded, or None if it is fine to proceed.

    This exists because the agent sometimes calls verify_file_type / inspect_apk
    with the download URL, or a path it has not fetched yet. That is a routing
    mistake, NOT an inability to inspect the file — so it must not go through
    _record_failure, which stamps a HIGH ANALYSIS_FAILED finding. That finding
    sticks in the registry and drags a perfectly benign file down to
    SUSPICIOUS even after a later, correct call finds nothing. Here we simply
    tell the agent to download first and let it retry, recording no finding.
    """
    if file_path in _paths() and os.path.exists(file_path):
        return None
    log.info("%s called with a non-downloaded path: %r", tool_name, file_path)
    evidence.record(tool_name, [])   # log the call, but record NO finding
    return json.dumps({
        "error": "file not downloaded yet",
        "hint": ("Call download_file first, then pass the 'file_path' it "
                 "returns to this tool — never the download URL."),
        "findings": [],
    }, indent=2)
 
 
@tool("check_filename_rules")
def check_filename_rules(filename: str, message_text: str = "") -> str:
    """Check a file's NAME for danger signs without downloading it.
 
    Use this FIRST for any file, before any other file tool. It is instant
    and requires no download. It detects executable extensions (.apk, .exe,
    .scr), double extensions like invoice.pdf.exe, hidden text-direction
    characters, macro-enabled Office documents, and password-protected
    archives.
 
    Args:
        filename: The name of the file, including its extension.
        message_text: The text sent alongside the file, if any.
 
    Returns:
        JSON with 'findings', 'conclusive', and 'needs_inspection'.
        If 'conclusive' is true, you already have enough to decide.
    """
    try:
        result = check_filename(filename, message_text)
    except Exception as exc:
        return _record_failure("check_filename_rules", exc)
    evidence.record("check_filename_rules", result.findings)
    return json.dumps(result.to_dict(), indent=2)
 
 
@tool("download_file")
def download_file(file_url: str, filename: str) -> str:
    """Download a file so its contents can be inspected.
 
    Only use this when you must examine the file's actual contents — for
    example when check_filename_rules returned needs_inspection=true, or when
    you need to read an Android app's permissions to explain exactly what it
    can do.
 
    Args:
        file_url: The URL provided in the task description.
        filename: The original filename, used to preserve the extension.
 
    Returns:
        JSON with 'file_path' to pass to other tools, plus 'sha256' and
        'size_bytes'. If it contains 'error', the download failed and you
        should say so rather than guessing about the contents.
    """
    # Refuse any URL that is not the Telegram file endpoint. Without this a
    # prompt-injected caption/filename could steer the agent into an SSRF.
    if not _is_allowed_download_url(file_url):
        log.warning("Blocked download from disallowed host: %r", file_url)
        return _record_failure(
            "download_file",
            ValueError("refused to download from a non-Telegram URL"),
        )

    suffix = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    try:
        path, sha256, size = download_to_temp(file_url, suffix)
    except Exception as exc:
        # A failed download means the file was never checked. Record a HIGH
        # finding so "could not fetch" cannot derive to SAFE either.
        return _record_failure("download_file", exc)
 
    _paths().append(path)
    evidence.record("download_file", [])   # no findings, but log the call
    return json.dumps({
        "file_path": path,
        "sha256": sha256,
        "size_bytes": size,
    }, indent=2)
 
 
@tool("verify_file_type")
def verify_file_type_tool(file_path: str, filename: str) -> str:
    """Read a downloaded file's contents to find its TRUE type.
 
    Use this when check_filename_rules returns needs_inspection=true, or
    whenever a file's name looks harmless but you are not certain. It detects
    programs disguised as documents or images — for example a .pdf that is
    really a Windows program, or a .jpg that is really an Android app.
 
    Do NOT use this if check_filename_rules already returned conclusive=true
    for an executable; the answer is already known.
 
    Args:
        file_path: Path to the downloaded file on disk.
        filename: The original filename as the user received it.
 
    Returns:
        JSON with 'actual_file_type', 'mismatch', and 'findings'.
    """
    guard = _needs_download_response("verify_file_type", file_path)
    if guard is not None:
        return guard
    try:
        result = _verify_file_type(file_path, filename)
    except Exception as exc:
        return _record_failure("verify_file_type", exc)
    evidence.record("verify_file_type", result.findings)
    return json.dumps(result.to_dict(), indent=2)
 
 
@tool("inspect_apk")
def inspect_apk(file_path: str) -> str:
    """Read an Android app's manifest to find what it can do to the phone.
 
    Use this when the file is an Android app (.apk) or an Android bundle
    (.apkm, .xapk, .apks), or when verify_file_type reports the actual type
    is android_apk or android_bundle.
 
    Pay attention to 'otp_theft_signature' — when true, the app can watch the
    screen and also capture the bank's one-time code, the combination used to
    empty accounts. Also check 'remote_access_tool' — when true the app is
    genuine, not a fake, but it lets another person control the phone
    remotely, which is the most common tool in Cambodian phone scams.
 
    Args:
        file_path: Path to the downloaded app file.
 
    Returns:
        JSON with package_name, dangerous_permissions, impersonation_target,
        otp_theft_signature, remote_access_tool, and findings.
    """
    guard = _needs_download_response("inspect_apk", file_path)
    if guard is not None:
        return guard
    try:
        result = _analyze_apk(file_path)
    except Exception as exc:
        return _record_failure("inspect_apk", exc)
    evidence.record("inspect_apk", result.findings)
    return json.dumps(result.to_dict(), indent=2)
 
 
@tool("inspect_links")
def inspect_links(message_text: str) -> str:
    """Check any web links in a message for signs of a scam.

    Use this whenever the message text or a file's caption contains a web
    link (http://, https://, www., or a bare address like example.com). It
    reads only the text of the link — it never opens it. It detects links
    that hide their real destination (shorteners), links to a numeric address
    instead of a real site, hidden-letter lookalike domains, web addresses
    that impersonate a Cambodian bank or wallet, and address endings commonly
    used for scams.

    Args:
        message_text: The full text of the message, or the file's caption.

    Returns:
        JSON with 'urls_checked' and 'findings'. If 'urls_checked' is 0 there
        were no links to examine.
    """
    try:
        result = _analyze_links(message_text)
    except Exception as exc:
        return _record_failure("inspect_links", exc)
    evidence.record("inspect_links", result.findings)
    return json.dumps(result.to_dict(), indent=2)


def cleanup_downloads() -> None:
    """Delete everything fetched during one check, in this thread only."""
    paths = _paths()
    while paths:
        cleanup(paths.pop())
 