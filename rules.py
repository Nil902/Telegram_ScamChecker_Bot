import re
import unicodedata

from models import Finding, Severity, FileCheckResult

# Programs that run on the user's device. No Cambodian bank, telco, or
# delivery company sends these over Telegram.
EXECUTABLE_EXT = {
    ".apk", ".exe", ".scr", ".bat", ".cmd", ".com",
    ".vbs", ".vbe", ".js", ".jse", ".msi", ".ps1", ".jar", ".hta",
}

# Office formats that can carry auto-executing macros.
MACRO_EXT = {".xlsm", ".docm", ".pptm", ".xlsb", ".dotm", ".xltm"}

# Containers — contents unknown until listed.
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".tar", ".gz", ".cab"}

# Android app bundles (.apkm/.xapk/.apks). A ZIP wrapping base.apk plus split
# parts. NOT conclusive on the name alone — a bundle can be perfectly
# legitimate — but it must be inspected.
BUNDLE_EXT = {".apkm", ".xapk", ".apks"}

# Documents that can embed scripts or launch actions.
DOCUMENT_EXT = {".pdf", ".docx", ".xlsx", ".pptx", ".rtf", ".doc", ".xls"}

# Extensions a victim reads as harmless.
SAFE_LOOKING_EXT = {".pdf", ".jpg", ".jpeg", ".png", ".docx", ".xlsx", ".txt", ".mp4"}

# Unicode direction-control characters. Inserted mid-filename, they make
# "photo\u202Egpj.apk" render on screen as "photoapk.jpg".
RTL_OVERRIDE_CHARS = {
    "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",
    "\u2066", "\u2067", "\u2068", "\u2069", "\u200F",
}

_PASSWORD_PATTERN = re.compile(
    r"(password|pass\s*word|pwd|លេខសម្ងាត់)\s*[:=]?\s*\S+", re.IGNORECASE
)


def _extensions(filename: str) -> list[str]:
    """All extensions, in order. 'invoice.pdf.exe' -> ['.pdf', '.exe']"""
    parts = filename.lower().split(".")
    return ["." + p for p in parts[1:]] if len(parts) > 1 else []


def check_filename(filename: str, message_text: str = "") -> FileCheckResult:
    """Apply every Tier 1 rule to a filename and its surrounding message."""
    result = FileCheckResult()
    exts = _extensions(unicodedata.normalize("NFKC", filename))
    final_ext = exts[-1] if exts else ""

    # Rule 1 — hidden direction-control character
    if any(c in filename for c in RTL_OVERRIDE_CHARS):
        result.findings.append(Finding(
            code="FILENAME_RTL_OVERRIDE",
            severity=Severity.CRITICAL,
            explanation=("The filename contains a hidden character that "
                         "disguises the real file type on screen."),
        ))
        result.conclusive = True

    # Rule 2 — double extension: invoice.pdf.exe
    if len(exts) >= 2 and final_ext in EXECUTABLE_EXT and exts[-2] in SAFE_LOOKING_EXT:
        result.findings.append(Finding(
            code="FILENAME_DOUBLE_EXTENSION",
            severity=Severity.CRITICAL,
            explanation=(f"The file looks like a '{exts[-2]}' but is really "
                         f"a '{final_ext}' program."),
        ))
        result.conclusive = True

    # Rule 3 — executable
    if final_ext in EXECUTABLE_EXT:
        explanation = (
            "This is an Android app installer. Banks in Cambodia never send "
            "their app through Telegram."
            if final_ext == ".apk"
            else "This file is a program that runs on your device."
        )
        result.findings.append(Finding(
            code="FILENAME_EXECUTABLE",
            severity=Severity.CRITICAL,
            explanation=explanation,
        ))
        result.conclusive = True

    # Rule 4 — macro-enabled document
    if final_ext in MACRO_EXT:
        result.findings.append(Finding(
            code="FILENAME_MACRO_ENABLED",
            severity=Severity.HIGH,
            explanation="This document can run hidden commands when opened.",
        ))

    # Rule 5 — locked archive with the password supplied in the message
    if final_ext in ARCHIVE_EXT and _PASSWORD_PATTERN.search(message_text or ""):
        result.findings.append(Finding(
            code="ARCHIVE_PASSWORD_IN_MESSAGE",
            severity=Severity.CRITICAL,
            explanation=("The file is locked with a password from the message. "
                         "This hides the contents from security scanners."),
        ))
        result.conclusive = True

    if not result.conclusive and final_ext in (ARCHIVE_EXT | DOCUMENT_EXT | BUNDLE_EXT):
        result.needs_inspection = True

    return result