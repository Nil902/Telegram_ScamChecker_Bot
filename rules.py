import re
import unicodedata

from models import Finding, Severity, FileCheckResult

# Programs that run on the user's device, directly, on a double-click. No
# Cambodian bank, telco, or delivery company sends these over Telegram.
#
# .msi/.msp (Windows Installer packages and patches) sit here at CRITICAL
# rather than in a milder tier: an installer can run arbitrary "custom
# actions" with elevated rights during install, so it is every bit as
# dangerous as a plain .exe. .cpl and .gadget are likewise executed by
# double-click even though they are not named like programs.
EXECUTABLE_EXT = {
    ".apk", ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".jar",
    ".msi", ".msix", ".msp", ".cpl", ".gadget",
}

# Files that are not programs themselves but silently launch one when
# opened. A .lnk shortcut can point at powershell.exe with a full command
# line; a .scf can trigger an outbound authentication attempt.
SHORTCUT_EXT = {".lnk", ".scf"}

# Files that change how the machine behaves rather than running on their
# own. A .reg edits the Windows registry on double-click; a .dll needs a
# loader, so it is a component of an attack rather than the whole of one.
SYSTEM_MODIFIER_EXT = {".reg", ".dll"}

# Disk images. Windows mounts these on double-click, and files inside a
# mounted image do not inherit the "downloaded from the internet" mark that
# would otherwise trigger a SmartScreen warning — a well-known way to smuggle
# an executable past that prompt. Contents are unknown until inspected.
DISK_IMAGE_EXT = {".iso", ".img"}

# Every extension that makes a file risky on name alone. Used by the
# double-extension rule, which must fire for "invoice.pdf.lnk" just as it
# does for "invoice.pdf.exe".
RISKY_EXT = EXECUTABLE_EXT | SHORTCUT_EXT | SYSTEM_MODIFIER_EXT | DISK_IMAGE_EXT

# Office formats that can carry auto-executing macros.
MACRO_EXT = {".xlsm", ".docm", ".pptm", ".xlsb", ".dotm", ".xltm"}

# Containers — contents unknown until listed. Disk images are containers too,
# so the password-protected-archive rule applies to them as well.
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab"} | DISK_IMAGE_EXT

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
    if len(exts) >= 2 and final_ext in RISKY_EXT and exts[-2] in SAFE_LOOKING_EXT:
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

    # Rule 3b — shortcut that launches something else
    if final_ext in SHORTCUT_EXT:
        result.findings.append(Finding(
            code="FILENAME_SHORTCUT",
            severity=Severity.CRITICAL,
            explanation=("This file is a shortcut. Opening it silently starts "
                         "a program you cannot see the name of."),
        ))
        result.conclusive = True

    # Rule 3c — changes system settings rather than running on its own.
    # HIGH, not CRITICAL: a .dll cannot start by itself, so on its own it is
    # a component of an attack rather than proof of one.
    if final_ext in SYSTEM_MODIFIER_EXT:
        result.findings.append(Finding(
            code="FILENAME_SYSTEM_MODIFIER",
            severity=Severity.HIGH,
            explanation=("This file changes settings deep inside a Windows "
                         "computer. It is not something a bank or a delivery "
                         "company would ever send you."),
        ))

    # Rule 3d — disk image. MEDIUM: the image itself is inert, and .iso is a
    # normal way to ship software, but it hides what is inside from the
    # warning Windows would otherwise show. Contents must still be inspected.
    if final_ext in DISK_IMAGE_EXT:
        result.findings.append(Finding(
            code="FILENAME_DISK_IMAGE",
            severity=Severity.MEDIUM,
            explanation=("This is a disk image. Windows opens it like a USB "
                         "stick, which lets whatever is inside skip the usual "
                         "safety warning."),
        ))

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