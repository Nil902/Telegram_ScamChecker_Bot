from dataclasses import dataclass

from models import Finding, Severity

# (signature bytes, offset, family name)
SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"MZ",                 0, "windows_executable"),
    (b"\x7fELF",            0, "linux_executable"),
    (b"\xca\xfe\xba\xbe",   0, "java_class"),
    (b"%PDF",               0, "pdf"),
    (b"PK\x03\x04",         0, "zip_container"),
    (b"Rar!\x1a\x07",       0, "rar_archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z_archive"),
    (b"\xd0\xcf\x11\xe0",   0, "ole_legacy_office"),
    (b"\xff\xd8\xff",       0, "jpeg"),
    (b"\x89PNG",            0, "png"),
    (b"GIF8",               0, "gif"),
    (b"\x1f\x8b",           0, "gzip"),
    (b"ftyp",               4, "mp4"),
]

# What each extension is ALLOWED to actually be.
# Note the OOXML and Android formats are legitimately ZIP containers.
EXPECTED_TYPES: dict[str, set[str]] = {
    ".pdf":  {"pdf"},
    ".docx": {"zip_container"},
    ".xlsx": {"zip_container"},
    ".pptx": {"zip_container"},
    ".xlsm": {"zip_container"},
    ".apk":  {"zip_container"},
    ".apkm": {"zip_container"},
    ".xapk": {"zip_container"},
    ".apks": {"zip_container"},
    ".jar":  {"zip_container"},
    ".zip":  {"zip_container"},
    ".doc":  {"ole_legacy_office"},
    ".xls":  {"ole_legacy_office"},
    ".rar":  {"rar_archive"},
    ".7z":   {"7z_archive"},
    ".jpg":  {"jpeg"},
    ".jpeg": {"jpeg"},
    ".png":  {"png"},
    ".gif":  {"gif"},
    ".mp4":  {"mp4"},
    ".exe":  {"windows_executable"},
    ".scr":  {"windows_executable"},
    ".msi":  {"ole_legacy_office", "windows_executable"},
    # Plain-text formats carry no magic signature, so their content must read
    # as "unknown". Anything with a real binary signature under one of these
    # names is a disguise (e.g. a Windows executable renamed evil.md) and is
    # flagged below rather than passed off as a harmless text file.
    ".txt":  {"unknown"},
    ".md":   {"unknown"},
    ".csv":  {"unknown"},
    ".log":  {"unknown"},
    ".text": {"unknown"},
}

EXECUTABLE_FAMILIES = {"windows_executable", "linux_executable"}

# Extensions whose only legitimate content is unsignatured plain text. Derived
# from the table above so the two never drift. A file that verifies as one of
# these is inert (it cannot execute and carries no macro/script container), so
# a VirusTotal malware-binary lookup is not applicable to it.
PLAIN_TEXT_EXT = {ext for ext, types in EXPECTED_TYPES.items() if types == {"unknown"}}


@dataclass
class TypeCheckResult:
    claimed_ext: str
    real_type: str
    mismatch: bool
    findings: list[Finding]

    def to_dict(self) -> dict:
        return {
            "claimed_extension": self.claimed_ext,
            "actual_file_type": self.real_type,
            "mismatch": self.mismatch,
            "findings": [f.to_dict() for f in self.findings],
        }


def detect_type(header: bytes) -> str:
    for sig, offset, family in SIGNATURES:
        if header[offset:offset + len(sig)] == sig:
            return family
    return "unknown"


def refine_zip_container(path: str) -> str:
    """A ZIP could be an APK, an Office document, or a plain archive.
    Look at the entry names to tell them apart."""
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except Exception:
        return "zip_container"

    if "AndroidManifest.xml" in names:
        return "android_apk"
    # An app bundle wraps base.apk (+ split_config.*.apk) rather than a
    # manifest at the top level.
    if any(n.endswith("base.apk") or "split_config" in n for n in names):
        return "android_bundle"
    if "[Content_Types].xml" in names:
        return "ooxml_document"
    return "zip_container"


def verify_file_type(path: str, filename: str) -> TypeCheckResult:
    """Compare a file's real content type against its claimed extension."""
    with open(path, "rb") as fh:
        header = fh.read(32)

    real = detect_type(header)
    if real == "zip_container":
        refined = refine_zip_container(path)
        # Treat APK and OOXML as zip for the compatibility check,
        # but report the refined name to the agent.
        real_reported = refined
    else:
        real_reported = real

    ext = "." + filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    expected = EXPECTED_TYPES.get(ext)
    findings: list[Finding] = []
    mismatch = False

    if expected is None:
        pass  # unknown extension — nothing to compare against
    elif real in expected:
        pass  # consistent
    else:
        mismatch = True
        if real in EXECUTABLE_FAMILIES:
            findings.append(Finding(
                code="TYPE_DISGUISED_EXECUTABLE",
                severity=Severity.CRITICAL,
                explanation=(f"This file is named like a '{ext}' document, but "
                             f"it is actually a program that runs on your "
                             f"device."),
            ))
        else:
            findings.append(Finding(
                code="TYPE_MISMATCH",
                severity=Severity.HIGH,
                explanation=(f"The file claims to be '{ext}' but its contents "
                             f"are actually {real_reported.replace('_', ' ')}."),
            ))

    # An APK that isn't named .apk is deliberate disguise.
    if real_reported == "android_apk" and ext != ".apk":
        mismatch = True
        findings.append(Finding(
            code="TYPE_HIDDEN_APK",
            severity=Severity.CRITICAL,
            explanation=("This is an Android app installer disguised with a "
                         "different file name."),
        ))

    return TypeCheckResult(ext, real_reported, mismatch, findings)