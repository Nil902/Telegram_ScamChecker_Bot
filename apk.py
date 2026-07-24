"""Static APK manifest analysis. PARSING ONLY — nothing is ever executed."""
import logging
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
import yaml

from models import Finding, Severity

# pyaxmlparser prints "res1 is not zero!" to stderr on many perfectly valid
# APKs. It is noise, not an error we can act on — quiet it.
logging.getLogger("pyaxmlparser").setLevel(logging.ERROR)

# Android app bundles: a ZIP wrapping base.apk plus split_config.*.apk parts.
# .apkm = APKMirror, .xapk = APKPure, .apks = bundletool/SAI.
BUNDLE_EXTENSIONS = {".apkm", ".xapk", ".apks"}

# Zip-bomb guard: refuse to extract a member larger than this uncompressed.
_MAX_BASE_APK_BYTES = 200 * 1024 * 1024   # 200 MB

# ---------------------------------------------------------------- reference

_REF_PATH = Path(__file__).parent / "data" / "cambodian_apps.yaml"
_REF = yaml.safe_load(_REF_PATH.read_text(encoding="utf-8"))

KNOWN_PACKAGES: dict[str, str] = {
    pkg: inst["name"]
    for inst in _REF["institutions"]
    for pkg in inst["packages"]
}
BRAND_KEYWORDS: list[str] = _REF["brand_keywords"]

# ---------------------------------------------------------------- signatures

DANGEROUS_PERMISSIONS: dict[str, tuple[Severity, str]] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        (Severity.CRITICAL, "read everything on your screen and tap buttons for you"),
    "android.permission.RECEIVE_SMS":
        (Severity.CRITICAL, "read the SMS messages you receive, including bank codes"),
    "android.permission.READ_SMS":
        (Severity.CRITICAL, "read the SMS messages saved on your phone"),
    "android.permission.SYSTEM_ALERT_WINDOW":
        (Severity.HIGH, "draw fake screens on top of your other apps"),
    "android.permission.REQUEST_INSTALL_PACKAGES":
        (Severity.HIGH, "install more apps onto your phone"),
    "android.permission.BIND_DEVICE_ADMIN":
        (Severity.HIGH, "stop you from uninstalling it"),
    "android.permission.SEND_SMS":
        (Severity.MEDIUM, "send SMS messages that you will be charged for"),
    "android.permission.READ_CONTACTS":
        (Severity.MEDIUM, "read your contact list"),
    "android.permission.CALL_PHONE":
        (Severity.MEDIUM, "make phone calls without asking you"),
}

SCREEN_CONTROL = "android.permission.BIND_ACCESSIBILITY_SERVICE"
SMS_READ = {"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"}
OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"

# Genuine remote-desktop apps. Not malware — but the primary tool in
# Cambodian remote-access bank fraud: the scammer watches the victim's
# screen live and reads the OTP as the victim reads it aloud.
REMOTE_ACCESS_PACKAGES: dict[str, str] = {
    "com.anydesk.anydeskandroid":              "AnyDesk",
    "com.teamviewer.quicksupport.market":      "TeamViewer QuickSupport",
    "com.teamviewer.teamviewer.market.mobile": "TeamViewer",
    "com.rsupport.mobizen.rc":                 "Mobizen",
    "com.microsoft.rdc.androidx":              "Microsoft Remote Desktop",
}

# Permissions that let an app stream or drive the screen without the
# accessibility+SMS combination the classic OTP-theft check looks for.
SCREEN_CAPTURE_PERMISSIONS = {
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION",
    "android.permission.INJECT_EVENTS",
    "com.samsung.android.knox.permission.KNOX_REMOTE_CONTROL",
    "android.permission.sec.MDM_REMOTE_CONTROL",
}


# ---------------------------------------------------------------- data types

@dataclass
class ApkFacts:
    """Raw facts extracted from the manifest. No interpretation."""
    package: str = ""
    app_label: str = ""
    version_name: str = ""
    permissions: list[str] = field(default_factory=list)
    min_sdk: int | None = None
    target_sdk: int | None = None
    parse_error: str | None = None
    from_bundle: bool = False   # extracted from an .apkm/.xapk/.apks wrapper


@dataclass
class ApkAnalysis:
    facts: ApkFacts
    findings: list[Finding] = field(default_factory=list)
    impersonation_target: str | None = None
    otp_theft_signature: bool = False
    remote_access_tool: bool = False

    def to_dict(self) -> dict:
        return {
            "package_name": self.facts.package,
            "app_label": self.facts.app_label,
            "target_sdk": self.facts.target_sdk,
            "dangerous_permissions": [
                p for p in self.facts.permissions if p in DANGEROUS_PERMISSIONS
            ],
            "impersonation_target": self.impersonation_target,
            "otp_theft_signature": self.otp_theft_signature,
            "remote_access_tool": self.remote_access_tool,
            "findings": [f.to_dict() for f in self.findings],
            "parse_error": self.facts.parse_error,
        }


# ---------------------------------------------------------------- parsing

def extract_base_apk(bundle_path: str) -> tuple[str | None, str | None]:
    """Pull only base.apk out of an app bundle (.apkm/.xapk/.apks).

    Returns (temp_apk_path, None) on success or (None, error_string) on
    failure. Never extracts the whole archive, and refuses any member whose
    uncompressed size exceeds the zip-bomb cap.
    """
    try:
        with zipfile.ZipFile(bundle_path) as z:
            infos = z.infolist()
            # Prefer an explicit base.apk; otherwise the first non-split .apk.
            member = next(
                (i for i in infos if i.filename.endswith("base.apk")), None
            )
            if member is None:
                member = next(
                    (i for i in infos
                     if i.filename.endswith(".apk")
                     and "split_config" not in i.filename),
                    None,
                )
            if member is None:
                return None, "bundle contains no base.apk"

            if member.file_size > _MAX_BASE_APK_BYTES:
                return None, (
                    f"base.apk is too large ({member.file_size} bytes); "
                    f"refusing to extract"
                )

            fd, tmp_path = tempfile.mkstemp(suffix=".apk", prefix="scancheck_")
            try:
                # Stream the single member; do not extractall().
                with os.fdopen(fd, "wb") as out, z.open(member) as src:
                    written = 0
                    while True:
                        chunk = src.read(64 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > _MAX_BASE_APK_BYTES:
                            raise ValueError("extracted size exceeded cap")
                        out.write(chunk)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            return tmp_path, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def parse_apk(path: str) -> ApkFacts:
    """Read AndroidManifest.xml. Never executes any code from the APK.

    Accepts a plain .apk or an app bundle (.apkm/.xapk/.apks); for a bundle
    it extracts only base.apk, parses that, and deletes the temp file.
    """
    try:
        from pyaxmlparser import APK
    except ImportError:
        return ApkFacts(parse_error="pyaxmlparser not installed")

    from_bundle = False
    apk_path = path
    temp_path: str | None = None

    if path.lower().endswith(tuple(BUNDLE_EXTENSIONS)):
        from_bundle = True
        temp_path, err = extract_base_apk(path)
        if err is not None:
            return ApkFacts(from_bundle=True,
                            parse_error=f"bundle extraction failed: {err}")
        apk_path = temp_path

    try:
        apk = APK(apk_path)
        return ApkFacts(
            package=apk.package or "",
            app_label=apk.application or "",
            version_name=apk.version_name or "",
            permissions=sorted(set(apk.permissions or [])),
            min_sdk=int(apk.get_min_sdk_version() or 0) or None,
            target_sdk=int(apk.get_target_sdk_version() or 0) or None,
            from_bundle=from_bundle,
        )
    except Exception as exc:
        return ApkFacts(from_bundle=from_bundle,
                        parse_error=f"{type(exc).__name__}: {exc}")
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# ---------------------------------------------------------------- scoring

def _levenshtein(a: str, b: str) -> int:
    """Edit distance. Small enough to write ourselves — no dependency."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def score_apk(facts: ApkFacts) -> ApkAnalysis:
    """Interpret manifest facts. Pure function — unit-testable without an APK."""
    analysis = ApkAnalysis(facts=facts)
    perms = set(facts.permissions)

    if facts.parse_error:
        analysis.findings.append(Finding(
            code="APK_PARSE_FAILED",
            severity=Severity.MEDIUM,
            explanation=("This file could not be read as a normal Android app, "
                         "which is itself unusual."),
        ))
        return analysis

    # --- individual dangerous permissions ---
    for perm in sorted(perms & set(DANGEROUS_PERMISSIONS)):
        severity, capability = DANGEROUS_PERMISSIONS[perm]
        analysis.findings.append(Finding(
            code="APK_PERMISSION_" + perm.rsplit(".", 1)[-1],
            severity=severity,
            explanation=f"This app can {capability}.",
        ))

    # --- the OTP-theft combination ---
    # Screen control PLUS a way to see the code: either reading SMS, or
    # streaming/driving the screen (a scammer watching live does not need SMS).
    if SCREEN_CONTROL in perms and (
        (perms & SMS_READ) or (perms & SCREEN_CAPTURE_PERMISSIONS)
    ):
        analysis.otp_theft_signature = True
        analysis.findings.append(Finding(
            code="APK_OTP_THEFT_SIGNATURE",
            severity=Severity.CRITICAL,
            explanation=("This app can both read your screen and read your SMS "
                         "messages. That combination is how money is stolen: it "
                         "sees your password and takes the code your bank sends."),
        ))

    if SCREEN_CONTROL in perms and OVERLAY in perms:
        analysis.findings.append(Finding(
            code="APK_OVERLAY_ATTACK_SIGNATURE",
            severity=Severity.CRITICAL,
            explanation=("This app can show a fake screen over your real bank "
                         "app and control what happens."),
        ))

    pkg = facts.package.lower()
    label = facts.app_label.lower()

    # --- impersonation vs. genuine-but-abused: exactly ONE outcome ---------
    # A file is at most one of these, so they form a single if/elif/else
    # chain. Each branch binds its own variable (remote_name, bank_name,
    # typo_match) — never a shared `name`, whose fall-through was the source
    # of the UnboundLocalError.
    if facts.package in REMOTE_ACCESS_PACKAGES:
        # The REAL app, correctly signed — not an imitation. We must NOT raise
        # brand-impersonation or typosquat findings on it; those would be
        # false positives. We warn about the social-engineering risk instead.
        analysis.remote_access_tool = True
        remote_name = REMOTE_ACCESS_PACKAGES[facts.package]
        analysis.findings.append(Finding(
            code="APK_REMOTE_ACCESS_TOOL",
            severity=Severity.HIGH,
            explanation=(f"{remote_name} is a real app, not a fake. It lets "
                         f"another person see and control your phone from "
                         f"anywhere. If someone asked you to install it, "
                         f"especially someone saying they are from your bank, "
                         f"the police, or a government office, this is a scam. "
                         f"No bank or government office will ever ask you to "
                         f"install this."),
            params={"name": remote_name},
        ))
    elif pkg in KNOWN_PACKAGES:
        bank_name = KNOWN_PACKAGES[pkg]
        analysis.impersonation_target = bank_name
        # Real package name, but arriving via Telegram is still wrong.
        analysis.findings.append(Finding(
            code="APK_CLAIMS_REAL_PACKAGE",
            severity=Severity.HIGH,
            explanation=(f"This app uses the real package name of {bank_name}, "
                         f"but genuine bank apps are only available from the "
                         f"Play Store, never from Telegram."),
            params={"bank": bank_name},
        ))
    else:
        # Typosquat check via an explicit flag, set inside the loop before the
        # break — no for/else, whose subtle scoping caused the original bug.
        typo_match = None
        for known, known_name in KNOWN_PACKAGES.items():
            if 0 < _levenshtein(pkg, known) <= 3:
                typo_match = known_name
                break
        if typo_match:
            analysis.impersonation_target = typo_match
            analysis.findings.append(Finding(
                code="APK_PACKAGE_TYPOSQUAT",
                severity=Severity.CRITICAL,
                explanation=(f"The app's internal name is almost identical to "
                             f"{typo_match}'s real app, but not the same. It is "
                             f"an imitation."),
                params={"bank": typo_match},
            ))
        else:
            hit = next((k for k in BRAND_KEYWORDS if k in label or k in pkg), None)
            if hit:
                analysis.impersonation_target = hit.upper()
                analysis.findings.append(Finding(
                    code="APK_BRAND_IMPERSONATION",
                    severity=Severity.HIGH,
                    explanation=(f"This app uses the name '{hit}' but is not the "
                                 f"official app from that company."),
                    params={"brand": hit},
                ))

    # --- deliberately old target SDK escapes modern permission controls ---
    if facts.target_sdk and facts.target_sdk < 26:
        analysis.findings.append(Finding(
            code="APK_OLD_TARGET_SDK",
            severity=Severity.MEDIUM,
            explanation=("This app is built for an old version of Android so it "
                         "can avoid newer security protections."),
        ))

    return analysis


def analyze_apk(path: str) -> ApkAnalysis:
    return score_apk(parse_apk(path))