# tests/test_apk.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apk import ApkFacts, score_apk

P = "android.permission."


def test_otp_theft_signature_detected():
    facts = ApkFacts(
        package="com.aba.update",
        app_label="ABA Mobile",
        permissions=[P + "BIND_ACCESSIBILITY_SERVICE", P + "RECEIVE_SMS"],
    )
    r = score_apk(facts)
    assert r.otp_theft_signature
    assert any(f.code == "APK_OTP_THEFT_SIGNATURE" for f in r.findings)


def test_package_typosquat():
    facts = ApkFacts(package="com.paygo24.ibonk", permissions=[])
    r = score_apk(facts)
    assert r.impersonation_target == "ABA Bank"
    assert any(f.code == "APK_PACKAGE_TYPOSQUAT" for f in r.findings)


def test_brand_in_label_flagged():
    facts = ApkFacts(package="com.random.app", app_label="Wing Money Update")
    r = score_apk(facts)
    assert any(f.code == "APK_BRAND_IMPERSONATION" for f in r.findings)


def test_benign_app_stays_quiet():
    """False-positive guard: an ordinary app must not be flagged."""
    facts = ApkFacts(
        package="org.videolan.vlc",
        app_label="VLC",
        permissions=[P + "INTERNET", P + "READ_EXTERNAL_STORAGE"],
        target_sdk=33,
    )
    r = score_apk(facts)
    assert not r.otp_theft_signature
    assert r.findings == []


def test_sms_alone_is_not_the_signature():
    """Legitimate bank apps read SMS for OTP autofill. Alone it is not proof."""
    facts = ApkFacts(package="com.some.app", permissions=[P + "RECEIVE_SMS"],
                     target_sdk=33)
    r = score_apk(facts)
    assert not r.otp_theft_signature


def test_anydesk_flagged_as_remote_access_not_malware():
    """A genuine, correctly-signed AnyDesk is legitimate-but-abused, not a fake."""
    facts = ApkFacts(
        package="com.anydesk.anydeskandroid",
        app_label="AnyDesk",
        permissions=[
            P + "SYSTEM_ALERT_WINDOW",
            P + "INJECT_EVENTS",
            P + "FOREGROUND_SERVICE_MEDIA_PROJECTION",
            P + "RECORD_AUDIO",
            P + "MANAGE_EXTERNAL_STORAGE",
            P + "QUERY_ALL_PACKAGES",
            "com.samsung.android.knox.permission.KNOX_REMOTE_CONTROL",
            "android.permission.sec.MDM_REMOTE_CONTROL",
        ],
    )
    r = score_apk(facts)
    assert r.remote_access_tool is True
    assert any(f.code == "APK_REMOTE_ACCESS_TOOL" for f in r.findings)
    # It is the real app — must NOT be accused of impersonation.
    assert not any(f.code == "APK_BRAND_IMPERSONATION" for f in r.findings)
    assert not any(f.code == "APK_PACKAGE_TYPOSQUAT" for f in r.findings)


def test_screen_capture_without_sms_triggers_signature():
    """Screen control + live screen capture is OTP theft even with no SMS access."""
    facts = ApkFacts(
        package="com.some.remote",
        permissions=[
            P + "BIND_ACCESSIBILITY_SERVICE",
            P + "FOREGROUND_SERVICE_MEDIA_PROJECTION",
        ],
    )
    r = score_apk(facts)
    assert r.otp_theft_signature is True


def test_benign_app_still_clean():
    """False-positive guard: the broadened rules must not flag an ordinary app."""
    facts = ApkFacts(
        package="org.videolan.vlc",
        app_label="VLC",
        permissions=[P + "INTERNET"],
    )
    r = score_apk(facts)
    assert r.findings == []


def test_anydesk_remote_access_no_impersonation_findings():
    """The incident file: genuine AnyDesk bundle. Remote-access, not a fake,
    and never accused of impersonation. Its finding must carry params so the
    Khmer template can fill {name}."""
    facts = ApkFacts(
        package="com.anydesk.anydeskandroid",
        app_label="AnyDesk",
        permissions=[
            P + "SYSTEM_ALERT_WINDOW",
            P + "INJECT_EVENTS",
            P + "FOREGROUND_SERVICE_MEDIA_PROJECTION",
            "com.samsung.android.knox.permission.KNOX_REMOTE_CONTROL",
            "android.permission.sec.MDM_REMOTE_CONTROL",
        ],
        target_sdk=34,
    )
    r = score_apk(facts)
    assert r.remote_access_tool is True
    remote = [f for f in r.findings if f.code == "APK_REMOTE_ACCESS_TOOL"]
    assert remote, "expected an APK_REMOTE_ACCESS_TOOL finding"
    assert not any(f.code == "APK_BRAND_IMPERSONATION" for f in r.findings)
    assert not any(f.code == "APK_PACKAGE_TYPOSQUAT" for f in r.findings)
    assert remote[0].params == {"name": "AnyDesk"}


def test_score_apk_never_raises_unbound_local():
    """Every branch of the impersonation chain must be reachable without an
    UnboundLocalError — the defect that made the incident fail open."""
    cases = [
        # a genuine remote-access package
        ApkFacts(package="com.anydesk.anydeskandroid", app_label="AnyDesk"),
        # a known bank package
        ApkFacts(package="com.acleda.mobile", app_label="ACLEDA"),
        # a near-miss typosquat package
        ApkFacts(package="com.paygo24.ibonk", app_label=""),
        # a brand keyword in the label
        ApkFacts(package="com.random.app", app_label="Wing Money Update"),
        # a completely unrelated app
        ApkFacts(package="org.videolan.vlc", app_label="VLC",
                 permissions=[P + "INTERNET"]),
    ]
    for facts in cases:
        score_apk(facts)   # must not raise