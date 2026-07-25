import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from rules import (
    check_filename, EXECUTABLE_EXT, SHORTCUT_EXT,
    SYSTEM_MODIFIER_EXT, DISK_IMAGE_EXT,
)


def _codes(result):
    return {f.code for f in result.findings}


def _severity(result, code):
    return next(f.severity.value for f in result.findings if f.code == code)


def test_apk_is_conclusive():
    r = check_filename("ABA_Mobile.apk")
    assert r.conclusive
    assert any(f.code == "FILENAME_EXECUTABLE" for f in r.findings)


def test_double_extension():
    r = check_filename("invoice.pdf.exe")
    assert r.conclusive
    assert any(f.code == "FILENAME_DOUBLE_EXTENSION" for f in r.findings)


def test_rtl_override():
    r = check_filename("photo\u202Egpj.apk")
    assert any(f.code == "FILENAME_RTL_OVERRIDE" for f in r.findings)


def test_macro_doc_flagged_but_not_conclusive():
    r = check_filename("salary.xlsm")
    assert any(f.code == "FILENAME_MACRO_ENABLED" for f in r.findings)


def test_locked_archive_with_password():
    r = check_filename("docs.zip", message_text="password: 1234")
    assert r.conclusive


def test_pdf_needs_inspection():
    r = check_filename("statement.pdf")
    assert not r.conclusive and r.needs_inspection


def test_benign_image_clean():
    r = check_filename("family.jpg")
    assert not r.conclusive and not r.needs_inspection and r.findings == []


# --- expanded risky-extension coverage ---------------------------------
# One sample per extension, so a future edit that drops one from the set
# fails loudly rather than silently reopening the gap that let an .msi
# through as SAFE.

@pytest.mark.parametrize("ext", sorted(EXECUTABLE_EXT))
def test_every_executable_ext_is_critical(ext):
    r = check_filename(f"update{ext}")
    assert r.conclusive, f"{ext} should be conclusive on the name alone"
    assert "FILENAME_EXECUTABLE" in _codes(r)
    assert _severity(r, "FILENAME_EXECUTABLE") == "critical"


@pytest.mark.parametrize("ext", sorted(SHORTCUT_EXT))
def test_every_shortcut_ext_is_critical(ext):
    r = check_filename(f"invoice{ext}")
    assert r.conclusive
    assert _severity(r, "FILENAME_SHORTCUT") == "critical"


@pytest.mark.parametrize("ext", sorted(SYSTEM_MODIFIER_EXT))
def test_every_system_modifier_ext_is_high(ext):
    r = check_filename(f"patch{ext}")
    assert _severity(r, "FILENAME_SYSTEM_MODIFIER") == "high"


@pytest.mark.parametrize("ext", sorted(DISK_IMAGE_EXT))
def test_every_disk_image_ext_is_medium(ext):
    r = check_filename(f"software{ext}")
    assert _severity(r, "FILENAME_DISK_IMAGE") == "medium"
    assert r.needs_inspection, "a disk image's contents still need inspecting"


def test_msi_and_msp_stay_critical():
    """Windows Installer packages run arbitrary custom actions at install
    time, so they rank with .exe, not below it."""
    for name in ("setup.msi", "update.msp", "app.msix"):
        r = check_filename(name)
        assert _severity(r, "FILENAME_EXECUTABLE") == "critical", name


def test_double_extension_fires_for_new_risky_types():
    for name in ("invoice.pdf.lnk", "photo.jpg.msi", "statement.pdf.iso"):
        r = check_filename(name)
        assert "FILENAME_DOUBLE_EXTENSION" in _codes(r), name


def test_disk_image_still_matches_password_archive_rule():
    r = check_filename("files.iso", message_text="password: 4321")
    assert "ARCHIVE_PASSWORD_IN_MESSAGE" in _codes(r)