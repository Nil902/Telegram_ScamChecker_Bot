import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from magic import verify_file_type


def test_exe_disguised_as_pdf():
    r = verify_file_type("fixtures/statement.pdf", "statement.pdf")
    assert r.mismatch
    assert any(f.code == "TYPE_DISGUISED_EXECUTABLE" for f in r.findings)


def test_real_pdf_is_clean():
    r = verify_file_type("fixtures/real_statement.pdf", "real_statement.pdf")
    assert not r.mismatch and r.findings == []


def test_legitimate_docx_not_flagged():
    """The false-positive guard: OOXML files ARE zips. Must not alarm."""
    r = verify_file_type("fixtures/report.docx", "report.docx")
    assert not r.mismatch


def test_apk_hiding_as_jpg():
    r = verify_file_type("fixtures/photo.jpg", "photo.jpg")
    assert r.mismatch
    assert any(f.code == "TYPE_HIDDEN_APK" for f in r.findings)


def test_real_jpeg_clean():
    r = verify_file_type("fixtures/family.jpg", "family.jpg")
    assert not r.mismatch