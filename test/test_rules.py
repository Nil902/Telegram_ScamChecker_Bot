import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules import check_filename


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