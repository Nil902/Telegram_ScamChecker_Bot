import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from magic import verify_file_type, PLAIN_TEXT_EXT


def _tmp(name: str, data: bytes) -> str:
    path = os.path.join(tempfile.mkdtemp(), name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


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


# --- plain-text types: real text is clean, disguised binaries are caught ---

def test_plain_text_ext_membership():
    """The plain-text set is what feeds coverage + the VT skip; lock it."""
    assert {".txt", ".md", ".csv", ".log", ".text"} <= PLAIN_TEXT_EXT


def test_real_markdown_is_clean():
    r = verify_file_type(_tmp("notes.md", b"# Title\n\nreal markdown\n"), "notes.md")
    assert not r.mismatch and r.findings == []


def test_real_csv_is_clean():
    r = verify_file_type(_tmp("data.csv", b"a,b,c\n1,2,3\n"), "data.csv")
    assert not r.mismatch and r.findings == []


def test_windows_exe_disguised_as_md_is_flagged():
    """A PE renamed evil.md must not pass as a harmless text file."""
    r = verify_file_type(_tmp("evil.md", b"MZ\x90\x00" + b"\x00" * 60), "evil.md")
    assert r.mismatch
    assert any(f.code == "TYPE_DISGUISED_EXECUTABLE" for f in r.findings)


def test_linux_exe_disguised_as_txt_is_flagged():
    r = verify_file_type(_tmp("evil.txt", b"\x7fELF" + b"\x00" * 60), "evil.txt")
    assert r.mismatch
    assert any(f.code == "TYPE_DISGUISED_EXECUTABLE" for f in r.findings)