"""Create harmless test files that exercise every detection path."""
import os, zipfile

os.makedirs("fixtures", exist_ok=True)

# A real PDF
with open("fixtures/real_statement.pdf", "wb") as f:
    f.write(b"%PDF-1.4\n% harmless test file\n")

# A Windows executable header, renamed to .pdf  <-- the key case
with open("fixtures/statement.pdf", "wb") as f:
    f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"harmless test file, not real malware")

# A real JPEG
with open("fixtures/family.jpg", "wb") as f:
    f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 32)

# A legitimate-looking OOXML document (must NOT be flagged)
with zipfile.ZipFile("fixtures/report.docx", "w") as z:
    z.writestr("[Content_Types].xml", "<Types/>")
    z.writestr("word/document.xml", "<document/>")

# An APK hiding as a JPEG
with zipfile.ZipFile("fixtures/photo.jpg", "w") as z:
    z.writestr("AndroidManifest.xml", "fake manifest")
    z.writestr("classes.dex", "fake dex")

print("fixtures created:", os.listdir("fixtures"))