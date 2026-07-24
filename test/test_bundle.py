# tests/test_bundle.py
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules import check_filename
from apk import extract_base_apk


def test_bundle_extension_needs_inspection():
    """An .apkm can be legitimate, so it is never conclusive on the name alone."""
    r = check_filename("app.apkm")
    assert r.conclusive is False
    assert r.needs_inspection is True


def test_extract_base_apk_from_synthetic_bundle(tmp_path):
    """extract_base_apk must pull base.apk out of a bundle, ignoring splits."""
    bundle = tmp_path / "app.apkm"
    with zipfile.ZipFile(bundle, "w") as z:
        z.writestr("base.apk", b"dummy-base-apk-bytes")
        z.writestr("split_config.en.apk", b"dummy-split-bytes")
        z.writestr("info.json", b"{}")

    path, error = extract_base_apk(str(bundle))
    try:
        assert error is None
        assert path is not None
        assert os.path.exists(path)
        # It extracted the base, not the split.
        with open(path, "rb") as fh:
            assert fh.read() == b"dummy-base-apk-bytes"
    finally:
        if path and os.path.exists(path):
            os.remove(path)
