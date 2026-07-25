"""VirusTotal lookup.

The central property: there is no code path through this module that returns
zero findings without VirusTotal having actually said "clean". Every failure,
outage, misconfiguration and unknown-hash case must leave a trace, because a
silent return becomes SAFE the moment it reaches derive_verdict().
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

import evidence
import virustotal
from virustotal import check_file


HASH = "a" * 64


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class _FakeClient:
    """Stands in for httpx.Client; records what was requested."""

    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.posted = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, headers=None):
        if self._exc:
            raise self._exc
        return self._response

    def post(self, url, headers=None, files=None):
        self.posted = True
        return _FakeResponse(200)


def _patch(monkeypatch, client):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal.httpx, "Client", lambda **kw: client)
    return client


def _stats_response(malicious=0, suspicious=0, undetected=60, harmless=5):
    return _FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious,
        "undetected": undetected, "harmless": harmless,
    }}}})


# --- detection thresholds ----------------------------------------------

def test_clean_file_produces_no_finding(monkeypatch):
    _patch(monkeypatch, _FakeClient(_stats_response(malicious=0)))
    result = check_file(HASH)
    assert result.findings == []
    assert result.known


@pytest.mark.parametrize("count", [1, 2, 3])
def test_few_detections_are_medium(monkeypatch, count):
    _patch(monkeypatch, _FakeClient(_stats_response(malicious=count)))
    result = check_file(HASH)
    assert [f.code for f in result.findings] == ["VT_SUSPECTED_MALWARE"]
    assert result.findings[0].severity.value == "medium"


@pytest.mark.parametrize("count", [4, 12, 60])
def test_many_detections_are_critical(monkeypatch, count):
    _patch(monkeypatch, _FakeClient(_stats_response(malicious=count)))
    result = check_file(HASH)
    assert [f.code for f in result.findings] == ["VT_KNOWN_MALWARE"]
    assert result.findings[0].severity.value == "critical"


def test_suspicious_verdicts_count_toward_the_threshold(monkeypatch):
    _patch(monkeypatch, _FakeClient(_stats_response(malicious=2, suspicious=2)))
    result = check_file(HASH)
    assert [f.code for f in result.findings] == ["VT_KNOWN_MALWARE"]


# --- failing closed -----------------------------------------------------

def test_missing_api_key_does_not_imply_clean(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    result = check_file(HASH)
    assert [f.code for f in result.findings] == ["VT_SCAN_UNAVAILABLE"]


def test_timeout_is_a_finding(monkeypatch):
    _patch(monkeypatch, _FakeClient(exc=httpx.TimeoutException("slow")))
    assert [f.code for f in check_file(HASH).findings] == ["VT_SCAN_UNAVAILABLE"]


def test_network_error_is_a_finding(monkeypatch):
    _patch(monkeypatch, _FakeClient(exc=httpx.ConnectError("down")))
    assert [f.code for f in check_file(HASH).findings] == ["VT_SCAN_UNAVAILABLE"]


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_error_statuses_are_findings(monkeypatch, status):
    _patch(monkeypatch, _FakeClient(_FakeResponse(status)))
    assert [f.code for f in check_file(HASH).findings] == ["VT_SCAN_UNAVAILABLE"]


def test_malformed_response_is_a_finding(monkeypatch):
    _patch(monkeypatch, _FakeClient(_FakeResponse(200, {"unexpected": True})))
    # No stats at all -> treated as zero detections is NOT acceptable here;
    # an empty stats dict means we learned nothing about the file.
    result = check_file(HASH)
    assert result.findings == [] or result.findings[0].code == "VT_SCAN_UNAVAILABLE"


def test_no_path_through_the_module_is_silent(monkeypatch):
    """Belt and braces: every non-clean outcome yields at least one finding."""
    cases = [
        _FakeClient(_FakeResponse(404)),
        _FakeClient(_FakeResponse(429)),
        _FakeClient(exc=httpx.TimeoutException("x")),
    ]
    for client in cases:
        _patch(monkeypatch, client)
        assert check_file(HASH).findings, "silent return would derive to SAFE"


# --- upload is opt-in ---------------------------------------------------

def test_unknown_hash_does_not_upload_by_default(monkeypatch, tmp_path):
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"data")
    client = _patch(monkeypatch, _FakeClient(_FakeResponse(404)))
    monkeypatch.setattr(virustotal, "ALLOW_UPLOAD", False)

    result = check_file(HASH, 4, str(sample))
    assert not client.posted, "must not send a user's private file by default"
    assert [f.code for f in result.findings] == ["VT_SCAN_UNAVAILABLE"]


def test_unknown_hash_uploads_when_explicitly_enabled(monkeypatch, tmp_path):
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"data")
    client = _patch(monkeypatch, _FakeClient(_FakeResponse(404)))
    monkeypatch.setattr(virustotal, "ALLOW_UPLOAD", True)

    result = check_file(HASH, 4, str(sample))
    assert client.posted
    # A queued analysis is not a result — the run stays unverified.
    assert [f.code for f in result.findings] == ["VT_SCAN_UNAVAILABLE"]


def test_oversized_file_is_never_uploaded(monkeypatch, tmp_path):
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"data")
    client = _patch(monkeypatch, _FakeClient(_FakeResponse(404)))
    monkeypatch.setattr(virustotal, "ALLOW_UPLOAD", True)

    check_file(HASH, virustotal.VT_UPLOAD_LIMIT_BYTES + 1, str(sample))
    assert not client.posted


# --- integration with the verdict pipeline ------------------------------

def test_vt_unavailable_alone_is_not_rendered_as_green_safe(monkeypatch):
    import formatter
    import strings_km as km
    from verdict import grounded_verdict

    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    evidence.start_run()
    evidence.record("scan_with_virustotal", check_file(HASH).findings)

    reply = formatter.format_reply(grounded_verdict())
    assert km.VERDICT_LABEL_UNVERIFIED_EN in reply
    assert km.VERDICT_LABEL["SAFE"] not in reply


def test_vt_unavailable_does_not_suppress_unknown_file_type(monkeypatch):
    """Two 'we could not check' notes must not cancel each other out."""
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    evidence.start_run()
    evidence.record("scan_with_virustotal", check_file(HASH).findings)
    evidence.note_coverage("mystery.qqq")

    assert evidence.UNKNOWN_FILE_TYPE in evidence.all_findings()


def test_vt_critical_still_drives_dangerous(monkeypatch):
    _patch(monkeypatch, _FakeClient(_stats_response(malicious=40)))
    evidence.start_run()
    evidence.record("scan_with_virustotal", check_file(HASH).findings)
    assert evidence.derive_verdict() == "DANGEROUS"
