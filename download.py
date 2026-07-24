import hashlib
import os
import tempfile
 
import httpx
 
MAX_FILE_BYTES = 20 * 1024 * 1024   # 20 MB hard cap
CHUNK = 64 * 1024
 
 
class DownloadTooLarge(Exception):
    pass
 
 
def download_to_temp(url: str, suffix: str = "") -> tuple[str, str, int]:
    """Stream a file to a temp path. Returns (path, sha256, size).
 
    Safety rules enforced here:
      - hard size cap, checked DURING streaming so a huge file is aborted
        mid-transfer rather than after it fills the disk
      - written to the OS temp directory, never the project folder
      - chmod 0o600: never executable, even by accident
      - the caller MUST delete the file when finished
    """
    digest = hashlib.sha256()
    size = 0
 
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="scancheck_")
    try:
        with os.fdopen(fd, "wb") as out:
            # follow_redirects stays False (also httpx's default, but pinned
            # here deliberately): a redirect could bounce an allowlisted
            # Telegram URL off to an attacker-controlled or internal host,
            # defeating the host check the caller performs before calling us.
            with httpx.stream("GET", url, timeout=30.0,
                              follow_redirects=False) as resp:
                resp.raise_for_status()
                for chunk in resp.iter_bytes(CHUNK):
                    size += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise DownloadTooLarge(f"exceeded {MAX_FILE_BYTES} bytes")
                    digest.update(chunk)
                    out.write(chunk)
        os.chmod(path, 0o600)
        return path, digest.hexdigest(), size
    except Exception:
        cleanup(path)
        raise
 
 
def cleanup(path: str) -> None:
    """Delete a temp file. Safe to call twice."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
 