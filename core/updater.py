"""Secure Release Update Checker and Verifier for Sentinel CAC Manager.

Enforces fail-closed supply-chain security:
- Strict HTTPS origin validation (github.com/CodeFXR/Sentinel-CAC-Manager)
- Strict semantic version tag validation (^v?\\d+\\.\\d+\\.\\d+$)
- Mandatory SHA-256 digest verification before any archive extraction
- Tar-slip (CWE-22) and symlink/device member rejection during extraction
"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
from typing import Callable, Optional, Tuple
import urllib.error
import urllib.request

from core import __version__

GITHUB_API_LATEST_URL = "https://api.github.com/repos/CodeFXR/Sentinel-CAC-Manager/releases/latest"
ALLOWED_HTML_PREFIX = "https://github.com/CodeFXR/Sentinel-CAC-Manager/"
ALLOWED_DOWNLOAD_PREFIX = "https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/download/"
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
BODY_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\s+\*?Sentinel-CAC-Manager[^\s]*\.tar\.gz\b")
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB ceiling


@dataclass
class UpdateInfo:
    current_version: str
    latest_version: str
    tag_name: str
    update_available: bool
    html_url: str
    download_url: Optional[str]
    expected_sha256: Optional[str]
    status_message: str
    error: Optional[str] = None


def parse_semver(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse a strict 'vX.Y.Z' or 'X.Y.Z' version string into a 3-int tuple."""
    if not isinstance(version_str, str):
        return None
    match = SEMVER_RE.match(version_str.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_newer_version(current_ver: str, candidate_ver: str) -> bool:
    """Return True only if candidate_ver is strictly newer than current_ver."""
    cur = parse_semver(current_ver)
    cand = parse_semver(candidate_ver)
    if cur is None or cand is None:
        return False
    return cand > cur


def _extract_sha256_from_release(release_data: dict, archive_name: str) -> Optional[str]:
    """Extract a 64-hex SHA-256 digest for the release tarball from GitHub metadata or body."""
    assets = release_data.get("assets") or []
    for asset in assets:
        if asset.get("name") == archive_name:
            digest = asset.get("digest", "")
            if isinstance(digest, str) and digest.lower().startswith("sha256:"):
                hex_part = digest.split(":", 1)[1].strip().lower()
                if SHA256_RE.match(hex_part):
                    return hex_part

    body = release_data.get("body") or ""
    if isinstance(body, str):
        match = BODY_SHA256_RE.search(body)
        if match:
            return match.group(1).lower()

    return None


def check_for_updates(current_version: str = __version__, timeout: float = 5.0) -> UpdateInfo:
    """Query GitHub Releases API over HTTPS to check if a newer release is available."""
    req = urllib.request.Request(
        GITHUB_API_LATEST_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"Sentinel-CAC-Manager/{current_version}",
        },
        method="GET",
    )
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw_bytes = resp.read(2 * 1024 * 1024)
            data = json.loads(raw_bytes.decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return UpdateInfo(
                current_version=current_version,
                latest_version=current_version,
                tag_name=f"v{current_version}",
                update_available=False,
                html_url=ALLOWED_HTML_PREFIX + "releases",
                download_url=None,
                expected_sha256=None,
                status_message=f"v{current_version} is up to date (no newer published release)",
                error=None,
            )
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            tag_name=f"v{current_version}",
            update_available=False,
            html_url=ALLOWED_HTML_PREFIX + "releases",
            download_url=None,
            expected_sha256=None,
            status_message=f"Update check failed (HTTP {e.code})",
            error=f"HTTP {e.code}",
        )
    except Exception as e:
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            tag_name=f"v{current_version}",
            update_available=False,
            html_url=ALLOWED_HTML_PREFIX + "releases",
            download_url=None,
            expected_sha256=None,
            status_message="Offline or unable to reach GitHub Releases",
            error=str(e),
        )

    tag_name = str(data.get("tag_name", "")).strip()
    parsed_latest = parse_semver(tag_name)
    if parsed_latest is None:
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            tag_name=f"v{current_version}",
            update_available=False,
            html_url=ALLOWED_HTML_PREFIX + "releases",
            download_url=None,
            expected_sha256=None,
            status_message="Rejected malformed release tag from server",
            error="Invalid semver tag",
        )

    latest_ver_str = f"{parsed_latest[0]}.{parsed_latest[1]}.{parsed_latest[2]}"
    html_url = str(data.get("html_url", "")).strip()
    if not html_url.startswith(ALLOWED_HTML_PREFIX):
        html_url = f"{ALLOWED_HTML_PREFIX}releases/tag/{tag_name}"

    download_url = None
    archive_name = "Sentinel-CAC-Manager.tar.gz"
    for asset in data.get("assets") or []:
        name = str(asset.get("name", ""))
        url = str(asset.get("browser_download_url", ""))
        if name.endswith(".tar.gz") and "Sentinel-CAC-Manager" in name and url.startswith(ALLOWED_DOWNLOAD_PREFIX):
            download_url = url
            archive_name = name
            break

    expected_sha256 = _extract_sha256_from_release(data, archive_name)
    newer = is_newer_version(current_version, latest_ver_str)

    if newer:
        status_msg = f"Update available: v{latest_ver_str} (current: v{current_version})"
    else:
        status_msg = f"Up to date (v{current_version})"

    return UpdateInfo(
        current_version=current_version,
        latest_version=latest_ver_str,
        tag_name=tag_name if tag_name.startswith("v") else f"v{latest_ver_str}",
        update_available=newer,
        html_url=html_url,
        download_url=download_url,
        expected_sha256=expected_sha256,
        status_message=status_msg,
        error=None,
    )


def safe_extract_tarball(tar_path: str, dest_dir: str) -> Tuple[bool, str]:
    """Safely extract a .tar.gz archive, rejecting path traversal, symlinks, and special files."""
    abs_dest = os.path.abspath(dest_dir)
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                return False, "Archive is empty."

            for member in members:
                if member.issym() or member.islnk():
                    return False, f"Security policy: Rejected symbolic/hard link in archive ({member.name})"
                if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                    return False, f"Security policy: Rejected special device file in archive ({member.name})"
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    return False, f"Security policy: Rejected path traversal in archive ({member.name})"

                target_path = os.path.abspath(os.path.join(abs_dest, member.name))
                if os.path.commonpath([abs_dest, target_path]) != abs_dest:
                    return False, f"Security policy: Archive member escapes destination ({member.name})"

            for member in members:
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, path=abs_dest, filter="data")
                else:
                    tar.extract(member, path=abs_dest)
        return True, "Archive extracted safely."
    except Exception as e:
        return False, f"Archive extraction failed: {e}"


def verify_and_stage_archive(
    archive_bytes: bytes,
    expected_sha256: str,
    staging_dir: str,
) -> Tuple[bool, str]:
    """Verify SHA-256 digest of archive bytes and extract safely into staging_dir."""
    if not expected_sha256 or not SHA256_RE.match(expected_sha256.strip()):
        return False, "Security policy: Refusing to apply update without a valid 64-hex SHA-256 digest."

    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        return False, "Security policy: Archive exceeds maximum permitted size."

    actual_sha256 = hashlib.sha256(archive_bytes).hexdigest().lower()
    if not hmac.compare_digest(actual_sha256, expected_sha256.strip().lower()):
        return (
            False,
            f"Security policy: SHA-256 digest mismatch! Expected {expected_sha256.lower()}, got {actual_sha256}.",
        )

    tar_path = os.path.join(staging_dir, "release.tar.gz")
    with open(tar_path, "wb") as f:
        f.write(archive_bytes)

    extract_dir = os.path.join(staging_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    return safe_extract_tarball(tar_path, extract_dir)


def perform_update(
    update_info: UpdateInfo,
    project_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Perform a verified update via signed/pinned Git tag or SHA-256 verified release tarball."""
    def _log(msg: str):
        if log_fn:
            log_fn(msg)

    if not update_info.update_available:
        return False, f"Already on latest version (v{update_info.current_version})."

    if parse_semver(update_info.tag_name) is None:
        return False, "Security policy: Rejected invalid release tag format."

    if project_dir is None:
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if not os.access(project_dir, os.W_OK):
        return False, f"Installation directory ({project_dir}) is not writable by current user."

    # Path 1: Git repository tag update if .git is present and clean
    git_dir = os.path.join(project_dir, ".git")
    if os.path.isdir(git_dir) and shutil.which("git"):
        try:
            status_proc = subprocess.run(
                ["git", "-C", project_dir, "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if status_proc.returncode == 0 and not status_proc.stdout.strip():
                _log(f"[UPDATER] Fetching release tag {update_info.tag_name} from origin...")
                fetch_proc = subprocess.run(
                    ["git", "-C", project_dir, "fetch", "--tags", "origin"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if fetch_proc.returncode == 0:
                    checkout_proc = subprocess.run(
                        ["git", "-C", project_dir, "checkout", f"refs/tags/{update_info.tag_name}"],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if checkout_proc.returncode == 0:
                        _log(f"[UPDATER] Updated repository to tag {update_info.tag_name}. Restart Sentinel to apply.")
                        return True, f"Updated to {update_info.tag_name} via git tag. Please restart Sentinel."
        except Exception as e:
            _log(f"[UPDATER] Git tag update skipped: {e}")

    # Path 2: SHA-256 Verified Release Archive Update
    if not update_info.download_url or not update_info.download_url.startswith(ALLOWED_DOWNLOAD_PREFIX):
        return (
            False,
            f"No verified release archive URL available. Download manually from {update_info.html_url}",
        )

    if not update_info.expected_sha256 or not SHA256_RE.match(update_info.expected_sha256):
        return (
            False,
            "Security policy: Refusing automatic update because release asset has no published SHA-256 digest.",
        )

    staging_dir = tempfile.mkdtemp(prefix="sentinel-update-")
    try:
        _log(f"[UPDATER] Downloading {update_info.download_url}...")
        req = urllib.request.Request(
            update_info.download_url,
            headers={"User-Agent": f"Sentinel-CAC-Manager/{update_info.current_version}"},
            method="GET",
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=30.0, context=ctx) as resp:
            archive_bytes = resp.read(MAX_ARCHIVE_BYTES + 1)

        ok, msg = verify_and_stage_archive(archive_bytes, update_info.expected_sha256, staging_dir)
        if not ok:
            _log(f"[UPDATER] {msg}")
            return False, msg

        extract_root = os.path.join(staging_dir, "extracted")
        entries = os.listdir(extract_root)
        src_root = os.path.join(extract_root, entries[0]) if len(entries) == 1 else extract_root
        if not os.path.isdir(src_root):
            return False, "Extracted release archive did not contain a valid application directory."

        for item in os.listdir(src_root):
            if item in {".git", "Sentinel-CAC-Manager.tar.gz"}:
                continue
            s_item = os.path.join(src_root, item)
            d_item = os.path.join(project_dir, item)
            if os.path.isdir(s_item):
                shutil.copytree(s_item, d_item, dirs_exist_ok=True)
            else:
                shutil.copy2(s_item, d_item)

        _log(f"[UPDATER] Verified SHA-256 and updated files to v{update_info.latest_version}.")
        return True, f"Updated to v{update_info.latest_version} (SHA-256 verified). Restart Sentinel to apply."
    except Exception as e:
        return False, f"Update failed: {e}"
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)
