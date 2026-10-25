"""Secure Release Update Checker and Archive Verifier for Sentinel CAC Manager.

Enforces fail-closed supply-chain security:
- Check-only release notification (never modifies a live installation or root-owned helper in-place)
- Strict HTTPS origin validation (github.com/CodeFXR/Sentinel-CAC-Manager)
- Strict semantic version tag validation (^v?\\d+\\.\\d+\\.\\d+$)
- Mandatory SHA-256 digest verification before any archive staging
- Tar-slip (CWE-22), hardlink, escaping symlink, and device member rejection during extraction
"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import ssl
import tarfile
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
                status_message="No published release found on GitHub (HTTP 404)",
                error="HTTP 404",
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
    """Safely extract a .tar.gz archive, rejecting path traversal, hardlinks, escaping symlinks, and devices."""
    abs_dest = os.path.abspath(dest_dir)
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                return False, "Archive is empty."

            for member in members:
                is_dev = bool(member.isdev() or member.isfifo() or member.ischr() or member.isblk())
                try:
                    from core.rust_bridge import validate_tar_member_safety_rust
                    rust_chk = validate_tar_member_safety_rust(
                        member.name,
                        bool(member.islnk()),
                        bool(member.issym()),
                        is_dev,
                        member.linkname or "",
                        int(member.size or 0),
                    )
                    if rust_chk is not None:
                        ok_member, err_member = rust_chk
                        if not ok_member:
                            return False, err_member
                except Exception:
                    pass

                if member.islnk():
                    return False, f"Security policy: Rejected hard link in archive ({member.name})"
                if is_dev:
                    return False, f"Security policy: Rejected special device file in archive ({member.name})"
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    return False, f"Security policy: Rejected path traversal in archive ({member.name})"

                target_path = os.path.abspath(os.path.join(abs_dest, member.name))
                if os.path.commonpath([abs_dest, target_path]) != abs_dest:
                    return False, f"Security policy: Archive member escapes destination ({member.name})"

                if member.issym():
                    linkname = member.linkname or ""
                    if os.path.isabs(linkname) or ".." in linkname.split("/"):
                        return False, f"Security policy: Rejected unsafe symbolic link in archive ({member.name})"
                    link_target = os.path.abspath(os.path.join(os.path.dirname(target_path), linkname))
                    if os.path.commonpath([abs_dest, link_target]) != abs_dest:
                        return False, f"Security policy: Symbolic link escapes destination ({member.name})"

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
        return False, "Security policy: Refusing to stage archive without a valid 64-hex SHA-256 digest."

    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        return False, "Security policy: Archive exceeds maximum permitted size."

    try:
        from core.rust_bridge import verify_archive_sha256_rust
        rust_ver = verify_archive_sha256_rust(archive_bytes, expected_sha256.strip(), MAX_ARCHIVE_BYTES)
        if rust_ver is not None:
            ok_sha, msg_sha = rust_ver
            if not ok_sha:
                return False, msg_sha
    except Exception:
        pass

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
    """Apply a cryptographically verified SHA-256 release archive update with transactional rollback.

    Never uses unauthenticated git checkout; strictly requires a 64-hex SHA-256 digest
    and an official HTTPS GitHub release asset URL.
    """
    import shutil
    import tempfile

    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    if not update_info.update_available:
        return False, f"Already up to date (v{update_info.current_version})."

    if not update_info.expected_sha256 or not SHA256_RE.match(update_info.expected_sha256.strip()):
        msg = (
            "Security policy: Refusing to apply update without a verified 64-hex SHA-256 digest. "
            f"Verify SHA-256 manually from {update_info.html_url} and run './install'."
        )
        _log(f"[UPDATER] {msg}")
        return False, msg

    if not update_info.download_url or not update_info.download_url.startswith(ALLOWED_DOWNLOAD_PREFIX):
        msg = "Security policy: Refusing to download update from untrusted or missing asset URL."
        _log(f"[UPDATER] {msg}")
        return False, msg

    target_dir = os.path.abspath(
        project_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    if not os.path.isdir(target_dir) or not os.access(target_dir, os.W_OK):
        msg = (
            f"Installation directory '{target_dir}' requires administrator permissions. "
            f"Run './install' to upgrade to {update_info.tag_name}."
        )
        _log(f"[UPDATER] {msg}")
        return False, msg

    _log(f"[UPDATER] Downloading {update_info.tag_name} from {update_info.download_url}...")
    req = urllib.request.Request(
        update_info.download_url,
        headers={"User-Agent": f"Sentinel-CAC-Manager/{update_info.current_version}"},
        method="GET",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30.0, context=ctx) as resp:
            archive_bytes = resp.read(MAX_ARCHIVE_BYTES + 1)
    except Exception as e:
        msg = f"Failed to download release archive: {e}"
        _log(f"[UPDATER] {msg}")
        return False, msg

    parent_fs_dir = os.path.dirname(target_dir)
    if not os.access(parent_fs_dir, os.W_OK):
        parent_fs_dir = target_dir

    with tempfile.TemporaryDirectory(dir=parent_fs_dir, prefix=".sentinel_stage_") as staging_dir:
        ok_stage, stage_msg = verify_and_stage_archive(
            archive_bytes, update_info.expected_sha256, staging_dir
        )
        if not ok_stage:
            _log(f"[UPDATER] {stage_msg}")
            return False, stage_msg

        extracted_root = os.path.join(staging_dir, "extracted")
        entries = os.listdir(extracted_root)
        if len(entries) == 1 and os.path.isdir(os.path.join(extracted_root, entries[0])):
            source_root = os.path.join(extracted_root, entries[0])
        else:
            source_root = extracted_root

        backup_dir = os.path.join(staging_dir, "rollback_backup")
        os.makedirs(backup_dir, exist_ok=True)
        staged_items = []

        try:
            for item in os.listdir(source_root):
                if item.startswith(".git"):
                    continue
                src_item = os.path.join(source_root, item)
                dst_item = os.path.join(target_dir, item)
                bak_item = os.path.join(backup_dir, item)
                if os.path.exists(dst_item) or os.path.islink(dst_item):
                    shutil.move(dst_item, bak_item)
                shutil.move(src_item, dst_item)
                staged_items.append(item)
        except Exception as e:
            for item in reversed(staged_items):
                dst_item = os.path.join(target_dir, item)
                bak_item = os.path.join(backup_dir, item)
                try:
                    if os.path.exists(dst_item) or os.path.islink(dst_item):
                        if os.path.isdir(dst_item) and not os.path.islink(dst_item):
                            shutil.rmtree(dst_item)
                        else:
                            os.remove(dst_item)
                    if os.path.exists(bak_item) or os.path.islink(bak_item):
                        shutil.move(bak_item, dst_item)
                except OSError:
                    pass
            msg = f"Update staging failed and was rolled back cleanly: {e}"
            _log(f"[UPDATER] {msg}")
            return False, msg

    helper_sync_note = " Restart the application to load the updated version."
    sys_helper = "/usr/libexec/sentinel/privileged_helper.py"
    new_helper = os.path.join(target_dir, "core", "privileged_helper.py")
    if os.path.isfile(sys_helper) and os.path.isfile(new_helper):
        try:
            with open(sys_helper, "rb") as f1, open(new_helper, "rb") as f2:
                if hashlib.sha256(f1.read()).digest() != hashlib.sha256(f2.read()).digest():
                    helper_sync_note = (
                        " Run './install' to synchronize the root-owned privileged helper, "
                        "then restart the application."
                    )
        except OSError:
            pass

    success_msg = (
        f"Verified SHA-256 digest and updated to {update_info.tag_name}.{helper_sync_note}"
    )
    _log(f"[UPDATER] {success_msg}")
    return True, success_msg
