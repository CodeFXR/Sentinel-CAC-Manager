"""Durable State and Ownership Ledger for Sentinel CAC Manager.

Tracks exact file paths, SHA-256 digests, pre-existing file backups, and pre-existing
JSON policy snapshots so uninstallation only removes or reverts state that Sentinel
actually created, and never deletes administrator-modified files.
"""

import hashlib
import json
import os
import tempfile
from typing import Any, Dict, Optional

DEFAULT_SYSTEM_MANIFEST = "/var/lib/sentinel/ownership_manifest.json"


def compute_file_sha256(filepath: str) -> Optional[str]:
    """Compute SHA-256 hex digest of a regular file."""
    try:
        from core.rust_bridge import compute_file_sha256_rust
        rust_sha = compute_file_sha256_rust(filepath)
        if rust_sha is not None:
            return rust_sha
    except Exception:
        pass

    if not os.path.isfile(filepath) or os.path.islink(filepath):
        return None
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest().lower()
    except OSError:
        return None


def load_ownership_manifest(manifest_path: str = DEFAULT_SYSTEM_MANIFEST) -> Dict[str, Any]:
    """Load the ownership manifest JSON or return a fresh structure."""
    default_data: Dict[str, Any] = {"files": {}, "firefox_policies": {}}
    if not os.path.isfile(manifest_path) or os.path.islink(manifest_path):
        return default_data
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data.setdefault("files", {})
            data.setdefault("firefox_policies", {})
            return data
    except Exception:
        pass
    return default_data


def save_ownership_manifest(data: Dict[str, Any], manifest_path: str = DEFAULT_SYSTEM_MANIFEST) -> bool:
    """Atomically write the ownership manifest JSON with mode 0600."""
    try:
        parent = os.path.dirname(os.path.abspath(manifest_path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=parent, delete=False, encoding="utf-8") as f_tmp:
            tmp_name = f_tmp.name
            json.dump(data, f_tmp, indent=2, sort_keys=True)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, manifest_path)
        return True
    except OSError:
        return False


def record_installed_file(
    target_path: str,
    installed_sha256: str,
    pre_existing_backup: Optional[str] = None,
    manifest_path: str = DEFAULT_SYSTEM_MANIFEST,
) -> None:
    """Record that Sentinel installed target_path with installed_sha256."""
    abs_target = os.path.abspath(target_path)
    data = load_ownership_manifest(manifest_path)
    existing_entry = data["files"].get(abs_target, {})
    # Preserve original pre_existing_backup across repeated installs
    backup_to_keep = existing_entry.get("pre_existing_backup") or pre_existing_backup
    data["files"][abs_target] = {
        "installed_sha256": installed_sha256.lower(),
        "pre_existing_backup": backup_to_keep,
    }
    save_ownership_manifest(data, manifest_path)


def record_firefox_policy_snapshot(
    policy_path: str,
    existed_before: bool,
    prior_policies_dict: Optional[Dict[str, Any]],
    manifest_path: str = DEFAULT_SYSTEM_MANIFEST,
) -> None:
    """Record the pre-Sentinel state of a Firefox policies.json file (only on first touch)."""
    abs_path = os.path.abspath(policy_path)
    data = load_ownership_manifest(manifest_path)
    if abs_path not in data["firefox_policies"]:
        data["firefox_policies"][abs_path] = {
            "existed_before": bool(existed_before),
            "prior_policies": prior_policies_dict if existed_before else None,
        }
        save_ownership_manifest(data, manifest_path)
