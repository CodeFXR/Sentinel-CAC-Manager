//! System Integrity, PKCS#11 Path Verification, OpenSC Config Parser, and Archive Safety Engine.
//!
//! Enforces CWE-74 injection rejection, root-owned (`UID 0`) non-world-writable PKCS#11 `.so`
//! verification, comment-aware OpenSC configuration inspection, streaming SHA-256 file hashing,
//! and tar-slip (CWE-22) / symlink / hardlink / device archive member inspection.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use crate::pki::{constant_time_hex_eq, Sha256Hasher};

/// Maximum single tar member size (50 MiB).
pub const MAX_ARCHIVE_MEMBER_BYTES: u64 = 50 * 1024 * 1024;

/// Allowed canonical directory prefixes for PKCS#11 shared libraries.
pub const ALLOWED_PKCS11_PREFIXES: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/lib",
    "/lib64",
];

/// Validate a PKCS#11 shared library path against CWE-74 injection, path traversal,
/// canonical directory restrictions, root ownership (`UID 0`), and writable-permission checks.
pub fn validate_pkcs11_module_path_rust(raw_path: &str) -> Result<String, String> {
    if raw_path.is_empty() {
        return Err("Empty PKCS#11 module path".to_string());
    }

    for ch in raw_path.chars() {
        let code = ch as u32;
        if code < 0x20 || code == 0x7f || matches!(ch, '"' | '\'' | '\\' | ';') {
            return Err(
                "Rejected PKCS#11 path containing control or delimiter characters".to_string(),
            );
        }
    }

    let input_path = Path::new(raw_path);
    if !input_path.is_absolute() {
        return Err("PKCS#11 module path must be an absolute path".to_string());
    }
    if input_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("PKCS#11 module path must not contain '..' traversal segments".to_string());
    }
    if !raw_path.contains(".so") {
        return Err("PKCS#11 module path must reference a '.so' shared object".to_string());
    }

    let real_path = fs::canonicalize(input_path)
        .map_err(|_| format!("PKCS#11 module does not exist on disk: {}", raw_path))?;
    let real_str = real_path
        .to_str()
        .ok_or_else(|| "PKCS#11 canonical path is not valid UTF-8".to_string())?
        .to_string();

    if !real_str.contains(".so") {
        return Err(format!(
            "Resolved PKCS#11 path does not reference a '.so' shared object: {}",
            real_str
        ));
    }

    let in_allowed_prefix = ALLOWED_PKCS11_PREFIXES.iter().any(|prefix| {
        real_str == *prefix
            || real_str
                .strip_prefix(prefix)
                .map(|rest| rest.starts_with('/'))
                .unwrap_or(false)
    });
    if !in_allowed_prefix {
        return Err(format!(
            "PKCS#11 module path outside trusted system library directories: {}",
            real_str
        ));
    }

    let meta = fs::metadata(&real_path)
        .map_err(|e| format!("Cannot stat PKCS#11 module '{}': {}", real_str, e))?;
    if !meta.is_file() {
        return Err(format!("PKCS#11 module is not a regular file: {}", real_str));
    }
    if meta.uid() != 0 {
        return Err(format!(
            "Security: Rejected PKCS#11 module not owned by root (uid={}): {}",
            meta.uid(),
            real_str
        ));
    }
    if (meta.mode() & 0o022) != 0 {
        return Err(format!(
            "Security: Rejected group- or world-writable PKCS#11 module (mode={:o}): {}",
            meta.mode() & 0o777,
            real_str
        ));
    }

    Ok(real_str)
}

/// Inspect `opensc.conf` text (stripping `#` comments) to verify CAC driver and transaction settings.
pub fn is_opensc_config_optimized_rust(content: &str) -> bool {
    let mut active_lines = Vec::new();
    for raw_line in content.lines() {
        let uncommented = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let trimmed = uncommented.trim();
        if !trimmed.is_empty() {
            active_lines.push(trimmed);
        }
    }
    if active_lines.is_empty() {
        return false;
    }

    let joined = active_lines.join(" ");
    let mut collapsed = String::with_capacity(joined.len());
    let mut prev_space = false;
    for ch in joined.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                collapsed.push(' ');
                prev_space = true;
            }
        } else {
            collapsed.push(ch);
            prev_space = false;
        }
    }

    // Verify `card_drivers = ...` includes `piv-II` or `cac`
    let mut has_piv_ii = false;
    let mut has_cac_driver = false;
    for stmt in collapsed.split(';') {
        if let Some(idx) = stmt.find("card_drivers") {
            let after = &stmt[idx + "card_drivers".len()..];
            if let Some(eq_idx) = after.find('=') {
                let rhs = &after[eq_idx + 1..];
                for tok in rhs.split(|c: char| c == ',' || c.is_whitespace()) {
                    let clean = tok.trim();
                    if clean.eq_ignore_ascii_case("piv-ii") {
                        has_piv_ii = true;
                    }
                    if clean.eq_ignore_ascii_case("cac") {
                        has_cac_driver = true;
                    }
                }
            }
        }
    }

    if has_piv_ii {
        return true;
    }

    let has_disconnect_or_lock = collapsed.contains("disconnect_action = reset")
        || collapsed.contains("disconnect_action=reset")
        || collapsed.contains("lock_login = false")
        || collapsed.contains("lock_login=false");

    has_cac_driver && has_disconnect_or_lock
}

/// Compute streaming lowercase SHA-256 hex digest of a regular file (rejecting symlinks).
pub fn compute_file_sha256_rust(filepath: &str) -> Option<String> {
    let path = Path::new(filepath);
    let sym_meta = fs::symlink_metadata(path).ok()?;
    if sym_meta.file_type().is_symlink() || !sym_meta.is_file() {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex_str = String::with_capacity(64);
    for b in &digest {
        hex_str.push_str(&format!("{:02x}", b));
    }
    Some(hex_str)
}

/// Verify that `archive_bytes` matches a 64-hex `expected_sha256` in constant time.
pub fn verify_bytes_sha256_rust(
    archive_bytes: &[u8],
    expected_sha256: &str,
    max_bytes: usize,
) -> Result<String, String> {
    let expected = expected_sha256.trim();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "Security policy: Refusing to stage archive without a valid 64-hex SHA-256 digest."
                .to_string(),
        );
    }
    if archive_bytes.len() > max_bytes {
        return Err("Security policy: Archive exceeds maximum permitted size.".to_string());
    }

    let mut hasher = Sha256Hasher::new();
    hasher.update(archive_bytes);
    let digest = hasher.finalize();
    let mut actual = String::with_capacity(64);
    for b in &digest {
        actual.push_str(&format!("{:02x}", b));
    }

    if !constant_time_hex_eq(&actual, expected) {
        return Err(format!(
            "Security policy: SHA-256 digest mismatch! Expected {}, got {}.",
            expected.to_ascii_lowercase(),
            actual
        ));
    }
    Ok(actual)
}

/// Normalize a relative path lexically without touching the filesystem, returning `None` if it escapes root.
fn normalize_relative_lexical(rel_path: &str) -> Option<Vec<String>> {
    if rel_path.is_empty() || rel_path.starts_with('/') || rel_path.contains('\0') {
        return None;
    }
    let mut stack: Vec<String> = Vec::new();
    for part in rel_path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        stack.push(part.to_string());
    }
    if stack.is_empty() {
        return None;
    }
    Some(stack)
}

/// Inspect a tar archive member's metadata for tar-slip (CWE-22), hardlinks, escaping symlinks, and special devices.
pub fn validate_tar_member_safety_rust(
    member_name: &str,
    is_hardlink: bool,
    is_symlink: bool,
    is_device_or_fifo: bool,
    linkname: &str,
    size: u64,
) -> Result<(), String> {
    if is_hardlink {
        return Err(format!(
            "Security policy: Rejected hard link in archive ({})",
            member_name
        ));
    }
    if is_device_or_fifo {
        return Err(format!(
            "Security policy: Rejected special device file in archive ({})",
            member_name
        ));
    }
    if size > MAX_ARCHIVE_MEMBER_BYTES {
        return Err(format!(
            "Security policy: Archive member exceeds size limit ({})",
            member_name
        ));
    }
    if member_name.starts_with('/') || member_name.split('/').any(|p| p == "..") {
        return Err(format!(
            "Security policy: Rejected path traversal in archive ({})",
            member_name
        ));
    }
    let Some(mut member_parts) = normalize_relative_lexical(member_name) else {
        return Err(format!(
            "Security policy: Archive member escapes destination ({})",
            member_name
        ));
    };

    if is_symlink {
        if linkname.is_empty()
            || linkname.starts_with('/')
            || linkname.contains('\0')
            || linkname.split('/').any(|p| p == "..")
        {
            return Err(format!(
                "Security policy: Rejected unsafe symbolic link in archive ({})",
                member_name
            ));
        }
        // Remove filename component to get parent directory depth
        member_parts.pop();
        for seg in linkname.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                if member_parts.pop().is_none() {
                    return Err(format!(
                        "Security policy: Symbolic link escapes destination ({})",
                        member_name
                    ));
                }
            } else {
                member_parts.push(seg.to_string());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opensc_config_parser() {
        let valid_cfg = r#"
        app default {
            # comment line
            card_drivers = cac, piv;
            framework pkcs15 {
                use_file_caching = true;
                lock_login = false;
            }
            reader_driver pcsc {
                disconnect_action = reset;
            }
        }
        "#;
        assert!(is_opensc_config_optimized_rust(valid_cfg));

        let commented_out = r#"
        app default {
            # card_drivers = cac;
            # disconnect_action = reset;
        }
        "#;
        assert!(!is_opensc_config_optimized_rust(commented_out));
    }

    #[test]
    fn test_tar_member_safety() {
        assert!(validate_tar_member_safety_rust(
            "Sentinel-CAC-Manager/core/updater.py",
            false,
            false,
            false,
            "",
            4096
        )
        .is_ok());

        assert!(validate_tar_member_safety_rust(
            "../etc/passwd",
            false,
            false,
            false,
            "",
            128
        )
        .is_err());

        assert!(validate_tar_member_safety_rust(
            "Sentinel-CAC-Manager/install.sh",
            false,
            true,
            false,
            "install",
            0
        )
        .is_ok());

        assert!(validate_tar_member_safety_rust(
            "Sentinel-CAC-Manager/evil_link",
            false,
            true,
            false,
            "/etc/shadow",
            0
        )
        .is_err());

        assert!(validate_tar_member_safety_rust(
            "Sentinel-CAC-Manager/hardlink",
            true,
            false,
            false,
            "install",
            0
        )
        .is_err());
    }

    #[test]
    fn test_pkcs11_path_rejection() {
        assert!(validate_pkcs11_module_path_rust("/usr/lib/opensc-pkcs11.so\nEvil: true").is_err());
        assert!(validate_pkcs11_module_path_rust("/tmp/evil-pkcs11.so").is_err());
        assert!(validate_pkcs11_module_path_rust("relative/opensc-pkcs11.so").is_err());
    }
}
