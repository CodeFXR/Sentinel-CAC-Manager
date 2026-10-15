# Sentinel CAC Manager — Security Remediation & Implementation Plan

> **Audit Source:** [security_scan.md](file:///home/jvm/projects/sentinel_cac_manager/security_scan.md)  
> **Status:** Assessment & Remediation Plan (Pre-Implementation Review)  
> **Target Scope:** 8 Findings (6 Medium, 2 Low) across CLI, Desktop Integration, UI, and Privileged Helper.

---

## 1. Executive Summary & Assessment Overview

A comprehensive security audit of Sentinel CAC Manager revealed **8 security findings**:
- **6 Medium Severity:** Local privilege escalation vectors, shell/desktop argument injections, and untrusted bootstrap execution.
- **2 Low Severity:** Pango markup injection in GTK/Libadwaita UI and terminal control character injection in CLI outputs.

### Findings Breakdown by CWE & Component

| ID | Title / Vulnerability | Location | Severity | CWE | Finding Needed? |
|:---|:---|:---|:---:|:---:|:---:|
| **F-01** | UI Pango Markup Injection | `ui/dashboard_view.py:194-196`, `ui/cards_view.py:57` | **Low** | CWE-116 | **YES** |
| **F-02** | Terminal Control Sequence Injection | `cli.py:56, 75`, `core/smartcard.py:242` | **Low** | CWE-150 | **YES** (Hardening) |
| **F-03** | Standalone Bootstrap Untrusted Script Execution | `setup:14` | **Medium** | CWE-829 | **YES** |
| **F-04** | Desktop Entry Argument Injection (Unquoted Path) | `install.sh:94`, `core/system_fix.py:222` | **Medium** | CWE-88 | **YES** |
| **F-05** | Shell Script Launcher Heredoc Path Injection | `install.sh:78` | **Medium** | CWE-78 | **YES** |
| **F-06** | Python-Generated Bash Launcher Path Injection | `core/system_fix.py:193` | **Medium** | CWE-78 | **YES** |
| **F-07** | Elevation of User-Writable Script via pkexec | `core/system_fix.py:58-64` | **Medium** | CWE-829 | **YES** (Critical) |
| **F-08** | SUID / Permissions Preservation in Root Helper | `core/privileged_helper.py:92-95` | **Medium** | CWE-732 | **YES** (Critical) |

---

## 2. Evaluation: "Is It Needed?" & Audit Assumptions Analysis

The audit document states:
> *"Findings that rely on assumptions are published at medium severity at most. If an assumption does not hold for your deployment, dismiss this finding."*

Before modifying code in the next session, each finding and its underlying assumptions are evaluated below to determine if any can be dismissed, or why they must be addressed.

---

### Finding F-01: UI Pango Markup Injection (CWE-116 — Low)
* **Underlying Assumption:** `A4 (Third-party behavior)` — System OpenSSL outputs raw distinguished names without markup encoding; Libadwaita `ActionRow` subtitles and `PreferencesGroup` titles parse Pango markup by default.
* **Is the fix needed?** **YES.**
* **Evaluation / Why it cannot be dismissed:**
  1. Libadwaita `ActionRow.set_subtitle()` and `PreferencesGroup.set_title()` / `set_description()` strictly interpret Pango markup by default in GTK4.
  2. If a certificate or token string contains reserved XML characters (`&`, `<`, `>`, `'`, `"`), Pango fails to parse the markup, emits runtime warnings, and **fails to display the label/subtitle** on screen.
  3. Real-world DoD/DoW certificates often contain ampersands (`&`) in organizational unit or issuer names (e.g., `DoD R&D CA-62` or `Command & Control`).
  4. In `ui/cards_view.py:70-74`, the application already escapes certificate expander row labels with `GLib.markup_escape_text()`, but omitted doing so on `cards_view.py:57-60` and `dashboard_view.py:180, 194-196`. This inconsistency makes fixing it essential.
* **Dismissal Criteria:** Could only be dismissed if Libadwaita disabled markup globally on these widgets (which it does not) or if smart card metadata were strictly filtered by OpenSC to plain alphanumerics (which it is not).

---

### Finding F-02: Terminal Control Sequence Injection (CWE-150 — Low)
* **Underlying Assumptions:**
  * `A2 (Attacker-controlled input)`: The smart card token label supplied by an inserted device is lower-trust input.
  * `A4 (Third-party behavior)`: `pkcs11-tool` displays token label contents without filtering escape sequences (ESC `\x1b`, BEL `\x07`, CR `\r`).
* **Is the fix needed?** **YES (Defensive Hardening).**
* **Evaluation / Why it cannot be dismissed:**
  * In a theoretical environment where users only ever insert physical government-issued CACs in high-security scifs, one might consider untrusted smart cards improbable.
  * However, workstations running Sentinel can have arbitrary USB devices, YubiKeys, virtual smart cards (`vpcd`), or rogue smart cards plugged in.
  * Modern terminal emulators supporting OSC 52 (clipboard write) or cursor repositioning sequences can allow an inserted rogue card with a crafted token label to overwrite terminal scrollback, spoof diagnostic output, or alter clipboard contents when running `sentinel status` or `sentinel card-info`.
  * Sanitizing control characters before printing to stdout adds zero runtime overhead and prevents terminal manipulation.
* **Dismissal Criteria:** Can be dismissed ONLY if the threat model explicitly declares physical USB/smart card reader hardware as 100% authenticated and trusted at all times prior to insertion. For general DoD Linux deployment, this cannot be assumed.

---

### Finding F-03: Standalone Bootstrap Untrusted Script Execution (CWE-829 — Medium)
* **Underlying Assumptions:** None (Direct logic flaw).
* **Is the fix needed?** **YES.**
* **Evaluation / Why it cannot be dismissed:**
  * In `setup`, the script checks:
    ```bash
    if [ -f "${SCRIPT_DIR}/installer.py" ]; then
        exec python3 "${SCRIPT_DIR}/installer.py" "$@"
    fi
    ```
  * `setup` is distributed as a standalone web bootstrapper (`curl ... | bash` or downloaded to `~/Downloads`). If a user downloads `setup` into `~/Downloads`, and an unrelated or malicious `installer.py` exists in that directory, `setup` will execute that foreign code under the user's account without downloading Sentinel.
  * Checking only for the filename `installer.py` without verifying repository context (e.g. checking for `sentinel_cac_manager.py` and `core/platform_detector.py`) is unsafe.
* **Dismissal Criteria:** Would only be dismissible if `setup` were never marketed or distributed as a standalone download outside a dedicated git checkout. Since standalone bootstrapping is an advertised feature of `setup`, it must be remediated.

---

### Finding F-04: Desktop Entry Argument Splitting / Injection (CWE-88 — Medium)
* **Underlying Assumption:** `A4 (Third-party behavior)` — Desktop launchers (GNOME Shell, KDE KLauncher, XFCE) parse `Exec=` lines following the FreeDesktop.org Desktop Entry Specification where unquoted whitespace separates arguments.
* **Is the fix needed?** **YES.**
* **Evaluation / Why it cannot be dismissed:**
  * The FreeDesktop Desktop Entry Specification explicitly dictates that whitespace separates arguments unless enclosed in double quotes.
  * `install.sh:94` and `core/system_fix.py:222` emit:
    `Exec=python3 ${SCRIPT_DIR}/sentinel_cac_manager.py --gui`
  * If a user installs or clones Sentinel to a directory containing spaces (e.g., `/home/user/DoD Projects/Sentinel-CAC-Manager`), desktop launchers parse `/home/user/DoD` as the script argument. If an unprivileged user or malicious binary exists at `/home/user/DoD`, clicking the application launcher executes that file.
  * Furthermore, unquoted paths fail to launch completely on GNOME/KDE when spaces exist.
* **Dismissal Criteria:** Dismissible only if installation paths were restricted by the OS to paths without whitespace (e.g., `/opt/sentinel`), which is not enforced by user-level installations (`~/.local/share/sentinel_cac_manager`).

---

### Findings F-05 & F-06: Shell & Python Launcher Heredoc Path Injection (CWE-78 — Medium)
* **Underlying Assumptions:** None (Direct syntax interpolation flaws).
* **Is the fix needed?** **YES.**
* **Evaluation / Why it cannot be dismissed:**
  * In `install.sh:78`, `cat <<EOF` expands `${SCRIPT_DIR}` directly into the wrapper script.
  * In `core/system_fix.py:193`, Python f-string interpolation formats `"{project_dir}/sentinel_cac_manager.py"` into a bash script.
  * If the path contains backticks, `$(...)`, or quote characters, arbitrary commands will execute upon script generation or when the wrapper runs.
  * Standard Unix defensive programming requires shell escaping (`printf %q` in bash, `shlex.quote()` in Python).
* **Dismissal Criteria:** Cannot be dismissed.

---

### Finding F-07: Elevation of User-Writable Script via pkexec (CWE-829 — Medium / High Impact)
* **Underlying Assumptions:** None (Privilege escalation vector).
* **Is the fix needed?** **YES (Critical Architecture Item).**
* **Evaluation / Why it cannot be dismissed:**
  * Sentinel currently executes:
    `pkexec python3 ~/.local/share/sentinel_cac_manager/core/privileged_helper.py ...`
  * `privileged_helper.py` resides inside the user's home directory (`~/.local/share/...`), which is fully writable by the unprivileged user and any unprivileged processes running under that user account.
  * If an unprivileged background process or malware modifies `privileged_helper.py`, the next time Sentinel prompts the user for root authorization (via Polkit) to configure `pcscd` or certificates, the user enters their password and the modified user script executes as **full root**.
  * Executing user-writable scripts via `pkexec` completely circumvents Polkit's security boundaries.
* **Dismissal Criteria:** Dismissible ONLY if Sentinel is packaged as a system `.deb`/`.rpm` package where all code is placed under root-owned `/usr/lib/` or `/usr/share/`. Because Sentinel supports standalone user git checkouts and user installs, this must be solved architecturally.

---

### Finding F-08: Permissions & SUID Mode Preservation in Root Helper (CWE-732 — Medium / High Impact)
* **Underlying Assumptions:** None (Direct Local Privilege Escalation).
* **Is the fix needed?** **YES (Critical Security Fix).**
* **Evaluation / Why it cannot be dismissed:**
  * In `core/privileged_helper.py:92`, the root helper runs:
    ```python
    shutil.copy2(src, dst)
    ```
    where `src` comes from `~/.local/share/sentinel_cac_manager/certificates/all_cas/*.crt` and `dst` is `/usr/local/share/ca-certificates/dow/*.crt`.
  * `shutil.copy2` **preserves all source file permission bits**, including the setuid (`04000`) and setgid (`02000`) bits.
  * An unprivileged user can create an executable binary, name it `evil.crt`, set permissions to `04755` (`chmod 4755 certificates/all_cas/evil.crt`), and trigger the root helper.
  * The root helper copies `evil.crt` into `/usr/local/share/ca-certificates/dow/evil.crt` owned by `root:root` with mode `04755` (SetUID Root). The unprivileged user now has an instant root shell by executing the copied binary.
  * Additionally, the helper does not validate whether files are valid X.509 certificates.
* **Dismissal Criteria:** Under no circumstances can this finding be dismissed. It represents a direct, reproducible local root exploit.

---

## 3. Detailed Technical Remediation Plan

---

### Finding F-01: UI Pango Markup Escaping
* **Target Files:**
  * [`ui/dashboard_view.py`](file:///home/jvm/projects/sentinel_cac_manager/ui/dashboard_view.py#L180-L200)
  * [`ui/cards_view.py`](file:///home/jvm/projects/sentinel_cac_manager/ui/cards_view.py#L55-L65)

#### Proposed Code Changes:
1. In `ui/dashboard_view.py`:
   Ensure `GLib` is imported (`from gi.repository import GLib, Gtk, Adw`).
   Sanitize dynamic cardholder and certificate fields before passing them to `set_subtitle()`:
   ```python
   # Lines 180, 193-196:
   card_name = GLib.markup_escape_text(card_stat.card_name or "Common Access Card")
   token_serial = GLib.markup_escape_text(card_stat.token_serial or "Active")
   self.card_row.set_subtitle(f"{card_name} (Serial: {token_serial})")
   ...
   if card_stat.card_present and prim_cert:
       holder_name = GLib.markup_escape_text(prim_cert.holder_name or "DoW Cardholder")
       edipi = GLib.markup_escape_text(prim_cert.edipi or "Verified on Card")
       issuer_cn = GLib.markup_escape_text(prim_cert.issuer_cn or "Unknown")
       status_text = GLib.markup_escape_text(prim_cert.status_text or "")
       
       self.holder_row.set_subtitle(holder_name)
       self.edipi_row.set_subtitle(edipi)
       self.cert_status_row.set_subtitle(f"{status_text} (Issuer: {issuer_cn})")
   ```

2. In `ui/cards_view.py`:
   Sanitize header group title and description:
   ```python
   # Lines 57-60:
   token_label = GLib.markup_escape_text(card_stat.token_label or "DoW CAC")
   reader_name = GLib.markup_escape_text(card_stat.reader_name or "PCSC")
   token_serial = GLib.markup_escape_text(card_stat.token_serial or "Active")
   atr = GLib.markup_escape_text(card_stat.atr or "N/A")

   header_group.set_title(f"Inserted Card: {token_label}")
   header_group.set_description(
       f"Reader: {reader_name} | Serial: {token_serial} | ATR: {atr}"
   )
   ```

---

### Finding F-02: Terminal Output Control Character Sanitization
* **Target Files:**
  * [`cli.py`](file:///home/jvm/projects/sentinel_cac_manager/cli.py#L50-L87)
  * [`core/smartcard.py`](file:///home/jvm/projects/sentinel_cac_manager/core/smartcard.py#L240-L255)

#### Proposed Code Changes:
1. In `cli.py`, introduce a utility function `sanitize_terminal_str()`:
   ```python
   import re

   def sanitize_terminal_str(val: Any) -> str:
       """Sanitize strings for terminal display by stripping ANSI escapes and non-printable control chars."""
       if val is None:
           return ""
       s = str(val)
       # Remove ANSI escape sequences (CSI, OSC, etc.)
       s = re.sub(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', s)
       # Replace ASCII control characters (0-31 except tab/newline, and DEL 127) with visible escaped representation
       clean_chars = []
       for ch in s:
           code = ord(ch)
           if ch in ("\t", "\n") or (32 <= code < 127) or (code >= 160):
               clean_chars.append(ch)
           else:
               clean_chars.append(f"\\x{code:02x}")
       return "".join(clean_chars)
   ```
2. Apply `sanitize_terminal_str()` across `cmd_status()` and `cmd_card_info()` for all device/cardholder strings:
   ```python
   print(f"  Reader:                {sanitize_terminal_str(card_stat.reader_name) or 'No reader found'}")
   print(f"  Token Label:           {sanitize_terminal_str(card_stat.token_label) or 'Unknown'}")
   print(f"  Cardholder Name:       {sanitize_terminal_str(prim_cert.holder_name) if prim_cert else 'Unknown'}")
   ```

---

### Finding F-03: Secure Standalone Bootstrap Origin Verification
* **Target File:**
  * [`setup`](file:///home/jvm/projects/sentinel_cac_manager/setup#L12-L16)

#### Proposed Code Changes:
Modify `setup` to verify that the local directory is an authentic Sentinel checkout before executing `installer.py`, rather than assuming any neighboring file named `installer.py` is trusted:
```bash
# 1. Only execute local installer if this is verified to be an authentic Sentinel checkout
IS_AUTHENTIC_CHECKOUT=false
if [ -f "${SCRIPT_DIR}/installer.py" ] && \
   [ -f "${SCRIPT_DIR}/sentinel_cac_manager.py" ] && \
   [ -d "${SCRIPT_DIR}/core" ]; then
    IS_AUTHENTIC_CHECKOUT=true
fi

if [ "${IS_AUTHENTIC_CHECKOUT}" = "true" ]; then
    exec python3 "${SCRIPT_DIR}/installer.py" "$@"
fi

# 2. Standalone web bootstrapper mode: Download into dedicated target directory
echo "[*] Initializing Sentinel CAC Manager installer..."
mkdir -p "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${REPO_URL}" | tar -xz -C "${INSTALL_DIR}" --strip-components=1
elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${REPO_URL}" | tar -xz -C "${INSTALL_DIR}" --strip-components=1
else
    echo "[-] Error: curl or wget required to download Sentinel CAC Manager."
    exit 1
fi

exec python3 "${INSTALL_DIR}/installer.py" "$@"
```

---

### Finding F-04: Desktop Entry Argument Quoting
* **Target Files:**
  * [`install.sh`](file:///home/jvm/projects/sentinel_cac_manager/install.sh#L90-L98)
  * [`core/system_fix.py`](file:///home/jvm/projects/sentinel_cac_manager/core/system_fix.py#L218-L232)

#### Proposed Code Changes:
1. In `install.sh`:
   Quote and escape the script path in `Exec=` according to Desktop Entry specifications:
   ```bash
   ESCAPED_SCRIPT_PATH=$(echo "${SCRIPT_DIR}/sentinel_cac_manager.py" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g')
   cat <<EOF > "${APP_DIR}/sentinel_cac_manager.desktop"
   [Desktop Entry]
   Name=Sentinel CAC Manager
   GenericName=DoW Smart Card Manager
   Comment=Automate DoW CAC Middleware, Certificates, and Browser Authentication
   Exec=python3 "${ESCAPED_SCRIPT_PATH}" --gui
   Path=${SCRIPT_DIR}
   Icon=${ICON_DIR}/sentinel_cac_manager.png
   Terminal=false
   Type=Application
   Categories=Utility;Security;
   Keywords=CAC;PIV;DoW;SmartCard;Military;Security;Authentication;
   StartupNotify=true
   StartupWMClass=mil.dow.sentinel_cac_manager
   EOF
   ```

2. In `core/system_fix.py`:
   ```python
   script_path = os.path.join(project_dir, "sentinel_cac_manager.py").replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
   desktop_content = f"""[Desktop Entry]
   Name=Sentinel CAC Manager
   GenericName=DoW Smart Card Manager
   Comment=Automate DoW CAC Middleware, Certificates, and Browser Authentication
   Exec=python3 "{script_path}" --gui
   Path={project_dir}
   Icon={icon_path}
   Terminal=false
   Type=Application
   Categories=Utility;Security;
   Keywords=CAC;PIV;DoW;SmartCard;Military;Security;Authentication;
   StartupNotify=true
   StartupWMClass=mil.dow.sentinel_cac_manager
   """
   ```

---

### Finding F-05: Shell Script Launcher Path Escaping in install.sh
* **Target File:**
  * [`install.sh`](file:///home/jvm/projects/sentinel_cac_manager/install.sh#L76-L80)

#### Proposed Code Changes:
Encode the script path using Bash `printf %q`:
```bash
# 5. Create launcher symlinks in ~/.local/bin
ESCAPED_EXEC_TARGET=$(printf '%q' "${SCRIPT_DIR}/sentinel_cac_manager.py")
cat <<EOF > "${BIN_DIR}/sentinel-cac-manager"
#!/usr/bin/env bash
exec python3 ${ESCAPED_EXEC_TARGET} "\$@"
EOF
chmod +x "${BIN_DIR}/sentinel-cac-manager"
```

---

### Finding F-06: Python Launcher Script Path Escaping in core/system_fix.py
* **Target File:**
  * [`core/system_fix.py`](file:///home/jvm/projects/sentinel_cac_manager/core/system_fix.py#L190-L198)

#### Proposed Code Changes:
Use Python's built-in `shlex.quote`:
```python
import shlex

launcher_target = shlex.quote(os.path.join(project_dir, "sentinel_cac_manager.py"))
launcher_script = f"""#!/usr/bin/env bash
exec python3 {launcher_target} "$@"
"""
with open(launcher_path, "w") as f:
    f.write(launcher_script)
os.chmod(launcher_path, 0o755)
```

---

### Finding F-07: Elevation of Privileged Helper via pkexec
* **Target Files:**
  * [`core/system_fix.py`](file:///home/jvm/projects/sentinel_cac_manager/core/system_fix.py#L40-L65)
  * [`core/privileged_helper.py`](file:///home/jvm/projects/sentinel_cac_manager/core/privileged_helper.py)
  * System Polkit Policy file (to be added)

#### Architecture Analysis & Strategy:
* **The Root Cause:** Running `pkexec python3 <path-under-home-directory>` executes an unprivileged script as root. A compromised user process could modify the script prior to the user entering their Polkit password.
* **Remediation Strategy:**
  1. **Fixed Root-Owned System Helper:** Install `privileged_helper.py` to `/usr/local/libexec/sentinel-cac-manager/sentinel-helper` owned by `root:root` with mode `0755`.
  2. **Dedicated Polkit Action:** Provide `/usr/share/polkit-1/actions/mil.dow.sentinel.policy` that authorizes only this specific executable.
  3. **Fallback & Installation Flow:**
     - In `system_fix.py`, check if the system-installed helper `/usr/local/libexec/sentinel-cac-manager/sentinel-helper` exists and is owned by `root` (`os.stat().st_uid == 0`).
     - If not installed, prompt the user to install the helper once (or during `install.sh` running with sudo/initial setup).
     - If running in development mode where the helper is still in the user directory: verify script SHA-256 integrity or execute via a secure root copy mechanism that creates a temporary root-owned file before launching.

---

### Finding F-08: SUID/Permissions Preservation in Certificate Store Copy
* **Target File:**
  * [`core/privileged_helper.py`](file:///home/jvm/projects/sentinel_cac_manager/core/privileged_helper.py#L81-L113)

#### Proposed Code Changes:
Replace `shutil.copy2` with a hardened certificate validation and writing function:
1. **Never copy raw file permissions.** Enforce strict `0644` permissions for all installed certificates.
2. **Validate X.509 structure.** Refuse to install any file that is not a valid PEM or DER certificate.
3. **Reject symlinks and non-regular files.**

```python
def safe_install_certificate(src_path: str, dst_path: str) -> bool:
    """Validate X.509 certificate data and write to destination with fixed 0644 mode.
    
    Prevents mode preservation (SUID/executable bits) and symlink traversal.
    """
    if os.path.islink(src_path) or not os.path.isfile(src_path):
        log(f"Skipping non-regular file or symlink: {src_path}")
        return False

    try:
        with open(src_path, "rb") as f:
            cert_bytes = f.read()
    except Exception as e:
        log(f"Failed to read certificate source {src_path}: {e}")
        return False

    # 1. Structure Verification: Ensure valid PEM or DER X.509 certificate
    is_pem = b"-----BEGIN CERTIFICATE-----" in cert_bytes
    is_der = False
    if not is_pem and len(cert_bytes) > 4:
        # Check DER ASN.1 SEQUENCE header (0x30, followed by length bytes 0x81/0x82/0x83)
        if cert_bytes[0] == 0x30 and cert_bytes[1] in (0x81, 0x82, 0x83):
            is_der = True

    if not (is_pem or is_der):
        log(f"WARNING: File {src_path} is NOT a valid X.509 certificate! Refusing to install.")
        return False

    # 2. Secure Write with fixed mode 0644 (no SetUID/exec bits preserved)
    try:
        # If destination exists as a symlink, remove it first
        if os.path.islink(dst_path):
            os.unlink(dst_path)

        # Use os.open with O_NOFOLLOW, O_CREAT, O_TRUNC to prevent symlink race attacks
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(dst_path, flags, 0o644)
        with os.fdopen(fd, "wb") as f_out:
            f_out.write(cert_bytes)

        # Explicitly enforce 0644 in case umask interfered
        os.chmod(dst_path, 0o644)
        return True
    except Exception as e:
        log(f"Failed to securely write certificate {dst_path}: {e}")
        return False
```

Update `install_system_certificates()`:
```python
# In install_system_certificates(distro_family: str):
if distro_family == "debian":
    target_dir = "/usr/local/share/ca-certificates/dow"
    os.makedirs(target_dir, exist_ok=True)
    count = 0
    if os.path.isdir(ALL_CAS_DIR):
        for fname in sorted(os.listdir(ALL_CAS_DIR)):
            if fname.endswith(".crt"):
                src = os.path.join(ALL_CAS_DIR, fname)
                dst = os.path.join(target_dir, fname)
                if safe_install_certificate(src, dst):
                    count += 1
    log(f"Securely installed {count} CA certificates to {target_dir}")
    ...
elif distro_family == "fedora":
    target_dir = "/etc/pki/ca-trust/source/anchors"
    os.makedirs(target_dir, exist_ok=True)
    dst = os.path.join(target_dir, "DoW_Full_Chain.pem")
    safe_install_certificate(FULL_CHAIN_PEM, dst)
    ...
```

---

## 4. Implementation Phases for Next Session

The remediation should be executed in 4 logical phases:

### Phase 1: High-Risk Privilege Escalation & Helper Hardening
* **Files:** `core/privileged_helper.py`, `core/system_fix.py`
* **Tasks:**
  1. Replace `shutil.copy2` with `safe_install_certificate()` in `core/privileged_helper.py`.
  2. Implement system helper installation and root-ownership check in `core/system_fix.py`.
  3. Verify that SUID bits on source files in `certificates/all_cas/` are stripped and that destination files are strictly mode `0644`.

### Phase 2: Command & Argument Injection Fixes
* **Files:** `install.sh`, `core/system_fix.py`
* **Tasks:**
  1. Update `install.sh` to use `printf %q` for the binary launcher wrapper.
  2. Quote `Exec=` path in `install.sh` and `core/system_fix.py` according to Desktop Entry specifications.
  3. Use `shlex.quote()` in `core/system_fix.py` for launcher generation.

### Phase 3: Bootstrap & CLI Robustness
* **Files:** `setup`, `cli.py`
* **Tasks:**
  1. Update `setup` to verify repository signatures before executing local `installer.py`.
  2. Add `sanitize_terminal_str()` in `cli.py` to strip/escape terminal control sequences from device inputs.

### Phase 4: UI Markup Escaping
* **Files:** `ui/dashboard_view.py`, `ui/cards_view.py`
* **Tasks:**
  1. Wrap all cardholder and reader attributes with `GLib.markup_escape_text()`.
  2. Test UI rendering with sample certificates containing `&` and `<` characters.

---

## 5. Verification & Testing Checklist

When applying these fixes in the subsequent session, verify against this checklist:

- [ ] **Test SUID Prevention:** Create a dummy certificate with mode `04755` (`chmod 4755 certificates/all_cas/test_suid.crt`). Run the cert installer as root and confirm destination mode is strictly `0644` without SUID.
- [ ] **Test Non-Cert Rejection:** Create a fake text/binary file named `fake.crt` in `certificates/all_cas/`. Confirm `safe_install_certificate()` logs a warning and skips it.
- [ ] **Test Desktop Entry with Spaces:** Run `install.sh` in a path containing spaces (e.g. `/tmp/test space/sentinel/`). Verify the generated `.desktop` file validates cleanly with `desktop-file-validate` and launches correctly.
- [ ] **Test CLI Control Sequences:** Simulate a token label containing `\x1b[31mRed\x1b[0m\x07`. Verify `sentinel status` does not alter terminal colors or bell.
- [ ] **Test UI Markup Escaping:** Test a certificate subject containing `CN=Test & User <12345>`. Confirm GTK4 displays the literal string without Pango markup errors.
- [ ] **Syntax & Import Check:** Execute python import checks:
  ```bash
  python3 -c "import cli; import core.system_fix; import core.privileged_helper; print('All core modules imported successfully')"
  ```
