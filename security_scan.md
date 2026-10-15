# Injection

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** low
- **State:** Open
- **Location:** `ui/dashboard_view.py:194-196`
- **CWE:** CWE-116
- **Reachability:** external
- **Exploitability:** difficult

## Description

Card-derived holder and issuer names are passed to markup-enabled subtitle setters without escaping. A token label also reaches a markup-enabled group title without escaping, allowing external metadata to introduce formatting and clickable destinations into the credential display.

**Evidence**

- Source/control: Subject and issuer common names from certificates read at supported card certificate identifiers, and the token label returned by pkcs11-tool.
- Sink/decision: Dashboard ActionRow.set_subtitle calls at ui/dashboard_view.py:194-196 and PreferencesGroup.set_title at ui/cards_view.py:57.
- Missing mitigation: The affected display setters do not distinguish literal card metadata from application-authored markup. Escaping applied in the certificate detail rows is missing at these separate rendering operations.

**Assumptions**
Based on these assumptions: A4 (Third-party behavior): System-provided OpenSSL uses its documented default distinguished-name formatting rather than markup encoding. Libadwaita ActionRow subtitles and PreferencesGroup titles interpret markup by default, and GTK label links use the documented default URI activation behavior.
Findings that rely on assumptions are published at medium severity at most. If an assumption does not hold for your deployment, dismiss this finding.

## Recommendation

Disable markup on the affected metadata widgets where supported, or escape each external value with GLib.markup_escape_text before passing it to a markup consumer. Apply the same rule to the token header and its externally supplied description values.

---

# Other

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** low
- **State:** Open
- **Location:** `cli.py:75-75`
- **CWE:** CWE-150
- **Reachability:** external
- **Exploitability:** difficult

## Description

The card-information command prints an external token label as terminal protocol text. Embedded control sequences can manipulate the display and, when the terminal permits OSC 52 writes, replace clipboard contents.

**Evidence**

- Source/control: Smart-card token metadata extracted from pkcs11-tool output at core/smartcard.py:242-245.
- Sink/decision: Unescaped terminal output at cli.py:75, with an alternate output operation at cli.py:56.
- Missing mitigation: The diagnostic output does not encode card-controlled terminal control characters as visible text before printing them.

**Assumptions**
Based on these assumptions: A2 (Attacker-controlled input): The token label supplied by an attacker-controlled supported smart card is lower-trust device input.; A4 (Third-party behavior): OpenSC's pkcs11-tool displays token-label contents without escaping embedded ESC and BEL, consistent with its normal textual token listing behavior; its implementation is not included in this repository.
Findings that rely on assumptions are published at medium severity at most. If an assumption does not hold for your deployment, dismiss this finding.

## Recommendation

Use a terminal-safe formatter for external metadata in both diagnostic commands. Render ESC, BEL, carriage returns, and other control characters visibly instead of emitting them literally.

---

# Other

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** medium
- **State:** Open
- **Location:** `setup:14-14`
- **CWE:** CWE-829
- **Reachability:** external
- **Exploitability:** difficult

## Description

The standalone bootstrap executes a neighboring installer.py merely because that filename exists. In a directory containing downloads from different origins, this lets an attacker-supplied file run with the launching user's authority before the official application is fetched.

**Evidence**

- Source/control: An attacker-supplied installer.py downloaded into the directory containing the genuine standalone setup script.
- Sink/decision: exec python3 "${SCRIPT_DIR}/installer.py" at setup:14.
- Missing mitigation: Standalone operation does not distinguish an official checkout from an unrelated neighboring executable. A filename existence check is insufficient to establish the origin of code that will execute.

## Recommendation

Separate standalone downloading from explicitly requested local-checkout launching. In standalone mode, fetch the official application into a dedicated directory and execute that fetched installer rather than discovering executable code beside the bootstrap.

---

# Injection

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** medium
- **State:** Open
- **Location:** `install.sh:94-94`
- **CWE:** CWE-88
- **Reachability:** external
- **Exploitability:** difficult

## Description

The desktop-entry generators write the Python script pathname without Desktop Entry argument quoting. A space in the installation path changes Python's first script argument, allowing execution of an attacker-owned file at the pathname prefix.

**Evidence**

- Source/control: The installation directory derived at install.sh:8, or the checkout pathname passed to install_desktop_integration by ui/installer_window.py:677.
- Sink/decision: Exec=python3 followed by an unquoted script pathname at install.sh:94 and core/system_fix.py:222.
- Missing mitigation: The desktop-entry generators do not preserve the complete application script pathname as one literal Exec argument. The working-directory field cannot compensate for the argument splitting.

**Assumptions**
Based on these assumptions: A4 (Third-party behavior): The victim's desktop launcher follows documented Desktop Entry Exec parsing: unquoted whitespace separates arguments, and Path specifies only the working directory. The desktop-launcher implementation is not included in the repository.
Findings that rely on assumptions are published at medium severity at most. If an assumption does not hold for your deployment, dismiss this finding.

## Recommendation

Quote and escape the complete script pathname according to Desktop Entry Exec rules in both generators, including reserved characters and literal percent signs. Ensure desktop activation passes exactly one intended script pathname to Python.

---

# Injection

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** medium
- **State:** Open
- **Location:** `install.sh:78-78`
- **CWE:** CWE-78
- **Reachability:** external
- **Exploitability:** difficult

## Description

The shell installer writes its source pathname directly into a new Bash program. The generated double-quoted argument still interprets command substitutions or injected quote syntax when the launcher later runs.

**Evidence**

- Source/control: SCRIPT_DIR derived from the installation pathname at install.sh:8.
- Sink/decision: The generated exec command at install.sh:78 in ~/.local/bin/sentinel-cac-manager.
- Missing mitigation: The installer does not encode the complete Python script pathname as a literal Bash argument before writing executable shell source.

## Recommendation

Encode the complete script pathname with Bash printf %q and write that encoded argument into the launcher without additional ad hoc quoting. Preserve "$@" separately for argument forwarding.

---

# Injection

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** medium
- **State:** Open
- **Location:** `core/system_fix.py:193-193`
- **CWE:** CWE-78
- **Reachability:** external
- **Exploitability:** difficult

## Description

The desktop-integration helper inserts the installation pathname into executable Bash source without encoding it as a literal argument. Command substitutions or quote characters in that pathname can execute commands when the generated launcher runs.

**Evidence**

- Source/control: The checkout directory incorporated into ui/installer_window.py:30 and passed as project_dir at line 677.
- Sink/decision: The generated Bash exec command at core/system_fix.py:193, persisted as the executable sentinel-cac-manager launcher.
- Missing mitigation: The complete script pathname is not shell-quoted before it becomes Bash source. Double quotes alone do not make arbitrary pathname contents literal.

## Recommendation

Apply shlex.quote to the complete application script pathname and insert the resulting shell literal without additional ad hoc quotes. Keep argument forwarding as a separate "$@" expression.

---

# Other

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** medium
- **State:** Open
- **Location:** `core/system_fix.py:58-64`
- **CWE:** CWE-829
- **Reachability:** external
- **Exploitability:** difficult

## Description

The application asks an elevated Python interpreter to execute a helper inside its user-writable installation. Replacing that helper changes the code that runs as root after administrative authorization.

**Evidence**

- Source/control: The installation owner's writable core/privileged_helper.py and its parent directories under ~/.local/share/sentinel_cac_manager.
- Sink/decision: subprocess.Popen executes pkexec python3 HELPER_SCRIPT, where HELPER_SCRIPT points into the per-user application tree.
- Missing mitigation: The elevated helper and its parent directories remain replaceable by the lower-privilege installation owner. Administrative authorization does not bind execution to protected application code.

## Recommendation

Install the privileged helper and all of its executable dependencies in a fixed root-owned directory that ordinary users cannot replace. Invoke that protected helper through a narrowly scoped Polkit action instead of elevating Python against a per-user script.

---

# Security misconfiguration

- **Repository:** `CodeFXR/CodeFXR/Sentinel-CAC-Manager`
- **Severity:** medium
- **State:** Open
- **Location:** `core/privileged_helper.py:92-95`
- **CWE:** CWE-732
- **Reachability:** external
- **Exploitability:** difficult

## Description

The root certificate installer preserves permissions from user-writable certificate sources. A native executable named with a .crt suffix and mode 04755 can become a root-owned setuid executable in the system certificate directory.

**Evidence**

- Source/control: A new attacker-selected .crt file in certificates/all_cas within the supported per-user installation.
- Sink/decision: shutil.copy2(src, dst) copies attacker-controlled contents and permission bits into /usr/local/share/ca-certificates/dow as root.
- Missing mitigation: The privileged installer neither validates the source as a certificate nor assigns a fixed non-executable destination mode. It imports executable and special permission bits from lower-trust files.

## Recommendation

Read and validate certificate contents before installation, then write only validated bytes into securely created root-owned files with mode 0644. Do not preserve source permissions or extended attributes, and publish the files without an executable-permission window.
