#!/usr/bin/env python3
"""Privileged helper script for Sentinel CAC Manager.
Runs elevated tasks (system certs, systemctl, opensc.conf, enterprise policies)
under a single pkexec / sudo invocation so the user only authenticates ONCE.
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Optional

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Cryptographic SHA-256 file digest manifest for official DoD certificates.
DOD_CA_FINGERPRINTS = {
    "DOD_DERILITY_CA-1.crt": "b792d3cd0a8d2b077ea81cab0c6cd4edc018b054b89c59268d42a5590bd691ff",
    "DOD_DERILITY_CA-3.crt": "365049baa57070951e53dc9011006d94f95b31baff9404fbf2a1734675559d84",
    "DOD_DERILITY_CA-4.crt": "69e4b7ac1dbd472c2b561775e0d992d2a2ec8a9e2dad537693740f0340016805",
    "DOD_DERILITY_CA-5.crt": "8416b0a5526c15f294309ed19cc790439b09b10755b7a370f670cac64dc810d7",
    "DOD_DERILITY_CA-6.crt": "713112199a0198a97837d8a3bca13c218bc7ec6590ced816ebdd8d7ea8b3c1a5",
    "DOD_EMAIL_CA-62.crt": "aa418e09adc19edb0a0302e01120a07d68f60cf05c2c4c28aef24af93b9a7d26",
    "DOD_EMAIL_CA-63.crt": "e0471278a605146108bcfb6cd8408ec94d497c2e912d91b13dc8c4d85e6474a7",
    "DOD_EMAIL_CA-64.crt": "433098257647e0fd92b2262bf58b16dacc54a98f51cf8b5be5d47dbb5d92b1a1",
    "DOD_EMAIL_CA-65.crt": "adb54e87d349dcc5665652d83274815da10e5cd18640a5f84a4ed90b96a83bc6",
    "DOD_EMAIL_CA-70.crt": "3988b7899fb52ba764169db787d7ae357b12f76e361d20c631cb41740fca6b69",
    "DOD_EMAIL_CA-71.crt": "97b6bcd92d05f4e4c764560365b4ed728f983ab48477286e106e4100c28a275d",
    "DOD_EMAIL_CA-72.crt": "b342f980fd1a88ad4605447db67eae6163ba33cb7e108ac9ace482a0139a9988",
    "DOD_EMAIL_CA-73.crt": "93f52cbb1c9666e5b9bc7dd7b901816560ee0d82edad97137aec35531b21761f",
    "DOD_EMAIL_CA-78.crt": "4f3ee6ddd7821cb9d49d09805ce3678d1ba521efc44d6f146fe79363b3170b9b",
    "DOD_EMAIL_CA-79.crt": "ef60845fc4d2bedcb404a7d7b375229e6a6dee6c2def84866f3dd0a14acd639b",
    "DOD_EMAIL_CA-80.crt": "bf463e544dbc8b2dbe588ef957df9251af2deb9171916fc1371f0ccaa7b73633",
    "DOD_EMAIL_CA-81.crt": "87696e907b5c9bb7bb407480559bd98e07b54d0a47d748540b01ce0bac379fcf",
    "DOD_ID_CA-62.crt": "25f2aa5eb6ebff9b66ffde5c62fea0d4eb791ec7fa7ff6f2e388126c74100ed0",
    "DOD_ID_CA-63.crt": "7649a6591cebc1c6400195caacba43e76d2588a2025eba49eb2d2cafe2c097ae",
    "DOD_ID_CA-64.crt": "c81bd68f5b7453aa99c471fe79f2eeba643e9b0ff2466235b6b9deecfac841c9",
    "DOD_ID_CA-65.crt": "15896437be65f4c922b51623b40621a362483175638c567f6738b5a8d136b3cb",
    "DOD_ID_CA-70.crt": "1fd13654266223a348e79f827a3f358ccf803215955990982d32009b270d9b2e",
    "DOD_ID_CA-71.crt": "9d93bfba93a82b8532ff3985b81fcf26dd42f878e8ab397a857ee6ba52db4306",
    "DOD_ID_CA-72.crt": "d53d3673229377b608f52f622a6db780baed0692ceb16593f1f87b45257cf005",
    "DOD_ID_CA-73.crt": "a4d2016bff3e1baec36b42a4921ec3d7ef8b3130e10bb1b02cf0c01babf8a3df",
    "DOD_ID_CA-78.crt": "178f10e93fb7966d437cf40f02115237f558704337a482f020d63cd9b004ae76",
    "DOD_ID_CA-79.crt": "3d49e89b592e2eeb4389fb82747e1e67e5389c7d25d70352c9df9480f83cebd9",
    "DOD_ID_CA-80.crt": "17038dc5ccd48f4ed0677dea3758d7059d0fec7aeb0aeaa748f80d0133a8d577",
    "DOD_ID_CA-81.crt": "09a0be8af9309bb53bbc643f7178a6b3d6e12f59907a7a2116fef53ac099c5ce",
    "DOD_SW_CA-66.crt": "6c592affece2d6bfcc51a5d74a8bf72f2a730554bfb886169cef4a692c1c077f",
    "DOD_SW_CA-67.crt": "a3f6b2e15d03b2be4b38d870fc483b7b29096978cbf469b23a55469bcf528f8e",
    "DOD_SW_CA-68.crt": "5043ab9bf7978b0292ed6f3e9c5057e86eab5d9107845766e878ddec2249c38a",
    "DOD_SW_CA-69.crt": "210c46224b7375fcf246165163c30185e41ec4df0730b10b9afa2fe79c4fa538",
    "DOD_SW_CA-74.crt": "bc3e078e31530686c0a058c0911aa1ccb80cbba0fd54c19c60f06f567ada2104",
    "DOD_SW_CA-75.crt": "8ee4b5c2731dad2a18e13eab0289ab7a52622ff55272ae796a0b5d20fcdb6cde",
    "DOD_SW_CA-76.crt": "550b688a41e6841c649b876e74d4a67331832ca834195bb78411036448dfa975",
    "DOD_SW_CA-77.crt": "2a5c88ce7e20096fdf6c739dc54d842996b6e75fc6d05913b0f3b06ede151db8",
    "DOD_SW_CA-82.crt": "81498acfe45eda7f67bef9c345618fec8efa8b612fd9c9bbb016306b04f2c5b5",
    "DOD_SW_CA-83.crt": "612625a070c229a89f4137995989689cace809ab75f1879c80adaee10c45acee",
    "DOD_SW_CA-84.crt": "4c7245e536c95d8035604e516e8a32b09670f33545de7cba06075da0757364f7",
    "DOD_SW_CA-85.crt": "d9ed4f3ebec2295f4a792a008a905e540f95834531540434a66c3a697ab3de35",
    "DoD_Full_Chain.crt": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoD_Full_Chain.pem": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoD_Root_CA_3.crt": "9ca4000a486094dbcf46f5d5162375789a5e8b564ce754a87e4b90e06db0e177",
    "DoD_Root_CA_4.crt": "488cac7d9d9fe818945410a5d37713ac3ebbd8d5a36f71d489278c8ba334b27c",
    "DoD_Root_CA_5.crt": "07820e449f9543fa02f9f207cd0babb15d82d7f2dea34874e8e85a2a3f55a0a4",
    "DoD_Root_CA_6.crt": "6936a739b3327f15c563d106862c5b9406c6be24cb5656288ada6826783e0ff4",
    "DoD_Roots.pem": "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779",
    "DoW_Full_Chain.crt": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoW_Full_Chain.pem": "df8f157b983be4673caee0154e0df1780981ee5865102b78aea0122550dd4c1d",
    "DoW_Roots.pem": "0b3070a1f74f5d370f758b9c0ea570e9a1d941fb71076969bb2d7902b7226779",
}

# Canonical ASN.1 DER SHA-256 certificate fingerprints (immune to CRLF/LF line-ending variance).
DOD_CA_DER_FINGERPRINTS = {
    "DOD_DERILITY_CA-1.crt": "67a953b9e17f77599c6e553053dcd43fd7478fdd5cbd844612ceb6064386f8df",
    "DOD_DERILITY_CA-3.crt": "83eea7e541716dcfb4b705a44e34f7e0af86d839c7cd796962a70e91d4932646",
    "DOD_DERILITY_CA-4.crt": "8112237903e9a9afdc4e5bec6970c3ef09c9a63897da4156c22a77d355ad0deb",
    "DOD_DERILITY_CA-5.crt": "70a011a6b00759f6ab1d08acb3f646d66f578e41f71f1c9586e1f470f4576870",
    "DOD_DERILITY_CA-6.crt": "4f6c4dc6800346464db209f5a05ec1f4019e7ba48f7346011d9643d2e4b3eace",
    "DOD_EMAIL_CA-62.crt": "36490d91175ca3b39b21b21941db70635c58a3fd0f51135af9f0edc15cbf55b6",
    "DOD_EMAIL_CA-63.crt": "c6a4dac9fd846474ea35c52afada31510d388ee5af694d8e7f7300eee73cbd2f",
    "DOD_EMAIL_CA-64.crt": "690c69044761d3a9ab208e4ef2c7b461f09ab524137e7d059176324df42480d8",
    "DOD_EMAIL_CA-65.crt": "d483b29aae8b40d62ad4757f2986a6d541c4241383d7928592fc61ba5d01085a",
    "DOD_EMAIL_CA-70.crt": "2ad7d00e45d128a46fdb5747d39eaa994f034086d05cb891e01bf61c7d97c083",
    "DOD_EMAIL_CA-71.crt": "9d7e0bfb84d6a5f66cfd701b786dc75db31422687212bf26c276b70df0627bdb",
    "DOD_EMAIL_CA-72.crt": "22ffd6b58540bed6f568890348da2654ca54b50f2216c9eade78812782206ba2",
    "DOD_EMAIL_CA-73.crt": "ca4733b4e471a699d025fa88cee35e07372dcaa9cfe609469c16a72ec5595cf7",
    "DOD_EMAIL_CA-78.crt": "2c95f5c815569b65cdf70d03f135f2cf130b82b33d5719a68d25a1ec19d405fc",
    "DOD_EMAIL_CA-79.crt": "3d8d7bf0c6381aa07ff5e0aa47fec6d077aeec1c2ee22183b2c2028a2ff35d68",
    "DOD_EMAIL_CA-80.crt": "8208232225e469e65e93497402be9a377d81a25938b85ccae3f3adc14078de93",
    "DOD_EMAIL_CA-81.crt": "8dc6e3657631ec33de1706c2803662786c120825d121b5dd4b1c90b126654967",
    "DOD_ID_CA-62.crt": "a3626dfa33eadf6f1ac300a733f52322c6cdc59f5d561e2188c493d016c49dd5",
    "DOD_ID_CA-63.crt": "dd2dc71d5affa281ceb4da78d58a8119ffe606d732dab5343b2b1c3de4993613",
    "DOD_ID_CA-64.crt": "fc6fd238f81a3b1755db3bc5471440a186ef3ab4e9ea6d76c2e157c22236b482",
    "DOD_ID_CA-65.crt": "80e252331942dcaaaa7de7fb450ee9610081f44bbe164fe9936a759ba4541e5b",
    "DOD_ID_CA-70.crt": "3ccc94baa9108ef0ca373b89074b8cfac6c0cf0f07ab190c570d5053032f337a",
    "DOD_ID_CA-71.crt": "f7ba690fe17cff7b191ac6d32522931c6f472df487574f0d1c576da0d2ab7049",
    "DOD_ID_CA-72.crt": "b1c14ea631f47bcd7698e7673fdf5b5b104c52631ce58913346ec7a07e154638",
    "DOD_ID_CA-73.crt": "3d6a666556365400d6e2beed9dd97082537fb74887a5c68b426eb06c327e0826",
    "DOD_ID_CA-78.crt": "bbaf5275b33aff5aa9e5bce945640ac0c08f4a4d02d7d2e26e78293e912231ce",
    "DOD_ID_CA-79.crt": "4a3a111b697959d3f620cbf9f5150e4087861d47a695860aff8136a819a71e1a",
    "DOD_ID_CA-80.crt": "ad6bb50b82da2f99c242d7971012175809b22af0112f1e695ef3c236c7d2f22e",
    "DOD_ID_CA-81.crt": "abdc810cf17cea00bbaace9418b872c25cf8bf3d7694a4e05b9f391d23b80d03",
    "DOD_SW_CA-66.crt": "79dd87d87503bd9c422b49e2bf7a23a5c0783cce85d588759f3a349ec26eb84a",
    "DOD_SW_CA-67.crt": "cca9b469b4edda4d615b58c130ecaebba5ca439adbee8be15206626e5122f4ca",
    "DOD_SW_CA-68.crt": "dcd29a5b27db87d5d617f395edad6d7fa0fe230117afbf6c4b7f31f372a2e66a",
    "DOD_SW_CA-69.crt": "3320f4876c4d0fa7118f2891a1421bb3cda7bb64be80f9bd040bcff6faa3dbee",
    "DOD_SW_CA-74.crt": "6338c57b568b1d47568ab7548a8d66cc31bc4a096a4cc10a4b45edeb09bd65f6",
    "DOD_SW_CA-75.crt": "6cbc8895834385d27678cb0012d224277b02dcfc4502bceafdfe1a0a2543f416",
    "DOD_SW_CA-76.crt": "0e0f71389c9937334989842a908206e671f356a10903e2cf398abb5e27b3f40c",
    "DOD_SW_CA-77.crt": "48e2775e6db09931c3d62a913889affc653aa9d9142ac4c10bd11f6968fc4a31",
    "DOD_SW_CA-82.crt": "7aafb4a72e96483d9db2b4226dcead0bb01a95c236768c7a0f681abf5f168e81",
    "DOD_SW_CA-83.crt": "cc88db853e8f8c2c61f40f281ebca7ed08a082e1ac10679b785db9f76e9b7015",
    "DOD_SW_CA-84.crt": "560eb4465753bd286bf65fd0d16256fd126daa0d1d5abbe9ff7a5688ae830357",
    "DOD_SW_CA-85.crt": "6fa364cfc7ecdc69e581d20f0bcea306f8d8a52142b3dadda949276db1061098",
    "DoD_Root_CA_3.crt": "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2",
    "DoD_Root_CA_4.crt": "559a5189452b13f8233f0022363c06f26e3c517c1d4b77445035959df3244f74",
    "DoD_Root_CA_5.crt": "1f4ede9dc2a241f6521bf518424acd49ebe84420e69daf5bac57af1f8ee294a9",
    "DoD_Root_CA_6.crt": "2a5e41aca93df7cc496d2369b7a0a037045d502f1abaaf76975fc07c6660cf93",
}

DOD_ROOT_FILES = ("DoD_Root_CA_3.crt", "DoD_Root_CA_4.crt", "DoD_Root_CA_5.crt", "DoD_Root_CA_6.crt")
DOD_ROOT_DER_FINGERPRINTS = {k: DOD_CA_DER_FINGERPRINTS[k] for k in DOD_ROOT_FILES}

SAFE_MODULE_PATH = re.compile(r"^/[a-zA-Z0-9_./\-]+\.so(\.[0-9]+)*$")


def find_default_opensc_module() -> str:
    """Discover the system's opensc-pkcs11.so path dynamically."""
    patterns = [
        "/usr/lib64/opensc-pkcs11.so*",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so*",
        "/usr/lib/opensc-pkcs11.so*",
        "/usr/lib/pkcs11/opensc-pkcs11.so*",
        "/usr/lib64/pkcs11/opensc-pkcs11.so*",
        "/usr/lib/*-linux-gnu/opensc-pkcs11.so*",
    ]
    for pattern in patterns:
        for m in sorted(glob.glob(pattern)):
            if os.path.isfile(m):
                return m
    return "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"


def validate_pkcs11_module_path(module_path: Optional[str]) -> Optional[str]:
    """Validate that a PKCS#11 module path is safe, normalized, under /usr/lib* or /lib*, exists, is root-owned, and is not world-writable."""
    if not module_path:
        module_path = find_default_opensc_module()
    try:
        from core.rust_bridge import validate_pkcs11_module_path_rust
        rust_res = validate_pkcs11_module_path_rust(module_path)
        if rust_res is not None:
            canonical, err_msg = rust_res
            if err_msg:
                log(f"Security: {err_msg}")
                return None
            return canonical
    except Exception:
        pass
    if any(c in module_path for c in ("\r", "\n", "\0", '"', "'", ";", "`", "$")):
        log(f"Security: Rejected PKCS#11 module path containing control/meta characters: {module_path!r}")
        return None
    if ".." in module_path.split("/"):
        log(f"Security: Rejected PKCS#11 module path containing '..' traversal: {module_path!r}")
        return None
    if not SAFE_MODULE_PATH.match(module_path) or not module_path.startswith(("/usr/lib", "/lib", "/usr/local/lib")):
        log(f"Security: Rejected PKCS#11 module path failing format/prefix validation: {module_path!r}")
        return None
    real_path = os.path.realpath(module_path)
    if not real_path.startswith(("/usr/lib", "/lib", "/usr/local/lib")) or not os.path.isfile(real_path):
        log(f"Security: Rejected non-existent or out-of-prefix PKCS#11 module path: {module_path!r}")
        return None
    try:
        st = os.stat(real_path)
        if st.st_uid != 0:
            log(f"Security: Rejected non-root-owned PKCS#11 module: {real_path}")
            return None
        if st.st_mode & stat.S_IWOTH:
            log(f"Security: Rejected world-writable PKCS#11 module: {real_path}")
            return None
    except OSError:
        return None
    return real_path


def get_certs_dir(override: str = None) -> str:
    """Discover certificates directory across system, local, and user installs."""
    system_store = "/usr/share/sentinel/certificates"
    if os.path.isdir(system_store) and os.path.isdir(os.path.join(system_store, "all_cas")):
        try:
            if os.stat(system_store).st_uid == 0:
                return system_store
        except Exception:
            pass

    if override and os.path.isdir(override) and os.path.isdir(os.path.join(override, "all_cas")):
        if not any(c in override for c in ("\r", "\n", "\0")):
            return os.path.abspath(override)

    candidates = [
        "/usr/share/sentinel/certificates",
        "/usr/libexec/sentinel/certificates",
        os.path.join(SCRIPT_DIR, "certificates"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "certificates"),
    ]

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            u_home = pwd.getpwnam(sudo_user).pw_dir
            candidates.append(os.path.join(u_home, ".local", "share", "sentinel_cac_manager", "certificates"))
        except Exception:
            pass

    for c in candidates:
        if os.path.isdir(c) and os.path.isdir(os.path.join(c, "all_cas")):
            return c

    return os.path.join(SCRIPT_DIR, "certificates")


CERTS_DIR = get_certs_dir()
ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoD_Full_Chain.pem")
if not os.path.isfile(FULL_CHAIN_PEM):
    FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoD_Full_Chain.crt")
if not os.path.isfile(FULL_CHAIN_CRT):
    FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoW_Full_Chain.crt")

OPENSC_DIRECTIVE = "card_drivers = piv-II, cac, cac1;"


def log(msg):
    print(f"[SENTINEL-ROOT] {msg}", flush=True)


def is_opensc_config_optimized(content: str) -> bool:
    """Return True if an uncommented card_drivers line in opensc.conf includes piv-II."""
    try:
        from core.rust_bridge import is_opensc_config_optimized_rust
        rust_opt = is_opensc_config_optimized_rust(content)
        if rust_opt is not None:
            return rust_opt
    except Exception:
        pass
    for line in content.splitlines():
        uncommented = line.split("#", 1)[0].strip()
        if "card_drivers" in uncommented and ("piv-II" in uncommented or "PIV-II" in uncommented):
            return True
    return False


def reset_smartcard_atr():
    """Trigger a warm card reset to avoid requiring physical card re-insertion after pcscd restart."""
    tool = shutil.which("opensc-tool")
    if tool:
        try:
            check = subprocess.run([tool, "-l"], capture_output=True, text=True, timeout=3)
            if check.returncode == 0 and "Reader" in check.stdout:
                res = subprocess.run([tool, "--reset", "warm"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    log("Executed warm ATR reset on inserted smart card.")
        except Exception as e:
            log(f"Warm ATR reset note: {e}")


def ensure_system_helper():
    """Ensure privileged_helper.py is installed in root-owned /usr/libexec/sentinel/ (0755 root:root)."""
    try:
        sys_dir = "/usr/libexec/sentinel"
        sys_helper = os.path.join(sys_dir, "privileged_helper.py")
        current_script = os.path.abspath(__file__)
        if current_script != sys_helper:
            os.makedirs(sys_dir, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=sys_dir, delete=False) as f_tmp:
                temp_dst = f_tmp.name
                with open(current_script, "rb") as f_src:
                    f_tmp.write(f_src.read())
            os.chmod(temp_dst, 0o755)
            try:
                os.chown(temp_dst, 0, 0)
            except Exception:
                pass
            os.replace(temp_dst, sys_helper)
            log("Synchronized protected privileged helper to /usr/libexec/sentinel/privileged_helper.py")
    except Exception as e:
        log(f"System helper sync note: {e}")


def enable_pcscd() -> bool:
    log("Enabling and starting pcscd daemon...")
    res = subprocess.run(["systemctl", "enable", "--now", "pcscd.socket", "pcscd"], capture_output=True, text=True)
    if res.returncode == 0:
        log("pcscd service and socket enabled and started.")
        reset_smartcard_atr()
        return True
    else:
        log(f"pcscd service warning: {res.stderr.strip()}")
        reset_smartcard_atr()
        return False


def fix_opensc_hang() -> bool:
    log("Configuring OpenSC reader compatibility...")
    candidates = ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]
    target_conf = None
    for c in candidates:
        if os.path.isfile(c) or os.path.isdir(os.path.dirname(c)):
            target_conf = c
            break
    if not target_conf:
        target_conf = "/etc/opensc.conf"

    original = ""
    if os.path.isfile(target_conf):
        try:
            with open(target_conf, "r", encoding="utf-8", errors="replace") as f:
                original = f.read()
        except OSError:
            pass

    # Check if card_drivers is already set in active (uncommented) configuration
    if is_opensc_config_optimized(original):
        log(f"OpenSC already optimized in {target_conf}")
        return True

    # Backup if exists (prevent symlink overwrite attacks)
    bak = f"{target_conf}.sentinel-bak"
    if os.path.isfile(target_conf) and not os.path.exists(bak) and not os.path.islink(bak):
        try:
            fd_bak = os.open(bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with open(fd_bak, "w", encoding="utf-8") as f_bak:
                f_bak.write(original)
            log(f"Backed up original configuration to {bak}")
        except Exception as e:
            log(f"Backup notice: {e}")

    # OpenSC requires card_drivers to be inside an app default { ... } block and end with a semicolon
    if "app default {" in original:
        idx = original.find("app default {") + len("app default {")
        updated = (
            original[:idx]
            + f"\n\t# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.\n\t{OPENSC_DIRECTIVE}\n"
            + original[idx:]
        )
    elif original.strip():
        updated = original.rstrip() + f"\n\napp default {{\n\t# Added by Sentinel CAC Manager.\n\t{OPENSC_DIRECTIVE}\n}}\n"
    else:
        updated = (
            "app default {\n"
            "\t# Added by Sentinel CAC Manager.\n"
            "\t# Restricts card drivers to skip the 26-second Broadcom 58200 setcos probe hang.\n"
            f"\t{OPENSC_DIRECTIVE}\n"
            "}\n"
        )

    try:
        conf_dir = os.path.dirname(target_conf)
        os.makedirs(conf_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=conf_dir, delete=False, encoding="utf-8") as f_tmp:
            tmp_name = f_tmp.name
            f_tmp.write(updated)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target_conf)
        log(f"Optimized {target_conf} with CAC/PIV drivers.")
        return True
    except Exception as e:
        log(f"Failed to update {target_conf}: {e}")
        return False


SAFE_CERT_FILENAME = re.compile(r"^[a-zA-Z0-9_.-]+\.(crt|pem)$")
PEM_CERT_PATTERN = re.compile(rb"-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----")


def _extract_der_from_pem_body(b64_body: bytes) -> Optional[bytes]:
    """Decode base64 body of a PEM certificate block into raw ASN.1 DER bytes."""
    try:
        cleaned = re.sub(rb"\s+", b"", b64_body)
        der = base64.b64decode(cleaned, validate=True)
        if len(der) >= 64 and der[0] == 0x30:
            return der
    except Exception:
        pass
    return None


def _verify_x509_ca_properties(der_bytes: bytes, require_self_signed: bool = False) -> Optional[bytes]:
    """Verify ASN.1 X.509 certificate structure, CA basic constraints, expiry, and self-signed root status.

    Returns canonical PEM bytes on success, or None if validation fails.
    """
    # 1. Verify via OpenSSL CLI (handles all NIST/DoD RSA and ECDSA P-384 certificates reliably)
    if shutil.which("openssl"):
        try:
            proc_check = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-inform",
                    "DER",
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-ext",
                    "basicConstraints",
                    "-checkend",
                    "0",
                ],
                input=der_bytes,
                capture_output=True,
                timeout=5,
            )
            if proc_check.returncode != 0:
                return None
            out_text = proc_check.stdout.decode(errors="replace")
            if "CA:TRUE" not in out_text:
                return None

            subj_line = ""
            iss_line = ""
            for line in out_text.splitlines():
                if line.startswith("subject="):
                    subj_line = line[len("subject="):].strip()
                elif line.startswith("issuer="):
                    iss_line = line[len("issuer="):].strip()

            if not subj_line or not iss_line:
                return None
            if require_self_signed and subj_line != iss_line:
                return None

            proc_pem = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                input=der_bytes,
                capture_output=True,
                timeout=5,
            )
            if proc_pem.returncode == 0 and b"-----BEGIN CERTIFICATE-----" in proc_pem.stdout:
                return proc_pem.stdout.strip()
        except Exception:
            pass

    # 2. Fallback to Python cryptography library if openssl binary is unavailable
    try:
        from datetime import datetime, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_der_x509_certificate(der_bytes)
        if not cert.subject or not cert.issuer:
            return None
        if require_self_signed and cert.subject != cert.issuer:
            return None
        now = datetime.now(timezone.utc)
        if hasattr(cert, "not_valid_after_utc") and cert.not_valid_after_utc <= now:
            return None
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            return None
        return cert.public_bytes(serialization.Encoding.PEM).strip()
    except Exception:
        return None


def _validate_and_reserialize_cert(
    data: bytes,
    fname: str,
    verify_whitelist: bool = True,
) -> Optional[bytes]:
    """Validate X.509 certificate data, DER fingerprints, and CA properties, returning canonical PEM."""
    pem_bodies = PEM_CERT_PATTERN.findall(data)
    if not pem_bodies:
        log(f"Security: Rejected {fname}: contains no valid PEM certificate blocks")
        return None

    is_root_target = fname in DOD_ROOT_DER_FINGERPRINTS or fname in ("DoD_Roots.pem", "DoW_Roots.pem")
    all_allowed_ders = set(DOD_CA_DER_FINGERPRINTS.values())
    root_allowed_ders = set(DOD_ROOT_DER_FINGERPRINTS.values())

    reserialized_certs = []
    seen_der_hashes = []

    for idx, body in enumerate(pem_bodies):
        der_bytes = _extract_der_from_pem_body(body)
        if not der_bytes:
            log(f"Security: Rejected {fname}: block {idx + 1} has invalid base64 or ASN.1 sequence")
            return None

        der_sha256 = hashlib.sha256(der_bytes).hexdigest().lower()
        seen_der_hashes.append(der_sha256)

        if verify_whitelist:
            if fname in DOD_CA_DER_FINGERPRINTS:
                expected_der = DOD_CA_DER_FINGERPRINTS[fname]
                if der_sha256 != expected_der:
                    log(
                        f"Security: DER fingerprint mismatch for '{fname}'! "
                        f"Expected {expected_der}, got {der_sha256}"
                    )
                    return None
            elif fname in ("DoD_Roots.pem", "DoW_Roots.pem"):
                if der_sha256 not in root_allowed_ders:
                    log(f"Security: Non-root certificate found inside root bundle '{fname}' ({der_sha256})")
                    return None
            elif fname in ("DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Full_Chain.pem", "DoW_Full_Chain.crt"):
                if der_sha256 not in all_allowed_ders:
                    log(f"Security: Unauthorized certificate block {idx + 1} in '{fname}' ({der_sha256})")
                    return None
            else:
                log(f"Security: Rejected unauthorized certificate filename '{fname}'")
                return None

        validated_pem = _verify_x509_ca_properties(der_bytes, require_self_signed=is_root_target)
        if not validated_pem:
            if fname in ("DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Full_Chain.pem", "DoW_Full_Chain.crt"):
                log(f"Skipping expired/retired intermediate block {idx + 1} in bundle '{fname}'")
                continue
            log(f"Security: Rejected {fname}: certificate block {idx + 1} failed X.509 CA/validity verification")
            return None
        reserialized_certs.append(validated_pem)

    if verify_whitelist:
        if fname in DOD_CA_DER_FINGERPRINTS and len(pem_bodies) != 1:
            log(f"Security: Rejected '{fname}': single-certificate file contained {len(pem_bodies)} blocks")
            return None
        if fname in ("DoD_Roots.pem", "DoW_Roots.pem") and set(seen_der_hashes) != root_allowed_ders:
            log(f"Security: Rejected '{fname}': root bundle does not contain all 4 required DoD Root CAs")
            return None

    if not reserialized_certs:
        return None

    return b"\n".join(reserialized_certs) + b"\n"


def _file_content_matches_sentinel_manifest(filepath: str) -> bool:
    """Return True only if filepath is a regular file whose content matches Sentinel's DoD CA manifest."""
    if not os.path.isfile(filepath) or os.path.islink(filepath):
        return False
    fname = os.path.basename(filepath)
    if fname not in DOD_CA_FINGERPRINTS and fname not in DOD_CA_DER_FINGERPRINTS:
        return False
    try:
        with open(filepath, "rb") as f:
            raw = f.read(5 * 1024 * 1024 + 1)
        if len(raw) > 5 * 1024 * 1024:
            return False
        raw_sha256 = hashlib.sha256(raw).hexdigest().lower()
        if raw_sha256 == DOD_CA_FINGERPRINTS.get(fname):
            return True
        pem_bodies = PEM_CERT_PATTERN.findall(raw)
        if fname in DOD_CA_DER_FINGERPRINTS and len(pem_bodies) == 1:
            der = _extract_der_from_pem_body(pem_bodies[0])
            if der and hashlib.sha256(der).hexdigest().lower() == DOD_CA_DER_FINGERPRINTS[fname]:
                return True
        if fname in ("DoD_Roots.pem", "DoW_Roots.pem") and pem_bodies:
            ders = [_extract_der_from_pem_body(b) for b in pem_bodies]
            if all(ders) and {hashlib.sha256(d).hexdigest().lower() for d in ders if d} == set(DOD_ROOT_DER_FINGERPRINTS.values()):
                return True
        if fname in ("DoD_Full_Chain.pem", "DoD_Full_Chain.crt", "DoW_Full_Chain.pem", "DoW_Full_Chain.crt") and pem_bodies:
            ders = [_extract_der_from_pem_body(b) for b in pem_bodies]
            if all(ders) and {hashlib.sha256(d).hexdigest().lower() for d in ders if d}.issubset(set(DOD_CA_DER_FINGERPRINTS.values())):
                return True
    except Exception:
        return False
    return False


def _remove_or_restore_sentinel_cert_file(filepath: str) -> bool:
    """Remove filepath only if its content matches Sentinel's manifest, restoring any pre-Sentinel backup."""
    bak_path = f"{filepath}.pre-sentinel-bak"
    if not os.path.exists(filepath) and not os.path.islink(filepath):
        return False
    if os.path.islink(filepath):
        try:
            os.remove(filepath)
            return True
        except OSError:
            return False

    if not _file_content_matches_sentinel_manifest(filepath):
        log(f"Preserving administrator/non-Sentinel file: {filepath}")
        return False

    try:
        if os.path.isfile(bak_path) and not os.path.islink(bak_path):
            os.replace(bak_path, filepath)
            log(f"Restored pre-existing administrator file from {bak_path} to {filepath}")
        else:
            os.remove(filepath)
        return True
    except OSError:
        return False


def _read_and_validate_cert(src_path: str, expected_dir: str, verify_whitelist: bool = True) -> Optional[bytes]:
    """Securely read and validate certificate bytes without following symlinks (CWE-59).

    Enforces source confinement, rejects symlinks, verifies regular file status,
    validates canonical X.509 DER SHA-256 fingerprint against authorized DoD manifest,
    validates X.509 CA constraints and validity, and returns canonical reserialized PEM bytes.
    """
    fname = os.path.basename(src_path)
    if not SAFE_CERT_FILENAME.match(fname):
        log(f"Security: Rejected certificate filename '{fname}' (invalid characters or extension)")
        return None

    if os.path.islink(src_path):
        log(f"Security: Rejected symlink in certificates directory: {src_path} (CWE-59)")
        return None

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(src_path, flags)
    except OSError as e:
        log(f"Security: Could not securely open {src_path} without following links: {e}")
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            log(f"Security: Rejected non-regular file: {src_path}")
            return None

        if st.st_size < 64 or st.st_size > 1048576:
            log(f"Security: Rejected cert {src_path} with unexpected size ({st.st_size} bytes)")
            return None

        try:
            real_src = os.path.realpath(f"/proc/self/fd/{fd}")
            real_expected = os.path.realpath(expected_dir)
            if os.path.commonpath([real_expected, real_src]) != real_expected:
                log(f"Security: Confinement violation: {src_path} resolved outside {expected_dir}")
                return None
        except Exception as e:
            log(f"Security: Confinement check error: {e}")
            return None

        raw_data = os.read(fd, st.st_size)
    finally:
        os.close(fd)

    if verify_whitelist and fname not in DOD_CA_FINGERPRINTS and fname not in DOD_CA_DER_FINGERPRINTS:
        log(f"Security: Rejected unauthorized certificate '{fname}' (not in authorized DoD manifest)")
        return None

    return _validate_and_reserialize_cert(raw_data, fname, verify_whitelist=verify_whitelist)


def _write_secure_cert(src_path: str, dst_path: str, expected_dir: str, verify_whitelist: bool = True) -> bool:
    """Read, validate, and write certificate bytes with explicit non-executable mode 0644, preserving any pre-existing non-Sentinel file."""
    data = _read_and_validate_cert(src_path, expected_dir, verify_whitelist=verify_whitelist)
    if not data:
        log(f"Skipping unvalidated or insecure certificate source: {src_path}")
        return False

    dst_dir = os.path.dirname(dst_path)
    os.makedirs(dst_dir, exist_ok=True)

    # Preserve pre-existing administrator file if its content differs from Sentinel's manifest
    bak_path = f"{dst_path}.pre-sentinel-bak"
    if (
        os.path.isfile(dst_path)
        and not os.path.islink(dst_path)
        and not _file_content_matches_sentinel_manifest(dst_path)
        and not os.path.exists(bak_path)
    ):
        try:
            with open(dst_path, "rb") as f_orig:
                orig_bytes = f_orig.read()
            fd_bak = os.open(bak_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with open(fd_bak, "wb") as f_bak:
                f_bak.write(orig_bytes)
            log(f"Backed up pre-existing administrator certificate to {bak_path}")
        except OSError as e:
            log(f"Backup notice for {dst_path}: {e}")

    temp_dst = None
    try:
        with tempfile.NamedTemporaryFile(dir=dst_dir, delete=False) as f_out:
            temp_dst = f_out.name
            f_out.write(data)
        os.chmod(temp_dst, 0o644)
        os.replace(temp_dst, dst_path)
        return True
    except Exception as e:
        log(f"Error writing certificate to {dst_path}: {e}")
        if temp_dst and os.path.exists(temp_dst):
            try:
                os.remove(temp_dst)
            except Exception:
                pass
        return False


def _clean_sentinel_owned_certs_in_dir(target_dir: str, keep_roots: bool = False) -> int:
    """Remove only certificates whose filename AND content match Sentinel's DoD manifest.

    Never deletes third-party or administrator-modified certificates in shared directories,
    even if they share a filename with a DoD certificate.
    """
    if not os.path.isdir(target_dir):
        return 0

    removed = 0
    known_sentinel_files = set(DOD_CA_FINGERPRINTS.keys()) | set(DOD_CA_DER_FINGERPRINTS.keys())
    root_set = set(DOD_ROOT_FILES)

    for existing in list(os.listdir(target_dir)):
        if keep_roots and existing in root_set:
            continue
        if existing in known_sentinel_files:
            p = os.path.join(target_dir, existing)
            if _remove_or_restore_sentinel_cert_file(p):
                removed += 1

    # Only remove directory if we are not keeping roots and the directory is now completely empty
    if not keep_roots:
        try:
            if not os.listdir(target_dir):
                os.rmdir(target_dir)
        except OSError:
            pass

    return removed


def install_system_certificates(distro_family: str) -> bool:
    """Install ONLY self-signed DoD Root CAs into the operating system trust store.

    Intermediate CAs are deliberately excluded from the system root store to enforce
    proper PKI trust anchor separation and prevent intermediate authority elevation.
    """
    log("Installing DoD Root CAs into system trust store (trust anchor separation enforced)...")
    roots_dir = os.path.join(CERTS_DIR, "roots")
    if not os.path.isdir(roots_dir):
        roots_dir = CERTS_DIR

    count = 0
    success = True
    if distro_family == "debian":
        target_dir = "/usr/local/share/ca-certificates/dod"
        os.makedirs(target_dir, exist_ok=True)
        # Clean only Sentinel-known legacy files in dow or stale Sentinel intermediates in dod
        _clean_sentinel_owned_certs_in_dir("/usr/local/share/ca-certificates/dow", keep_roots=False)
        _clean_sentinel_owned_certs_in_dir(target_dir, keep_roots=True)

        # Deploy ALL 4 self-signed Root CAs; fail if any required root is missing or invalid
        for fname in DOD_ROOT_FILES:
            src = os.path.join(roots_dir, fname)
            if not os.path.isfile(src):
                src = os.path.join(CERTS_DIR, fname)
            if os.path.isfile(src):
                dst = os.path.join(target_dir, fname)
                if _write_secure_cert(src, dst, os.path.dirname(src)):
                    count += 1
                else:
                    success = False
            else:
                log(f"ERROR: Required root certificate missing: {fname}")
                success = False

        if count != len(DOD_ROOT_FILES):
            success = False

        log(f"Installed {count}/{len(DOD_ROOT_FILES)} DoD Root CAs into {target_dir}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Ran update-ca-certificates: {res.stdout.strip()}")
        if res.returncode != 0:
            success = False
    elif distro_family == "fedora":
        target_dir = "/etc/pki/ca-trust/source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            _remove_or_restore_sentinel_cert_file(os.path.join(target_dir, old))
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Ran update-ca-trust successfully.")
        if res.returncode != 0:
            success = False
    elif distro_family == "arch":
        target_dir = "/etc/ca-certificates/trust-source/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            _remove_or_restore_sentinel_cert_file(os.path.join(target_dir, old))
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["trust", "extract-compat"], capture_output=True, text=True)
        log("Ran trust extract-compat on Arch Linux.")
        if res.returncode != 0:
            success = False
    elif distro_family == "suse":
        target_dir = "/etc/pki/trust/anchors"
        os.makedirs(target_dir, exist_ok=True)
        for old in ["DoD_Full_Chain.pem", "DoW_Full_Chain.pem", "DoW_Roots.pem"]:
            _remove_or_restore_sentinel_cert_file(os.path.join(target_dir, old))
        dst = os.path.join(target_dir, "DoD_Roots.pem")
        roots_pem_src = os.path.join(CERTS_DIR, "DoD_Roots.pem")
        if _write_secure_cert(roots_pem_src, dst, CERTS_DIR):
            log(f"Installed DoD Root trust bundle into {dst}")
        else:
            success = False
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        log("Ran update-ca-certificates on openSUSE.")
        if res.returncode != 0:
            success = False
    else:
        target_dir = "/usr/local/share/ca-certificates/dod"
        os.makedirs(target_dir, exist_ok=True)
        for fname in DOD_ROOT_FILES:
            src = os.path.join(roots_dir, fname)
            if os.path.isfile(src):
                if _write_secure_cert(src, os.path.join(target_dir, fname), os.path.dirname(src)):
                    count += 1
                else:
                    success = False
            else:
                success = False
        if count != len(DOD_ROOT_FILES):
            success = False
        res = subprocess.run(["update-ca-certificates"], capture_output=True)
        log("Updated system ca certificates.")
        if res.returncode != 0:
            success = False

    return success


def merge_firefox_policy_file(target: str, module_path: str, cert_path: str) -> bool:
    """Safely deep-merge Sentinel CAC settings into a Firefox policies.json file, recording pre-existing state."""
    try:
        target_dir = os.path.dirname(target)
        os.makedirs(target_dir, exist_ok=True)
        existing_data = {}
        existed_before = os.path.isfile(target)
        if existed_before:
            try:
                with open(target, "r", encoding="utf-8") as f_ex:
                    loaded = json.load(f_ex)
                    if isinstance(loaded, dict):
                        existing_data = loaded
            except Exception:
                existing_data = {}

        # Record pre-Sentinel snapshot once (O_CREAT | O_EXCL prevents overwriting initial snapshot)
        snap_path = f"{target}.pre-sentinel-snap"
        if not os.path.exists(snap_path) and not os.path.islink(snap_path):
            try:
                snap_payload = json.dumps(
                    {
                        "existed_before": existed_before,
                        "prior_data": json.loads(json.dumps(existing_data)),
                    },
                    indent=2,
                )
                fd_snap = os.open(snap_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with open(fd_snap, "w", encoding="utf-8") as f_snap:
                    f_snap.write(snap_payload)
            except OSError:
                pass

        policies = existing_data.get("policies")
        if not isinstance(policies, dict):
            policies = {}

        # Deep merge Certificates
        certs_block = policies.get("Certificates")
        if not isinstance(certs_block, dict):
            certs_block = {}
        certs_block["ImportEnterpriseRoots"] = True
        install_list = certs_block.get("Install")
        if not isinstance(install_list, list):
            install_list = []
        if cert_path not in install_list:
            install_list.append(cert_path)
        certs_block["Install"] = install_list
        policies["Certificates"] = certs_block

        # Deep merge SecurityDevices
        sec_devices = policies.get("SecurityDevices")
        if not isinstance(sec_devices, dict):
            sec_devices = {}
        sec_devices["DoD CAC"] = module_path
        sec_devices.pop("DoW CAC", None)
        policies["SecurityDevices"] = sec_devices

        # Deep merge Preferences
        prefs = policies.get("Preferences")
        if not isinstance(prefs, dict):
            prefs = {}
        prefs["security.default_personal_cert"] = "Ask Every Time"
        prefs["security.enterprise_roots.enabled"] = True
        policies["Preferences"] = prefs

        existing_data["policies"] = policies
        content = json.dumps(existing_data, indent=2)

        with tempfile.NamedTemporaryFile(mode="w", dir=target_dir, delete=False, encoding="utf-8") as f_out:
            tmp_name = f_out.name
            f_out.write(content)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
        log(f"Configured Firefox policy in {target}")
        return True
    except Exception as e:
        log(f"Firefox policy note for {target}: {e}")
        return False


def revert_firefox_policy_file(target: str) -> bool:
    """Remove only Sentinel-managed keys from a Firefox policies.json file using pre-Sentinel ownership snapshot.

    Preserves all unrelated enterprise policies (Homepage, Proxy, Extensions,
    Telemetry, third-party SecurityDevices or Certificates) AND preserves any
    ImportEnterpriseRoots / Preferences keys that existed prior to Sentinel.
    """
    snap_path = f"{target}.pre-sentinel-snap"
    prior_policies = {}
    if os.path.isfile(snap_path) and not os.path.islink(snap_path):
        try:
            with open(snap_path, "r", encoding="utf-8") as f_snap:
                snap = json.load(f_snap)
            if isinstance(snap, dict) and snap.get("existed_before"):
                p_data = snap.get("prior_data")
                if isinstance(p_data, dict) and isinstance(p_data.get("policies"), dict):
                    prior_policies = p_data["policies"]
        except Exception:
            prior_policies = {}

    if not os.path.isfile(target):
        if os.path.isfile(snap_path):
            try:
                os.remove(snap_path)
            except OSError:
                pass
        return True

    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return True

        policies = data.get("policies")
        if isinstance(policies, dict):
            prior_sec = prior_policies.get("SecurityDevices") if isinstance(prior_policies.get("SecurityDevices"), dict) else {}
            prior_certs = prior_policies.get("Certificates") if isinstance(prior_policies.get("Certificates"), dict) else {}
            prior_prefs = prior_policies.get("Preferences") if isinstance(prior_policies.get("Preferences"), dict) else {}
            prior_install = prior_certs.get("Install") if isinstance(prior_certs.get("Install"), list) else []

            # 1. Clean SecurityDevices (preserve if "DoD CAC" was set prior to Sentinel)
            sec_devices = policies.get("SecurityDevices")
            if isinstance(sec_devices, dict):
                if "DoD CAC" in prior_sec:
                    sec_devices["DoD CAC"] = prior_sec["DoD CAC"]
                else:
                    sec_devices.pop("DoD CAC", None)
                sec_devices.pop("DoW CAC", None)
                if not sec_devices and "SecurityDevices" not in prior_policies:
                    policies.pop("SecurityDevices", None)

            # 2. Clean Certificates (preserve any Install path or ImportEnterpriseRoots that existed before Sentinel)
            certs_block = policies.get("Certificates")
            if isinstance(certs_block, dict):
                install_list = certs_block.get("Install")
                if isinstance(install_list, list):
                    install_list = [
                        c
                        for c in install_list
                        if c in prior_install
                        or not any(
                            k in str(c)
                            for k in ("DoD_Full_Chain", "DoW_Full_Chain", "DoD_Roots", "DoW_Roots", "/usr/share/sentinel/")
                        )
                    ]
                    if install_list:
                        certs_block["Install"] = install_list
                    elif "Install" not in prior_certs:
                        certs_block.pop("Install", None)

                if (
                    "Install" not in certs_block
                    and certs_block.get("ImportEnterpriseRoots") is True
                    and "ImportEnterpriseRoots" not in prior_certs
                ):
                    if len(certs_block) == 1:
                        certs_block.pop("ImportEnterpriseRoots", None)

                if not certs_block and "Certificates" not in prior_policies:
                    policies.pop("Certificates", None)

            # 3. Clean Preferences added by Sentinel (restore/preserve if present in prior_prefs)
            prefs = policies.get("Preferences")
            if isinstance(prefs, dict):
                if "security.default_personal_cert" in prior_prefs:
                    prefs["security.default_personal_cert"] = prior_prefs["security.default_personal_cert"]
                elif prefs.get("security.default_personal_cert") == "Ask Every Time":
                    prefs.pop("security.default_personal_cert", None)

                if "security.enterprise_roots.enabled" in prior_prefs:
                    prefs["security.enterprise_roots.enabled"] = prior_prefs["security.enterprise_roots.enabled"]
                elif prefs.get("security.enterprise_roots.enabled") is True:
                    prefs.pop("security.enterprise_roots.enabled", None)

                if not prefs and "Preferences" not in prior_policies:
                    policies.pop("Preferences", None)

        # Only delete the file if policies is completely empty AND no other top-level keys exist
        other_top_keys = [k for k in data.keys() if k != "policies"]
        if not policies and not other_top_keys:
            os.remove(target)
            log(f"Removed empty Firefox policy file: {target}")
        else:
            target_dir = os.path.dirname(target)
            content = json.dumps(data, indent=2)
            with tempfile.NamedTemporaryFile(mode="w", dir=target_dir, delete=False, encoding="utf-8") as f_out:
                tmp_name = f_out.name
                f_out.write(content)
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, target)
            log(f"Cleaned Sentinel entries while preserving existing enterprise policies in {target}")

        if os.path.isfile(snap_path):
            try:
                os.remove(snap_path)
            except OSError:
                pass
        return True
    except Exception as e:
        log(f"Note reverting policy {target}: {e}")
        return False


def install_firefox_policies(module_path: str, distro_family: str) -> bool:
    validated_mod = validate_pkcs11_module_path(module_path)
    if not validated_mod:
        return False

    log("Installing Firefox Enterprise Policies with safe deep merge...")
    cert_path = (
        "/usr/share/sentinel/certificates/DoD_Full_Chain.pem"
        if os.path.isfile("/usr/share/sentinel/certificates/DoD_Full_Chain.pem")
        else FULL_CHAIN_PEM
    )

    # Always write to /etc/firefox/policies/policies.json (standard non-package-clobbered location).
    # Only touch /usr/lib*/firefox/distribution or snap if their parent directory already exists,
    # avoiding creating stray /usr/lib64 directories on Debian/Ubuntu.
    policy_targets = ["/etc/firefox/policies/policies.json"]
    for optional_dir in [
        "/usr/lib/firefox/distribution",
        "/usr/lib64/firefox/distribution",
        "/var/snap/firefox/common/policies",
    ]:
        if os.path.isdir(optional_dir):
            policy_targets.append(os.path.join(optional_dir, "policies.json"))
    if os.path.isdir("/var/snap/firefox/common") and "/var/snap/firefox/common/policies/policies.json" not in policy_targets:
        policy_targets.append("/var/snap/firefox/common/policies/policies.json")

    any_ok = False
    for target in policy_targets:
        if merge_firefox_policy_file(target, validated_mod, cert_path):
            any_ok = True
    return any_ok


def install_p11_kit_module(module_path: str) -> bool:
    validated_mod = validate_pkcs11_module_path(module_path)
    if not validated_mod:
        return False

    log("Installing system-wide p11-kit module...")
    mod_dir = "/etc/pkcs11/modules"
    os.makedirs(mod_dir, exist_ok=True)
    # Use sentinel-opensc.module so we never shadow the distribution's own opensc.module
    mod_file = os.path.join(mod_dir, "sentinel-opensc.module")
    content = f"# Added by Sentinel CAC Manager\nmodule: {validated_mod}\n"
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=mod_dir, delete=False, encoding="utf-8") as f_out:
            tmp_name = f_out.name
            f_out.write(content)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, mod_file)
        log(f"Wrote system p11-kit config: {mod_file}")

        # Clean up legacy opensc.module only if it was written by Sentinel
        legacy_mod = os.path.join(mod_dir, "opensc.module")
        if os.path.isfile(legacy_mod):
            try:
                with open(legacy_mod, "r", encoding="utf-8", errors="replace") as f_leg:
                    if "Sentinel CAC Manager" in f_leg.read():
                        os.remove(legacy_mod)
            except OSError:
                pass
        return True
    except Exception as e:
        log(f"p11-kit config note: {e}")
        return False


def connect_snap_firefox():
    if shutil.which("snap"):
        log("Connecting snap firefox:pcscd interface...")
        subprocess.run(["snap", "connect", "firefox:pcscd"], capture_output=True)


def install_system_packages(distro_family: str) -> bool:
    log("Checking and installing system packages via package manager...")
    pkg_ok = True
    if distro_family == "debian":
        pkgs = [
            "pcscd",
            "libpcsclite1",
            "pcsc-tools",
            "opensc",
            "libccid",
            "libnss3-tools",
            "openssl",
            "p11-kit",
            "p11-kit-modules",
            "python3-cryptography",
        ]
        log(f"Running apt-get install for {len(pkgs)} packages...")
        res = subprocess.run(["apt-get", "install", "-y"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via apt.")
        else:
            log(f"apt-get error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False
    elif distro_family == "fedora":
        pkgs = [
            "pcsc-lite",
            "pcsc-tools",
            "opensc",
            "openssl",
            "nss-tools",
            "p11-kit",
            "ccid",
            "python3-cryptography",
        ]
        log(f"Running dnf install for {len(pkgs)} packages...")
        res = subprocess.run(["dnf", "install", "-y"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via dnf.")
        else:
            log(f"dnf error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False
    elif distro_family == "arch":
        pkgs = ["pcsclite", "pcsc-tools", "opensc", "openssl", "nss", "p11-kit", "ccid", "python-cryptography"]
        log(f"Running pacman -S --needed for {len(pkgs)} packages...")
        res = subprocess.run(["pacman", "-S", "--needed", "--noconfirm"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via pacman.")
        else:
            log(f"pacman error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False
    elif distro_family == "suse":
        pkgs = [
            "pcsc-lite",
            "pcsc-tools",
            "opensc",
            "openssl",
            "mozilla-nss-tools",
            "p11-kit",
            "pcsc-ccid",
            "python3-cryptography",
        ]
        log(f"Running zypper install for {len(pkgs)} packages...")
        res = subprocess.run(["zypper", "--non-interactive", "install"] + pkgs, capture_output=True, text=True)
        if res.returncode == 0:
            log("Required middleware packages verified/installed via zypper.")
        else:
            log(f"zypper error: {res.stderr.strip() or res.stdout.strip()}")
            pkg_ok = False

    log("Reloading and triggering udev rules for smart card readers...")
    try:
        subprocess.run(["udevadm", "control", "--reload-rules"], capture_output=True)
        subprocess.run(["udevadm", "trigger", "--action=add", "--subsystem-match=usb"], capture_output=True)
    except Exception as e:
        log(f"udevadm trigger note: {e}")

    return pkg_ok


def cleanup_legacy_smartcard_logon(distro_family: str) -> bool:
    """Cleanly roll back any legacy v2.0.0 PAM/SSSD workstation logon configuration."""
    ok = True
    legacy_sssd_dropin = "/etc/sssd/conf.d/sentinel-smartcard.conf"
    if os.path.isfile(legacy_sssd_dropin):
        try:
            os.remove(legacy_sssd_dropin)
            log(f"Removed legacy {legacy_sssd_dropin}")
        except OSError:
            ok = False

    sssd_ca_db = "/etc/sssd/pki/sssd_auth_ca_db.pem"
    if os.path.isfile(sssd_ca_db):
        try:
            with open(sssd_ca_db, "rb") as f_db:
                raw = f_db.read(5 * 1024 * 1024)
            sha = hashlib.sha256(raw).hexdigest().lower()
            if sha in (DOD_CA_FINGERPRINTS.get("DoD_Roots.pem"), DOD_CA_FINGERPRINTS.get("DoD_Full_Chain.pem")):
                os.remove(sssd_ca_db)
                log(f"Removed Sentinel-installed {sssd_ca_db}")
        except OSError:
            pass

    if distro_family == "fedora" and shutil.which("authselect"):
        if os.path.isdir("/var/lib/authselect/backups/sentinel_backup"):
            res = subprocess.run(
                ["authselect", "backup-restore", "sentinel_backup"],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                log("Restored pre-Sentinel authselect profile from sentinel_backup")
            else:
                ok = False
    elif distro_family == "debian" and shutil.which("pam-auth-update"):
        if os.path.isfile("/usr/share/pam-configs/sss-smart-card-optional"):
            subprocess.run(
                ["pam-auth-update", "--package", "--remove", "sss-smart-card-optional"],
                capture_output=True,
                text=True,
            )

    return ok


def uninstall_system_configuration(distro_family: str) -> bool:
    """Revert Sentinel system configuration, remove Sentinel-installed DoD CAs, and restore policies."""
    log("Reverting Sentinel CAC Manager system configuration and removing trust...")
    all_ok = True

    # 1. Remove ONLY Sentinel-owned system CA certificates (never rmtree shared directories)
    if distro_family == "debian":
        for d in ["/usr/local/share/ca-certificates/dod", "/usr/local/share/ca-certificates/dow"]:
            if os.path.isdir(d):
                removed = _clean_sentinel_owned_certs_in_dir(d, keep_roots=False)
                log(f"Removed {removed} Sentinel-managed certificate(s) from {d}")
        res = subprocess.run(["update-ca-certificates", "--fresh"], capture_output=True, text=True)
        log(f"Rebuilt system CA trust store: {res.stdout.strip()}")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "fedora":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/pki/ca-trust/source/anchors", old)
            if _remove_or_restore_sentinel_cert_file(p):
                log(f"Removed {p}")
        res = subprocess.run(["update-ca-trust"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with update-ca-trust.")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "arch":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/ca-certificates/trust-source/anchors", old)
            if _remove_or_restore_sentinel_cert_file(p):
                log(f"Removed {p}")
        res = subprocess.run(["trust", "extract-compat"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with trust extract-compat.")
        if res.returncode != 0:
            all_ok = False
    elif distro_family == "suse":
        for old in ["DoD_Roots.pem", "DoD_Full_Chain.pem", "DoW_Roots.pem", "DoW_Full_Chain.pem"]:
            p = os.path.join("/etc/pki/trust/anchors", old)
            if _remove_or_restore_sentinel_cert_file(p):
                log(f"Removed {p}")
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        log("Rebuilt system CA trust store with update-ca-certificates.")
        if res.returncode != 0:
            all_ok = False

    # Remove ONLY manifest-verified certificate files in /usr/share/sentinel/certificates (never rmtree)
    for sub in [
        "/usr/share/sentinel/certificates/roots",
        "/usr/share/sentinel/certificates/intermediates",
        "/usr/share/sentinel/certificates/all_cas",
        "/usr/share/sentinel/certificates",
    ]:
        if os.path.isdir(sub):
            _clean_sentinel_owned_certs_in_dir(sub, keep_roots=False)
    if os.path.isdir("/usr/share/sentinel") and not os.listdir("/usr/share/sentinel"):
        try:
            os.rmdir("/usr/share/sentinel")
        except OSError:
            pass

    # 2. Revert Firefox enterprise policies non-destructively
    policy_targets = [
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
        "/var/snap/firefox/common/policies/policies.json",
    ]
    for target in policy_targets:
        if not revert_firefox_policy_file(target):
            all_ok = False

    # 3. Revert system p11-kit module
    for p11_file in ["/etc/pkcs11/modules/sentinel-opensc.module", "/etc/pkcs11/modules/opensc.module"]:
        if os.path.isfile(p11_file):
            try:
                with open(p11_file, "r", encoding="utf-8", errors="replace") as f:
                    c = f.read()
                if "Sentinel" in c or os.path.basename(p11_file) == "sentinel-opensc.module":
                    os.remove(p11_file)
                    log(f"Removed system p11-kit module config: {p11_file}")
            except Exception:
                pass

    # 4. Revert OpenSC config if backup exists
    for conf_cand in ["/etc/opensc/opensc.conf", "/etc/opensc.conf"]:
        bak = f"{conf_cand}.sentinel-bak"
        if os.path.isfile(bak):
            try:
                shutil.copy2(bak, conf_cand)
                os.remove(bak)
                log(f"Restored original OpenSC configuration from {bak}")
            except Exception as e:
                log(f"Note restoring OpenSC config: {e}")

    # 5. Clean up any legacy SSSD/PAM smart card logon state from earlier versions
    cleanup_legacy_smartcard_logon(distro_family)

    # 6. Remove Polkit policy and helper from /usr/libexec/sentinel
    polkit_policy = "/usr/share/polkit-1/actions/com.codefxr.sentinel.policy"
    if os.path.isfile(polkit_policy):
        try:
            os.remove(polkit_policy)
            log(f"Removed {polkit_policy}")
        except OSError:
            pass

    helper_path = "/usr/libexec/sentinel/privileged_helper.py"
    if os.path.isfile(helper_path):
        try:
            os.remove(helper_path)
            log("Removed /usr/libexec/sentinel/privileged_helper.py")
            if os.path.isdir("/usr/libexec/sentinel") and not os.listdir("/usr/libexec/sentinel"):
                os.rmdir("/usr/libexec/sentinel")
        except Exception:
            pass

    log("System-level uninstallation and trust rollback complete.")
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Sentinel Root Helper")
    parser.add_argument("--family", default="debian", help="distro family (debian/fedora/arch/suse)")
    parser.add_argument("--module", default=None, help="path to opensc module")
    parser.add_argument("--certs-dir", default=None, help="path to source certificates directory")
    parser.add_argument("--all", action="store_true", help="run all root setup steps")
    parser.add_argument("--packages", action="store_true", help="install system packages")
    parser.add_argument("--certs", action="store_true", help="install system certs only")
    parser.add_argument("--service", action="store_true", help="enable pcscd only")
    parser.add_argument("--reader-fix", action="store_true", help="fix opensc.conf only")
    parser.add_argument("--policies", action="store_true", help="install policies only")
    parser.add_argument("--disable-logon", action="store_true", help="roll back legacy v2.0.0 PAM/SSSD logon")
    parser.add_argument("--sync-helper", action="store_true", help="install/sync helper into /usr/libexec/sentinel")
    parser.add_argument("--uninstall", action="store_true", help="revert system changes and remove DoD trust")

    args = parser.parse_args()

    if os.geteuid() != 0:
        log("ERROR: This helper must be run as root (via pkexec or sudo).")
        return 1

    if args.uninstall:
        ok = uninstall_system_configuration(args.family)
        return 0 if ok else 1

    if args.disable_logon:
        ok = cleanup_legacy_smartcard_logon(args.family)
        return 0 if ok else 1

    global CERTS_DIR, ALL_CAS_DIR, FULL_CHAIN_PEM, FULL_CHAIN_CRT
    if args.certs_dir:
        CERTS_DIR = get_certs_dir(args.certs_dir)
        ALL_CAS_DIR = os.path.join(CERTS_DIR, "all_cas")
        FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoD_Full_Chain.pem")
        if not os.path.isfile(FULL_CHAIN_PEM):
            FULL_CHAIN_PEM = os.path.join(CERTS_DIR, "DoW_Full_Chain.pem")
        FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoD_Full_Chain.crt")
        if not os.path.isfile(FULL_CHAIN_CRT):
            FULL_CHAIN_CRT = os.path.join(CERTS_DIR, "DoW_Full_Chain.crt")

    # Only sync system helper when explicitly requested during administrative install (SEC-02)
    if args.sync_helper:
        ensure_system_helper()

    pkgs_ok = True
    if args.packages or args.all:
        pkgs_ok = install_system_packages(args.family)

    svc_ok = True
    if args.all or args.service:
        svc_ok = enable_pcscd()

    reader_ok = True
    if args.all or args.reader_fix:
        reader_ok = fix_opensc_hang()

    certs_ok = True
    if args.all or args.certs:
        certs_ok = install_system_certificates(args.family)

    policies_ok = True
    if args.all or args.policies:
        mod_path = validate_pkcs11_module_path(args.module)
        if not mod_path:
            log("ERROR: Invalid PKCS#11 module path supplied.")
            return 3
        ff_ok = install_firefox_policies(mod_path, args.family)
        p11_ok = install_p11_kit_module(mod_path)
        policies_ok = ff_ok and p11_ok
        connect_snap_firefox()

    reset_smartcard_atr()

    if not pkgs_ok:
        log("ERROR: System middleware package installation failed.")
        return 4

    if not svc_ok:
        log("ERROR: pcscd service or socket activation failed.")
        return 5

    if not reader_ok:
        log("ERROR: OpenSC configuration optimization failed.")
        return 6

    if not certs_ok:
        log("ERROR: Certificate installation into system trust store encountered errors.")
        return 2

    if not policies_ok:
        log("ERROR: Browser policy or PKCS#11 module installation encountered errors.")
        return 3

    log("Elevated system configuration complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
