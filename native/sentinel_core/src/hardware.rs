use libloading::{Library, Symbol};
use pyo3::prelude::*;
use regex::Regex;
use std::ffi::{c_char, c_void, CString};

pub const SCARD_SCOPE_SYSTEM: u32 = 2;
pub const SCARD_SCOPE_USER: u32 = 0;
pub const SCARD_SHARE_SHARED: u32 = 2;
pub const SCARD_PROTOCOL_T0: u32 = 1;
pub const SCARD_PROTOCOL_T1: u32 = 2;
pub const SCARD_LEAVE_CARD: u32 = 0;
pub const SCARD_S_SUCCESS: i64 = 0;
pub const SCARD_STATE_UNAWARE: u32 = 0x0000;
pub const SCARD_STATE_PRESENT: u32 = 0x0020;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SCARD_IO_REQUEST {
    pub dw_protocol: usize,
    pub cb_pci_length: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SCARD_READERSTATE {
    pub sz_reader: *const c_char,
    pub pv_user_data: *mut c_void,
    pub dw_current_state: u32,
    pub dw_event_state: u32,
    pub cb_atr: u32,
    pub rgb_atr: [u8; 33],
}

type SCardEstablishContextFn = unsafe extern "C" fn(
    scope: u32,
    r1: *const c_void,
    r2: *const c_void,
    ph_context: *mut i64,
) -> i64;

type SCardReleaseContextFn = unsafe extern "C" fn(h_context: i64) -> i64;

type SCardListReadersFn = unsafe extern "C" fn(
    h_context: i64,
    msz_groups: *const c_char,
    msz_readers: *mut c_char,
    pcch_readers: *mut u32,
) -> i64;

type SCardGetStatusChangeFn = unsafe extern "C" fn(
    h_context: i64,
    dw_timeout: u32,
    rg_reader_states: *mut SCARD_READERSTATE,
    c_readers: u32,
) -> i64;

type SCardConnectFn = unsafe extern "C" fn(
    h_context: i64,
    sz_reader: *const c_char,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    ph_card: *mut i64,
    pdw_active_protocol: *mut u32,
) -> i64;

type SCardDisconnectFn = unsafe extern "C" fn(h_card: i64, dw_disposition: u32) -> i64;

type SCardTransmitFn = unsafe extern "C" fn(
    h_card: i64,
    pio_send_pci: *const SCARD_IO_REQUEST,
    pb_send_buffer: *const u8,
    cb_send_length: u32,
    pio_recv_pci: *mut SCARD_IO_REQUEST,
    pb_recv_buffer: *mut u8,
    pcb_recv_length: *mut u32,
) -> i64;

struct PcscSymbols {
    _lib: Library,
    establish_context: SCardEstablishContextFn,
    release_context: SCardReleaseContextFn,
    list_readers: SCardListReadersFn,
    get_status_change: SCardGetStatusChangeFn,
    connect: Option<SCardConnectFn>,
    disconnect: Option<SCardDisconnectFn>,
    transmit: Option<SCardTransmitFn>,
}

impl PcscSymbols {
    fn try_load() -> Option<Self> {
        let candidates = [
            "libpcsclite.so.1",
            "libpcsclite.so",
            "/lib64/libpcsclite.so.1",
            "/usr/lib64/libpcsclite.so.1",
            "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
            "/usr/lib/libpcsclite.so.1",
        ];

        for path in &candidates {
            if let Ok(lib) = unsafe { Library::new(path) } {
                unsafe {
                    let establish: Result<Symbol<SCardEstablishContextFn>, _> =
                        lib.get(b"SCardEstablishContext");
                    let release: Result<Symbol<SCardReleaseContextFn>, _> =
                        lib.get(b"SCardReleaseContext");
                    let list: Result<Symbol<SCardListReadersFn>, _> =
                        lib.get(b"SCardListReaders");
                    let status: Result<Symbol<SCardGetStatusChangeFn>, _> =
                        lib.get(b"SCardGetStatusChange");

                    if let (Ok(e), Ok(r), Ok(l), Ok(s)) = (establish, release, list, status) {
                        let connect = lib.get(b"SCardConnect").ok().map(|sym: Symbol<SCardConnectFn>| *sym);
                        let disconnect = lib.get(b"SCardDisconnect").ok().map(|sym: Symbol<SCardDisconnectFn>| *sym);
                        let transmit = lib.get(b"SCardTransmit").ok().map(|sym: Symbol<SCardTransmitFn>| *sym);

                        return Some(PcscSymbols {
                            establish_context: *e,
                            release_context: *r,
                            list_readers: *l,
                            get_status_change: *s,
                            connect,
                            disconnect,
                            transmit,
                            _lib: lib,
                        });
                    }
                }
            }
        }
        None
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyNativePcscStatus {
    #[pyo3(get)]
    pub available: bool,
    #[pyo3(get)]
    pub service_running: bool,
    #[pyo3(get)]
    pub readers: Vec<String>,
    #[pyo3(get)]
    pub card_present: bool,
    #[pyo3(get)]
    pub primary_reader: Option<String>,
    #[pyo3(get)]
    pub atr: Option<String>,
    #[pyo3(get)]
    pub is_cac: bool,
}

#[pymethods]
impl PyNativePcscStatus {
    fn __repr__(&self) -> String {
        format!(
            "<NativePcscStatus available={} service={} readers={} card_present={}>",
            self.available,
            self.service_running,
            self.readers.len(),
            self.card_present
        )
    }
}

/// Query hardware status directly via PC/SC Lite C API without subprocesses.
pub fn query_native_pcsc_status() -> PyNativePcscStatus {
    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => {
            return PyNativePcscStatus {
                available: false,
                service_running: false,
                readers: Vec::new(),
                card_present: false,
                primary_reader: None,
                atr: None,
                is_cac: false,
            };
        }
    };

    let mut context: i64 = 0;
    // Attempt system scope first, then user scope
    let rc = unsafe {
        (symbols.establish_context)(
            SCARD_SCOPE_SYSTEM,
            std::ptr::null(),
            std::ptr::null(),
            &mut context,
        )
    };

    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut context,
            )
        };
        if rc_user != SCARD_S_SUCCESS {
            return PyNativePcscStatus {
                available: true,
                service_running: false,
                readers: Vec::new(),
                card_present: false,
                primary_reader: None,
                atr: None,
                is_cac: false,
            };
        }
        context
    };

    // Context established -> pcscd is running
    let mut cch: u32 = 0;
    let list_rc = unsafe {
        (symbols.list_readers)(
            context,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut cch,
        )
    };

    let mut readers = Vec::new();
    if list_rc == SCARD_S_SUCCESS && cch > 0 {
        let mut buf = vec![0u8; cch as usize];
        let list_rc2 = unsafe {
            (symbols.list_readers)(
                context,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut c_char,
                &mut cch,
            )
        };

        if list_rc2 == SCARD_S_SUCCESS {
            // Buffer contains null-separated strings ending with \0\0
            let mut start = 0;
            for i in 0..buf.len() {
                if buf[i] == 0 {
                    if i > start {
                        if let Ok(s) = std::str::from_utf8(&buf[start..i]) {
                            let trimmed = s.trim();
                            if !trimmed.is_empty() {
                                readers.push(trimmed.to_string());
                            }
                        }
                    }
                    start = i + 1;
                }
            }
        }
    }

    let mut card_present = false;
    let mut primary_reader = None;
    let mut found_atr = None;
    let mut is_cac = false;

    for r_name in &readers {
        if let Ok(c_name) = CString::new(r_name.as_str()) {
            let mut state = SCARD_READERSTATE {
                sz_reader: c_name.as_ptr(),
                pv_user_data: std::ptr::null_mut(),
                dw_current_state: SCARD_STATE_UNAWARE,
                dw_event_state: 0,
                cb_atr: 0,
                rgb_atr: [0u8; 33],
            };

            let st_rc = unsafe {
                (symbols.get_status_change)(context, 0, &mut state, 1)
            };

            if st_rc == SCARD_S_SUCCESS && (state.dw_event_state & SCARD_STATE_PRESENT) != 0 {
                card_present = true;
                primary_reader = Some(r_name.clone());
                if state.cb_atr > 0 && state.cb_atr <= 33 {
                    let atr_bytes = &state.rgb_atr[..state.cb_atr as usize];
                    let atr_hex = atr_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    is_cac = is_cac_or_piv_atr(&atr_hex);
                    found_atr = Some(atr_hex);
                }
                break;
            }
        }
    }

    if primary_reader.is_none() && !readers.is_empty() {
        primary_reader = Some(readers[0].clone());
    }

    unsafe {
        (symbols.release_context)(context);
    }

    PyNativePcscStatus {
        available: true,
        service_running: true,
        readers,
        card_present,
        primary_reader,
        atr: found_atr,
        is_cac,
    }
}

/// Checks if an ATR matches known DoD CAC or PIV smart card profiles.
pub fn is_cac_or_piv_atr(raw_atr: &str) -> bool {
    let clean = raw_atr.replace([':', ' ', '-'], "").to_lowercase();
    // Known historical and modern CAC / PIV ATR prefixes
    clean.starts_with("3b7d96")
        || clean.starts_with("3bdb96")
        || clean.starts_with("3b7b94")
        || clean.starts_with("3b7d94")
        || clean.starts_with("3bf818")
        || clean.starts_with("3bfa18")
}

/// Parses the output of `pkcs15-tool -c` into (id, label) tuples.
pub fn parse_pkcs15_tool_list(output: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current_id = None;
    let mut current_label = None;

    let re_id = Regex::new(r"^\s*ID\s*:\s*([a-fA-F0-9]+)").unwrap();
    let re_label = Regex::new(r"^\s*Label\s*:\s*(.+)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re_id.captures(line) {
            current_id = Some(caps[1].trim().to_string());
        } else if let Some(caps) = re_label.captures(line) {
            current_label = Some(caps[1].trim().to_string());
        }

        if let (Some(id), Some(label)) = (current_id.as_ref(), current_label.as_ref()) {
            pairs.push((id.clone(), label.clone()));
            current_id = None;
            current_label = None;
        }
    }

    pairs
}

/// Extracts the raw X.509 DER certificate bytes from a NIST SP 800-73-4 PIV container.
///
/// Supports:
/// 1. PIV compressed certificates (Tag 0x71, GZIP decompression)
/// 2. PIV uncompressed certificates (Tag 0x70 / 0x53 BER-TLV wrapper)
/// 3. Raw ASN.1 sequence headers (0x30 0x82, 0x30 0x81, 0x30 0x83)
pub fn extract_cert_from_piv_container(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }

    // 1. Check for GZIP compression anywhere in payload (PIV Tag 0x71 compressed format)
    for i in 0..payload.len().saturating_sub(2) {
        if payload[i] == 0x1F && payload[i + 1] == 0x8B {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&payload[i..]);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok()
                && !decompressed.is_empty()
                && decompressed[0] == 0x30
                && x509_parser::parse_x509_certificate(&decompressed).is_ok()
            {
                return Some(decompressed);
            }
        }
    }

    // 2. Scan for ASN.1 DER SEQUENCE (0x30 0x82 / 0x30 0x81 / 0x30 0x83)
    let len = payload.len();
    for i in 0..len.saturating_sub(4) {
        if payload[i] == 0x30 {
            let cert_len = if payload[i + 1] == 0x82 && i + 4 <= len {
                let hi = payload[i + 2] as usize;
                let lo = payload[i + 3] as usize;
                4 + (hi << 8 | lo)
            } else if payload[i + 1] == 0x81 && i + 3 <= len {
                3 + (payload[i + 2] as usize)
            } else if payload[i + 1] == 0x83 && i + 5 <= len {
                let b1 = payload[i + 2] as usize;
                let b2 = payload[i + 3] as usize;
                let b3 = payload[i + 4] as usize;
                5 + (b1 << 16 | b2 << 8 | b3)
            } else {
                continue;
            };

            if cert_len >= 64 && i + cert_len <= len {
                let candidate = &payload[i..i + cert_len];
                if x509_parser::parse_x509_certificate(candidate).is_ok() {
                    return Some(candidate.to_vec());
                }
            }
        }
    }

    None
}

fn transmit_apdu(
    transmit_fn: SCardTransmitFn,
    h_card: i64,
    active_proto: u32,
    apdu: &[u8],
) -> Result<Vec<u8>, i64> {
    let pci = SCARD_IO_REQUEST {
        dw_protocol: active_proto as usize,
        cb_pci_length: std::mem::size_of::<SCARD_IO_REQUEST>(),
    };
    let mut recv_buf = vec![0u8; 4096];
    let mut recv_len: u32 = recv_buf.len() as u32;

    let rc = unsafe {
        transmit_fn(
            h_card,
            &pci,
            apdu.as_ptr(),
            apdu.len() as u32,
            std::ptr::null_mut(),
            recv_buf.as_mut_ptr(),
            &mut recv_len,
        )
    };

    if rc != SCARD_S_SUCCESS {
        return Err(rc);
    }
    recv_buf.truncate(recv_len as usize);
    Ok(recv_buf)
}

fn read_piv_container_data(
    transmit_fn: SCardTransmitFn,
    h_card: i64,
    active_proto: u32,
    tag: [u8; 3],
) -> Option<Vec<u8>> {
    // GET DATA APDU: 00 CB 3F FF 05 5C 03 [tag0] [tag1] [tag2] 00
    let get_data_apdu = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, tag[0], tag[1], tag[2], 0x00];
    let mut resp = match transmit_apdu(transmit_fn, h_card, active_proto, &get_data_apdu) {
        Ok(r) => r,
        Err(_) => return None,
    };

    if resp.len() < 2 {
        return None;
    }

    let mut sw1 = resp[resp.len() - 2];
    let mut sw2 = resp[resp.len() - 1];

    // If 0x6C XX: wrong Le, retry with exact Le = sw2
    if sw1 == 0x6C {
        let retry_apdu = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, tag[0], tag[1], tag[2], sw2];
        resp = match transmit_apdu(transmit_fn, h_card, active_proto, &retry_apdu) {
            Ok(r) => r,
            Err(_) => return None,
        };
        if resp.len() < 2 {
            return None;
        }
        sw1 = resp[resp.len() - 2];
        sw2 = resp[resp.len() - 1];
    }

    if sw1 != 0x90 && sw1 != 0x61 {
        return None;
    }

    let mut container_bytes = Vec::new();
    container_bytes.extend_from_slice(&resp[..resp.len() - 2]);

    // Handle 0x61 XX pagination with GET RESPONSE
    let mut iterations = 0;
    while sw1 == 0x61 && iterations < 100 {
        iterations += 1;
        let get_response_apdu = [0x00, 0xC0, 0x00, 0x00, sw2];
        let chunk = match transmit_apdu(transmit_fn, h_card, active_proto, &get_response_apdu) {
            Ok(c) => c,
            Err(_) => break,
        };
        if chunk.len() < 2 {
            break;
        }
        sw1 = chunk[chunk.len() - 2];
        sw2 = chunk[chunk.len() - 1];
        container_bytes.extend_from_slice(&chunk[..chunk.len() - 2]);
        if sw1 == 0x90 && sw2 == 0x00 {
            break;
        }
    }

    if container_bytes.is_empty() {
        None
    } else {
        Some(container_bytes)
    }
}

/// Discovers and reads digital certificates from a physical smart card via direct in-process
/// NIST SP 800-73-4 PIV APDUs, eliminating external pkcs15-tool or opensc subprocess dependencies.
pub fn read_piv_certificates_native(reader_opt: Option<&str>) -> Vec<crate::cert::PyCardCertificate> {
    let mut results = Vec::new();
    let symbols = match PcscSymbols::try_load() {
        Some(s) => s,
        None => return results,
    };

    let (connect_fn, disconnect_fn, transmit_fn) = match (symbols.connect, symbols.disconnect, symbols.transmit) {
        (Some(c), Some(d), Some(t)) => (c, d, t),
        _ => return results,
    };

    let mut context: i64 = 0;
    let rc = unsafe {
        (symbols.establish_context)(
            SCARD_SCOPE_SYSTEM,
            std::ptr::null(),
            std::ptr::null(),
            &mut context,
        )
    };

    let context = if rc == SCARD_S_SUCCESS {
        context
    } else {
        let rc_user = unsafe {
            (symbols.establish_context)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut context,
            )
        };
        if rc_user != SCARD_S_SUCCESS {
            return results;
        }
        context
    };

    // Determine target reader
    let target_reader = if let Some(r) = reader_opt {
        r.to_string()
    } else {
        let mut cch: u32 = 0;
        let list_rc = unsafe {
            (symbols.list_readers)(context, std::ptr::null(), std::ptr::null_mut(), &mut cch)
        };
        if list_rc != SCARD_S_SUCCESS || cch == 0 {
            unsafe { (symbols.release_context)(context); }
            return results;
        }
        let mut buf = vec![0u8; cch as usize];
        let list_rc2 = unsafe {
            (symbols.list_readers)(context, std::ptr::null(), buf.as_mut_ptr() as *mut c_char, &mut cch)
        };
        if list_rc2 != SCARD_S_SUCCESS {
            unsafe { (symbols.release_context)(context); }
            return results;
        }

        let mut readers = Vec::new();
        let mut start = 0;
        for i in 0..buf.len() {
            if buf[i] == 0 {
                if i > start {
                    if let Ok(s) = std::str::from_utf8(&buf[start..i]) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            readers.push(trimmed.to_string());
                        }
                    }
                }
                start = i + 1;
            }
        }

        if readers.is_empty() {
            unsafe { (symbols.release_context)(context); }
            return results;
        }

        // Search for reader with card present
        let mut selected = readers[0].clone();
        for r_name in &readers {
            if let Ok(c_name) = CString::new(r_name.as_str()) {
                let mut state = SCARD_READERSTATE {
                    sz_reader: c_name.as_ptr(),
                    pv_user_data: std::ptr::null_mut(),
                    dw_current_state: SCARD_STATE_UNAWARE,
                    dw_event_state: 0,
                    cb_atr: 0,
                    rgb_atr: [0u8; 33],
                };
                let st_rc = unsafe {
                    (symbols.get_status_change)(context, 0, &mut state, 1)
                };
                if st_rc == SCARD_S_SUCCESS && (state.dw_event_state & SCARD_STATE_PRESENT) != 0 {
                    selected = r_name.clone();
                    break;
                }
            }
        }
        selected
    };

    let c_reader = match CString::new(target_reader.as_str()) {
        Ok(c) => c,
        Err(_) => {
            unsafe { (symbols.release_context)(context); }
            return results;
        }
    };

    let mut h_card: i64 = 0;
    let mut active_proto: u32 = 0;
    let conn_rc = unsafe {
        connect_fn(
            context,
            c_reader.as_ptr(),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
            &mut h_card,
            &mut active_proto,
        )
    };

    if conn_rc != SCARD_S_SUCCESS {
        unsafe { (symbols.release_context)(context); }
        return results;
    }

    // Select PIV Application (try standard 9-byte AID first, then 11-byte AID)
    let piv_aid_9 = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
    let piv_aid_11 = [0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

    let select_ok = if let Ok(resp) = transmit_apdu(transmit_fn, h_card, active_proto, &piv_aid_9) {
        resp.len() >= 2 && (resp[resp.len() - 2] == 0x90 || resp[resp.len() - 2] == 0x61)
    } else {
        false
    };

    if !select_ok {
        let select_11_ok = if let Ok(resp) = transmit_apdu(transmit_fn, h_card, active_proto, &piv_aid_11) {
            resp.len() >= 2 && (resp[resp.len() - 2] == 0x90 || resp[resp.len() - 2] == 0x61)
        } else {
            false
        };
        if !select_11_ok {
            unsafe {
                disconnect_fn(h_card, SCARD_LEAVE_CARD);
                (symbols.release_context)(context);
            }
            return results;
        }
    }

    // PIV AID selected: Query standard NIST SP 800-73-4 certificate containers
    let targets = [
        ([0x5F, 0xC1, 0x05], "0005", "CAC ID / PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        ([0x5F, 0xC1, 0x01], "0001", "PIV Authentication", "DoD Web Logon, PIV Mutual Authentication"),
        ([0x5F, 0xC1, 0x02], "0002", "CAC Email Signature", "S/MIME Digital Email Signing"),
        ([0x5F, 0xC1, 0x03], "0003", "CAC Email Encryption", "S/MIME Key Management and Decryption"),
    ];

    for (tag, id, label, usage) in targets {
        if let Some(container_data) = read_piv_container_data(transmit_fn, h_card, active_proto, tag) {
            if let Some(der_bytes) = extract_cert_from_piv_container(&container_data) {
                if let Ok(py_cert) = crate::cert::parse_der_or_pem_bytes(
                    id.to_string(),
                    label.to_string(),
                    usage.to_string(),
                    &der_bytes,
                ) {
                    results.push(py_cert);
                }
            }
        }
    }

    unsafe {
        disconnect_fn(h_card, SCARD_LEAVE_CARD);
        (symbols.release_context)(context);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_atr_detection() {
        assert!(is_cac_or_piv_atr("3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"));
        assert!(!is_cac_or_piv_atr("3b:00:00:00"));
    }

    #[test]
    fn test_native_pcsc_query_does_not_crash() {
        let status = query_native_pcsc_status();
        println!("PC/SC status: {:?}", status);
    }

    #[test]
    fn test_extract_cert_from_piv_container_der_and_wrapper() {
        // Load real test DoD cert
        let pem_bytes = include_bytes!("../../../certificates/roots/DoD_Root_CA_3.crt");
        let pem_str = std::str::from_utf8(pem_bytes).unwrap();
        let b64 = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>();
        let der = base64_simd_or_standard_decode(&b64);

        // 1. Direct raw DER extraction
        let extracted_raw = extract_cert_from_piv_container(&der);
        assert!(extracted_raw.is_some());
        assert_eq!(extracted_raw.unwrap(), der);

        // 2. Wrapped in NIST PIV Tag 0x70 + Length + EDC Tag 0xFE
        let mut wrapped = vec![0x70, 0x82, (der.len() >> 8) as u8, (der.len() & 0xFF) as u8];
        wrapped.extend_from_slice(&der);
        wrapped.extend_from_slice(&[0xFE, 0x00]); // EDC

        let extracted_wrapped = extract_cert_from_piv_container(&wrapped);
        assert!(extracted_wrapped.is_some());
        assert_eq!(extracted_wrapped.unwrap(), der);

        // 3. Wrapped in GZIP compressed PIV container (Tag 0x71)
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&der).unwrap();
        let gz_bytes = encoder.finish().unwrap();

        let mut gz_container = vec![0x71, 0x82, (gz_bytes.len() >> 8) as u8, (gz_bytes.len() & 0xFF) as u8];
        gz_container.extend_from_slice(&gz_bytes);
        gz_container.extend_from_slice(&[0xFE, 0x00]);

        let extracted_gz = extract_cert_from_piv_container(&gz_container);
        assert!(extracted_gz.is_some());
        assert_eq!(extracted_gz.unwrap(), der);
    }

    fn base64_simd_or_standard_decode(b64: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for c in b64.chars() {
            let val = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '+' => 62,
                '/' => 63,
                '=' | '\r' | '\n' | ' ' => continue,
                _ => continue,
            };
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        out
    }
}
