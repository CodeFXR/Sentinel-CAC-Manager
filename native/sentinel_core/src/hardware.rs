use libloading::{Library, Symbol};
use pyo3::prelude::*;
use regex::Regex;
use std::ffi::{c_char, c_void, CString};

pub const SCARD_SCOPE_SYSTEM: u32 = 2;
pub const SCARD_SCOPE_USER: u32 = 0;
pub const SCARD_S_SUCCESS: i64 = 0;
pub const SCARD_STATE_UNAWARE: u32 = 0x0000;
pub const SCARD_STATE_PRESENT: u32 = 0x0020;

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

struct PcscSymbols {
    _lib: Library,
    establish_context: SCardEstablishContextFn,
    release_context: SCardReleaseContextFn,
    list_readers: SCardListReadersFn,
    get_status_change: SCardGetStatusChangeFn,
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
                        return Some(PcscSymbols {
                            establish_context: *e,
                            release_context: *r,
                            list_readers: *l,
                            get_status_change: *s,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atr_detection() {
        assert!(is_cac_or_piv_atr("3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"));
        assert!(!is_cac_or_piv_atr("3b:00:00:00"));
    }

    #[test]
    fn test_native_pcsc_query_does_not_crash() {
        let status = query_native_pcsc_status();
        // Regardless of whether a physical reader is connected, it must safely return without panicking
        println!("PC/SC status: {:?}", status);
    }
}
