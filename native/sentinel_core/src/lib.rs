pub mod cert;
pub mod hardware;
pub mod security;

use pyo3::prelude::*;

use cert::{parse_der_or_pem_bytes, PyCardCertificate};
use hardware::{
    change_piv_pin_native, is_cac_or_piv_atr, parse_pkcs15_tool_list,
    query_native_pcsc_status, query_piv_pin_status, read_piv_certificates_native,
    wait_for_smartcard_event, PyNativePcscStatus,
};
use security::PinBuffer;

#[pyfunction]
fn version() -> &'static str {
    "2.0.0"
}

#[pyfunction]
fn parse_certificate(
    id: String,
    label: String,
    usage: String,
    data: &[u8],
) -> PyResult<PyCardCertificate> {
    parse_der_or_pem_bytes(id, label, usage, data)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn read_card_certificates(reader: Option<String>) -> Vec<PyCardCertificate> {
    read_piv_certificates_native(reader.as_deref())
}

#[pyfunction]
fn query_pin_status(reader: Option<String>) -> (bool, u8, String) {
    query_piv_pin_status(reader.as_deref())
}

#[pyfunction]
fn change_pin(old_pin: String, new_pin: String, reader: Option<String>) -> (bool, u8, String) {
    change_piv_pin_native(reader.as_deref(), &old_pin, &new_pin)
}

#[pyfunction]
fn wait_for_card_event(timeout_ms: u32) -> Option<(String, bool)> {
    wait_for_smartcard_event(timeout_ms)
}

#[pyfunction]
fn parse_pkcs15_list(output: &str) -> Vec<(String, String)> {
    parse_pkcs15_tool_list(output)
}

#[pyfunction]
fn is_cac_atr(atr: &str) -> bool {
    is_cac_or_piv_atr(atr)
}

#[pyfunction]
fn query_native_pcsc() -> PyNativePcscStatus {
    query_native_pcsc_status()
}

#[pymodule]
fn sentinel_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(parse_certificate, m)?)?;
    m.add_function(wrap_pyfunction!(read_card_certificates, m)?)?;
    m.add_function(wrap_pyfunction!(query_pin_status, m)?)?;
    m.add_function(wrap_pyfunction!(change_pin, m)?)?;
    m.add_function(wrap_pyfunction!(wait_for_card_event, m)?)?;
    m.add_function(wrap_pyfunction!(parse_pkcs15_list, m)?)?;
    m.add_function(wrap_pyfunction!(is_cac_atr, m)?)?;
    m.add_function(wrap_pyfunction!(query_native_pcsc, m)?)?;
    m.add_class::<PyCardCertificate>()?;
    m.add_class::<PyNativePcscStatus>()?;
    m.add_class::<PinBuffer>()?;
    Ok(())
}
