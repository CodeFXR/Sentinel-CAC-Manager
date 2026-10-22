pub mod cert;
pub mod hardware;
pub mod security;

use pyo3::prelude::*;

use cert::{parse_der_or_pem_bytes, PyCardCertificate};
use hardware::{is_cac_or_piv_atr, parse_pkcs15_tool_list, query_native_pcsc_status, PyNativePcscStatus};
use security::PinBuffer;

#[pyfunction]
fn version() -> &'static str {
    "1.4.0"
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
    m.add_function(wrap_pyfunction!(parse_pkcs15_list, m)?)?;
    m.add_function(wrap_pyfunction!(is_cac_atr, m)?)?;
    m.add_function(wrap_pyfunction!(query_native_pcsc, m)?)?;
    m.add_class::<PyCardCertificate>()?;
    m.add_class::<PyNativePcscStatus>()?;
    m.add_class::<PinBuffer>()?;
    Ok(())
}
