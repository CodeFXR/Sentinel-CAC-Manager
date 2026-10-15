use pyo3::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory-hardened buffer for sensitive credentials (PINs/PUKs).
/// Scans and zeros out allocated memory when dropped.
#[pyclass]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinBuffer {
    #[zeroize(skip)]
    len: usize,
    buffer: Vec<u8>,
}

#[pymethods]
impl PinBuffer {
    #[new]
    pub fn new(pin: &str) -> Self {
        let bytes = pin.as_bytes().to_vec();
        let len = bytes.len();
        Self { len, buffer: bytes }
    }

    pub fn length(&self) -> usize {
        self.len
    }

    pub fn __len__(&self) -> usize {
        self.len
    }

    pub fn is_valid_pin_format(&self) -> bool {
        self.len >= 6 && self.len <= 8 && self.buffer.iter().all(|b| b.is_ascii_digit())
    }

    pub fn scrub(&mut self) {
        self.buffer.zeroize();
        self.len = 0;
    }

    fn __repr__(&self) -> String {
        "<PinBuffer [REDACTED: MEMORY PROTECTED]>".to_string()
    }
}
