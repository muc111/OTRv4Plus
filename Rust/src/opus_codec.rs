// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The Opus codec for the Android APK: upstream libopus, statically linked.
//!
//! WHY THIS EXISTS
//! ===============
//! Voice encodes 20/60 ms PCM frames with Opus before they are sealed by the
//! voice cipher (`voice.rs`) and sent as I2P datagrams. The Termux client gets
//! Opus from the Python package `opuslib`, a ctypes wrapper over Termux's
//! `libopus.so` (`otrv4plus_xmpp._load_opus`). An APK has neither: Chaquopy
//! ships no `opuslib`, and Android's own libopus is a private platform library
//! an app may not load. So the APK had no codec at all, and the Android call
//! path asked the Termux question -- "is opuslib installed?" -- and answered
//! the user with the Termux remedy (`pip install opuslib`).
//!
//! This is built only with the `android-opus` feature, which the Android CI
//! build enables. The Termux build (`Rust/build.sh`) does not, and keeps using
//! `opuslib` exactly as before.
//!
//! WHAT IT IS NOT
//! ==============
//! No `unsafe` here: the libopus FFI is in the `otrv4-opus-codec` crate
//! (Rust/opus-codec), so this crate keeps `#![forbid(unsafe_code)]`.
//!
//! Not cryptography. Opus turns PCM into compressed frames and back; it holds
//! no key and sees nothing the microphone did not already produce. Sealing,
//! the ratchet, rekey and the datagram transport are untouched and remain in
//! `voice.rs` and `otrv4plus_voice.py`.
//!
//! THE INTERFACE IS OPUSLIB'S
//! ==========================
//! `OpusEncoder` / `OpusDecoder` take the same constructor arguments, the same
//! `encode(pcm, frame_size)` / `decode(data, frame_size, decode_fec=False)`
//! calls, and the same settable attributes (`bitrate`, `vbr`, `dtx`,
//! `inband_fec`, `packet_loss_perc`, `complexity`, `signal`, `bandwidth`) that
//! `VoiceCallManager._build_codec` sets through `setattr`. That is what lets
//! the voice pipeline stay one pipeline for both platforms: the Android host
//! hands the manager this codec where Termux hands it opuslib.

use otrv4_opus_codec as codec;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn err(e: codec::OpusError) -> PyErr {
    match e {
        codec::OpusError::Argument(a) => PyValueError::new_err(a),
        codec::OpusError::Codec(c) => PyRuntimeError::new_err(format!("opus error {}", c)),
    }
}

/// opuslib-compatible encoder over libopus.
#[pyclass(module = "otrv4_core")]
pub struct OpusEncoder {
    inner: codec::Encoder,
}

impl OpusEncoder {
    fn ctl(&mut self, c: codec::Ctl, v: i32) -> PyResult<()> {
        self.inner.set(c, v).map_err(err)
    }
}

#[pymethods]
impl OpusEncoder {
    #[new]
    fn new(sample_rate: i32, channels: i32, application: i32) -> PyResult<Self> {
        Ok(Self { inner: codec::Encoder::new(sample_rate, channels, application).map_err(err)? })
    }

    /// Encode one frame of interleaved signed 16-bit little-endian PCM.
    fn encode<'py>(&mut self, py: Python<'py>, pcm: &[u8], frame_size: i32) -> PyResult<Bound<'py, PyBytes>> {
        if pcm.len() % 2 != 0 {
            return Err(PyValueError::new_err("PCM is not whole 16-bit samples"));
        }
        let samples: Vec<i16> = pcm.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]])).collect();
        let out = self.inner.encode(&samples, frame_size).map_err(err)?;
        Ok(PyBytes::new(py, &out))
    }

    #[setter]
    fn set_bitrate(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::Bitrate, v) }
    #[setter]
    fn set_vbr(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::Vbr, v) }
    #[setter]
    fn set_dtx(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::Dtx, v) }
    #[setter]
    fn set_inband_fec(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::InbandFec, v) }
    #[setter]
    fn set_packet_loss_perc(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::PacketLossPerc, v) }
    #[setter]
    fn set_complexity(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::Complexity, v) }
    #[setter]
    fn set_signal(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::Signal, v) }
    #[setter]
    fn set_bandwidth(&mut self, v: i32) -> PyResult<()> { self.ctl(codec::Ctl::Bandwidth, v) }
}

/// opuslib-compatible decoder over libopus.
#[pyclass(module = "otrv4_core")]
pub struct OpusDecoder {
    inner: codec::Decoder,
}

#[pymethods]
impl OpusDecoder {
    #[new]
    fn new(sample_rate: i32, channels: i32) -> PyResult<Self> {
        Ok(Self { inner: codec::Decoder::new(sample_rate, channels).map_err(err)? })
    }

    /// Decode one packet to interleaved s16le PCM. `data=None` (or empty) is
    /// packet-loss concealment; `decode_fec=True` recovers the previous frame
    /// from this packet's in-band FEC.
    #[pyo3(signature = (data, frame_size, decode_fec=false))]
    fn decode<'py>(&mut self, py: Python<'py>, data: Option<&[u8]>, frame_size: i32,
                   decode_fec: bool) -> PyResult<Bound<'py, PyBytes>> {
        let pcm = self.inner.decode(data, frame_size, decode_fec).map_err(err)?;
        let mut bytes = Vec::with_capacity(pcm.len() * 2);
        for s in pcm {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        Ok(PyBytes::new(py, &bytes))
    }
}

/// The libopus version string, e.g. "libopus 1.5.2".
#[pyfunction]
pub fn opus_version() -> String {
    codec::version()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OpusEncoder>()?;
    m.add_class::<OpusDecoder>()?;
    m.add_function(wrap_pyfunction!(opus_version, m)?)?;
    m.add("OPUS_APPLICATION_VOIP", codec::APPLICATION_VOIP)?;
    m.add("OPUS_SIGNAL_VOICE", codec::SIGNAL_VOICE)?;
    m.add("OPUS_BANDWIDTH_WIDEBAND", codec::BANDWIDTH_WIDEBAND)?;
    Ok(())
}
