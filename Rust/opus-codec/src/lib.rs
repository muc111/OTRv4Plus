// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Safe Opus encoder/decoder over libopus (opusic-sys).
//!
//! Every `unsafe` block is an FFI call whose preconditions are established
//! right beside it: a live, exclusively owned handle, and buffers of exactly
//! the length passed. The handles are freed once, in `Drop`.

#![deny(unsafe_op_in_unsafe_fn)]

use opusic_sys as ffi;

pub const APPLICATION_VOIP: i32 = ffi::OPUS_APPLICATION_VOIP;
pub const SIGNAL_VOICE: i32 = ffi::OPUS_SIGNAL_VOICE;
pub const BANDWIDTH_WIDEBAND: i32 = ffi::OPUS_BANDWIDTH_WIDEBAND;

/// Largest packet libopus will produce for one frame (RFC 6716 §3.4).
pub const MAX_PACKET: usize = 1275 * 3 + 7;
/// Largest frame accepted: 120 ms at 48 kHz, the Opus maximum.
pub const MAX_FRAME_SAMPLES: i32 = 5760;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpusError {
    /// A libopus error code (negative).
    Codec(i32),
    /// The caller's arguments were wrong before libopus was asked.
    Argument(&'static str),
}

impl std::fmt::Display for OpusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpusError::Codec(c) => write!(f, "libopus error {}", c),
            OpusError::Argument(a) => write!(f, "{}", a),
        }
    }
}

impl std::error::Error for OpusError {}

fn check(code: i32) -> Result<i32, OpusError> {
    if code < 0 { Err(OpusError::Codec(code)) } else { Ok(code) }
}

fn check_format(sample_rate: i32, channels: i32) -> Result<(), OpusError> {
    if ![8000, 12000, 16000, 24000, 48000].contains(&sample_rate) {
        return Err(OpusError::Argument("unsupported Opus sample rate"));
    }
    if channels != 1 && channels != 2 {
        return Err(OpusError::Argument("Opus supports 1 or 2 channels"));
    }
    Ok(())
}

fn check_frame(frame_size: i32) -> Result<(), OpusError> {
    if frame_size <= 0 || frame_size > MAX_FRAME_SAMPLES {
        return Err(OpusError::Argument("bad Opus frame size"));
    }
    Ok(())
}

/// The encoder CTLs the voice pipeline sets. Each takes one opus_int32.
#[derive(Debug, Clone, Copy)]
pub enum Ctl {
    Bitrate,
    Vbr,
    Dtx,
    InbandFec,
    PacketLossPerc,
    Complexity,
    Signal,
    Bandwidth,
}

impl Ctl {
    fn request(self) -> i32 {
        match self {
            Ctl::Bitrate => ffi::OPUS_SET_BITRATE_REQUEST,
            Ctl::Vbr => ffi::OPUS_SET_VBR_REQUEST,
            Ctl::Dtx => ffi::OPUS_SET_DTX_REQUEST,
            Ctl::InbandFec => ffi::OPUS_SET_INBAND_FEC_REQUEST,
            Ctl::PacketLossPerc => ffi::OPUS_SET_PACKET_LOSS_PERC_REQUEST,
            Ctl::Complexity => ffi::OPUS_SET_COMPLEXITY_REQUEST,
            Ctl::Signal => ffi::OPUS_SET_SIGNAL_REQUEST,
            Ctl::Bandwidth => ffi::OPUS_SET_BANDWIDTH_REQUEST,
        }
    }
}

pub struct Encoder {
    st: *mut ffi::OpusEncoder,
    channels: i32,
}

// SAFETY: the handle is owned exclusively and libopus state has no thread
// affinity, so moving it is fine (Send). Every method that touches the handle
// takes `&mut self`; a shared `&Encoder` exposes nothing, so sharing is fine
// (Sync). PyO3 serialises `&mut` borrows at runtime.
unsafe impl Send for Encoder {}
unsafe impl Sync for Encoder {}

impl Encoder {
    pub fn new(sample_rate: i32, channels: i32, application: i32) -> Result<Self, OpusError> {
        check_format(sample_rate, channels)?;
        let mut err: i32 = 0;
        // SAFETY: plain constructor; `err` is a valid out-pointer.
        let st = unsafe { ffi::opus_encoder_create(sample_rate, channels, application, &mut err) };
        if st.is_null() || err != ffi::OPUS_OK {
            return Err(OpusError::Codec(if err < 0 { err } else { ffi::OPUS_INTERNAL_ERROR }));
        }
        Ok(Self { st, channels })
    }

    pub fn set(&mut self, ctl: Ctl, value: i32) -> Result<(), OpusError> {
        // SAFETY: `st` is live and owned; every SET request in `Ctl` takes
        // exactly one opus_int32 variadic argument.
        check(unsafe { ffi::opus_encoder_ctl(self.st, ctl.request(), value) }).map(|_| ())
    }

    /// Encode one frame of interleaved i16 PCM (frame_size * channels samples).
    pub fn encode(&mut self, pcm: &[i16], frame_size: i32) -> Result<Vec<u8>, OpusError> {
        check_frame(frame_size)?;
        if pcm.len() != (frame_size * self.channels) as usize {
            return Err(OpusError::Argument("PCM length does not match the frame size"));
        }
        let mut out = vec![0u8; MAX_PACKET];
        // SAFETY: `pcm` holds frame_size*channels samples; `out` is
        // MAX_PACKET bytes, the capacity passed.
        let n = check(unsafe {
            ffi::opus_encode(self.st, pcm.as_ptr(), frame_size, out.as_mut_ptr(), MAX_PACKET as i32)
        })?;
        out.truncate(n as usize);
        Ok(out)
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        if !self.st.is_null() {
            // SAFETY: created by opus_encoder_create and destroyed only here.
            unsafe { ffi::opus_encoder_destroy(self.st) };
            self.st = std::ptr::null_mut();
        }
    }
}

pub struct Decoder {
    st: *mut ffi::OpusDecoder,
    channels: i32,
}

// SAFETY: as for `Encoder`: owned exclusively, no thread affinity, and only
// `&mut self` methods touch the handle.
unsafe impl Send for Decoder {}
unsafe impl Sync for Decoder {}

impl Decoder {
    pub fn new(sample_rate: i32, channels: i32) -> Result<Self, OpusError> {
        check_format(sample_rate, channels)?;
        let mut err: i32 = 0;
        // SAFETY: plain constructor; `err` is a valid out-pointer.
        let st = unsafe { ffi::opus_decoder_create(sample_rate, channels, &mut err) };
        if st.is_null() || err != ffi::OPUS_OK {
            return Err(OpusError::Codec(if err < 0 { err } else { ffi::OPUS_INTERNAL_ERROR }));
        }
        Ok(Self { st, channels })
    }

    /// Decode one packet to interleaved i16 PCM. `None` (or empty) is
    /// packet-loss concealment; `fec` recovers the previous frame from this
    /// packet's in-band FEC.
    pub fn decode(&mut self, packet: Option<&[u8]>, frame_size: i32, fec: bool) -> Result<Vec<i16>, OpusError> {
        check_frame(frame_size)?;
        let packet = packet.unwrap_or(&[]);
        if packet.len() > MAX_PACKET {
            return Err(OpusError::Argument("Opus packet too large"));
        }
        let mut out = vec![0i16; (frame_size * self.channels) as usize];
        let (ptr, len) = if packet.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (packet.as_ptr(), packet.len() as i32)
        };
        // SAFETY: `out` holds frame_size*channels samples, the capacity
        // given; a null packet of length 0 is libopus's documented PLC call.
        let n = check(unsafe {
            ffi::opus_decode(self.st, ptr, len, out.as_mut_ptr(), frame_size, fec as i32)
        })?;
        out.truncate(n as usize * self.channels as usize);
        Ok(out)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        if !self.st.is_null() {
            // SAFETY: created by opus_decoder_create and destroyed only here.
            unsafe { ffi::opus_decoder_destroy(self.st) };
            self.st = std::ptr::null_mut();
        }
    }
}

/// e.g. "libopus 1.5.2".
pub fn version() -> String {
    // SAFETY: libopus returns a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(ffi::opus_get_version_string()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(n: usize) -> Vec<i16> {
        (0..n).map(|i| ((i as f32 * 0.07).sin() * 8000.0) as i16).collect()
    }

    #[test]
    fn a_voice_frame_round_trips_at_the_pipeline_settings() {
        let mut enc = Encoder::new(16000, 1, APPLICATION_VOIP).unwrap();
        for (c, v) in [(Ctl::Bitrate, 24000), (Ctl::Vbr, 0), (Ctl::Dtx, 0), (Ctl::InbandFec, 1),
                       (Ctl::PacketLossPerc, 10), (Ctl::Complexity, 5), (Ctl::Signal, SIGNAL_VOICE),
                       (Ctl::Bandwidth, BANDWIDTH_WIDEBAND)] {
            enc.set(c, v).unwrap();
        }
        let mut dec = Decoder::new(16000, 1).unwrap();
        let frame = 960; // 60 ms at 16 kHz
        let mut sizes = vec![];
        for _ in 0..5 {
            let pkt = enc.encode(&tone(frame), frame as i32).unwrap();
            sizes.push(pkt.len());
            let pcm = dec.decode(Some(&pkt), frame as i32, false).unwrap();
            assert_eq!(pcm.len(), frame);
        }
        // CBR with DTX off: constant packet size, the property voice relies on.
        assert!(sizes.windows(2).all(|w| w[0] == w[1]), "{:?}", sizes);
        // Concealment and FEC calls work.
        assert_eq!(dec.decode(None, frame as i32, false).unwrap().len(), frame);
    }

    #[test]
    fn bad_arguments_are_refused_before_libopus() {
        assert!(Encoder::new(44100, 1, APPLICATION_VOIP).is_err());
        assert!(Decoder::new(16000, 3).is_err());
        let mut enc = Encoder::new(16000, 1, APPLICATION_VOIP).unwrap();
        assert!(enc.encode(&tone(100), 960).is_err());
        let mut dec = Decoder::new(16000, 1).unwrap();
        assert!(dec.decode(Some(&vec![0u8; MAX_PACKET + 1]), 960, false).is_err());
    }

    #[test]
    fn it_is_libopus_1_5() {
        assert!(version().starts_with("libopus 1.5"), "{}", version());
    }
}
