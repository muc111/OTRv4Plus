// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Voice masking for live calls: the speaker stays easy to understand, but
//! does not sound like themselves.
//!
//! Owner (2026-11-09): "we must clearly understand the person speaking but
//! can't identify who -- maybe men should sound like women and vice versa
//! ... keep it simple for a user to cloak voice in realtime".
//!
//! WHAT IT DOES, per call, on the sender's own device
//! ==================================================
//! A streaming phase vocoder at the call's 24 kHz (1024-sample analysis,
//! 256-sample hop: 32 ms of added delay). Each frame's spectrum is split
//! into its smooth ENVELOPE (the vocal tract: formants) and the EXCITATION
//! under it (the voice source: pitch and harmonics), and both are moved:
//!
//!   * the pitch, by 4.5-6.5 semitones;
//!   * the formants, by 12-20 % (with a slight random McAdams bend), in the
//!     SAME direction -- which is what makes a low voice sound like a high
//!     one rather than like a sped-up tape, and keeps vowels clear;
//!   * the direction is chosen from the speaker's own pitch: a low voice
//!     goes up, a high voice goes down (the "men sound like women and vice
//!     versa" the owner asked for);
//!   * nothing above 7.5 kHz is sent: much of a microphone's and a speaker's
//!     fine detail lives there, speech intelligibility does not.
//!
//! The amounts are drawn from the OS random generator when the call starts,
//! held only here, and never returned, logged or sent: every call is a
//! different masked voice, and in a group call every participant's phone
//! draws its own. Until the direction is known (about a third of a second of
//! voiced speech) the output is SILENCE, never the unmasked voice. The
//! direction (one bit, "low" or "high") is then kept in this process's
//! memory so the next call starts masked at once; it is never written down.
//!
//! WHAT IT DOES NOT DO
//! ===================
//! This defeats being recognised by ear and naive voiceprint matching
//! against recordings of the real voice. It does not defeat a determined
//! analyst who trains a recogniser on masked speech: intonation, rhythm and
//! accent survive a pitch-and-formant change (the VoicePrivacy Challenge's
//! signal-processing baselines). What is SAID is untouched. The fully
//! synthetic voice of voice notes (voice_mask.rs) is stronger and was not
//! wanted for calls, where understanding comes first.
//!
//! Not cryptography: no key here. The masked audio is encoded and sent as
//! any call audio is.

use std::f64::consts::PI;
use std::sync::atomic::{AtomicI8, Ordering};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroize;

use crate::voice_mask::fft;

/// The call audio's sample rate (otrv4plus_voice.VOICE_SAMPLE_RATE).
pub const RATE: f64 = 24_000.0;
const N: usize = 1024;
const OSAMP: usize = 4;
const HOP: usize = N / OSAMP;
const BINS: usize = N / 2 + 1;
/// Added delay, in samples: 768 = 32 ms.
pub const LATENCY: usize = N - HOP;
/// Cepstral lifter for the envelope: 1.5 ms, below any speaking pitch period.
const LIFTER: usize = 36;
/// Nothing above this is sent (a cosine taper over the 1 kHz below it).
const LOWPASS_HZ: f64 = 7_500.0;
/// A median pitch below this is a "low" voice and goes up; above, down.
const F0_SPLIT: f64 = 160.0;
/// Voiced analysis frames (10.7 ms apart) before the direction is chosen.
const VOICED_TO_DECIDE: usize = 30;

/// The speaker's direction, once found: 1 up (a low voice), -1 down.
/// Process memory only.
static DIRECTION: AtomicI8 = AtomicI8::new(0);

/// One call's transform, drawn at the start of the call. Never leaves here.
#[derive(Zeroize)]
struct Draws {
    semitones: f64,
    up_formant: f64,
    down_formant: f64,
    alpha: f64,
}

impl Draws {
    fn new() -> Self {
        let mut rng = OsRng;
        Draws {
            semitones: rng.gen_range(4.5..6.5),
            up_formant: rng.gen_range(1.12..1.20),
            down_formant: rng.gen_range(0.83..0.89),
            alpha: rng.gen_range(0.95..1.05),
        }
    }
}

#[derive(Clone, Copy, Zeroize)]
struct Params {
    pitch: f64,
    formant: f64,
    alpha: f64,
}

impl Params {
    fn for_direction(d: &Draws, direction: i8) -> Self {
        if direction > 0 {
            Params { pitch: 2f64.powf(d.semitones / 12.0), formant: d.up_formant, alpha: d.alpha }
        } else {
            Params { pitch: 2f64.powf(-d.semitones / 12.0), formant: d.down_formant, alpha: d.alpha }
        }
    }
}

pub struct Core {
    in_fifo: Vec<f64>,
    out_fifo: Vec<f64>,
    accum: Vec<f64>,
    last_phase: Vec<f64>,
    sum_phase: Vec<f64>,
    rover: usize,
    window: Vec<f64>,
    window_ac: Vec<f64>,
    draws: Draws,
    params: Option<Params>,
    f0s: Vec<f64>,
}

impl Drop for Core {
    fn drop(&mut self) {
        // The buffers hold the speaker's real voice.
        self.in_fifo.zeroize();
        self.out_fifo.zeroize();
        self.accum.zeroize();
        self.f0s.zeroize();
        self.draws.zeroize();
        if let Some(p) = self.params.as_mut() {
            p.zeroize();
        }
    }
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub fn new() -> Self {
        let window: Vec<f64> = (0..N)
            .map(|k| 0.5 - 0.5 * (2.0 * PI * k as f64 / N as f64).cos())
            .collect();
        let window_ac = (0..N)
            .map(|lag| (0..N - lag).map(|i| window[i] * window[i + lag]).sum::<f64>())
            .collect();
        let draws = Draws::new();
        let direction = DIRECTION.load(Ordering::Relaxed);
        let params = (direction != 0).then(|| Params::for_direction(&draws, direction));
        Core {
            in_fifo: vec![0.0; N],
            out_fifo: vec![0.0; N],
            accum: vec![0.0; 2 * N],
            last_phase: vec![0.0; BINS],
            sum_phase: vec![0.0; BINS],
            rover: LATENCY,
            window,
            window_ac,
            draws,
            params,
            f0s: Vec::new(),
        }
    }

    #[cfg(test)]
    fn with_params(pitch: f64, formant: f64, alpha: f64) -> Self {
        let mut core = Core::new();
        core.params = Some(Params { pitch, formant, alpha });
        core
    }

    pub fn ready(&self) -> bool {
        self.params.is_some()
    }

    /// Mask [x] (samples in -1..1); returns as many samples, LATENCY late.
    pub fn process(&mut self, x: &[f64]) -> Vec<f64> {
        let mut out = Vec::with_capacity(x.len());
        for &sample in x {
            self.in_fifo[self.rover] = sample;
            out.push(self.out_fifo[self.rover - LATENCY]);
            self.rover += 1;
            if self.rover >= N {
                self.rover = LATENCY;
                self.frame();
            }
        }
        out
    }

    fn frame(&mut self) {
        let freq_per_bin = RATE / N as f64;
        let expected = 2.0 * PI * HOP as f64 / N as f64;
        let mut re: Vec<f64> = (0..N).map(|k| self.in_fifo[k] * self.window[k]).collect();
        let mut im = vec![0.0; N];
        fft(&mut re, &mut im, false);

        let mut magn = vec![0.0; BINS];
        let mut phase = vec![0.0; BINS];
        let mut freq = vec![0.0; BINS];
        for k in 0..BINS {
            magn[k] = 2.0 * re[k].hypot(im[k]);
            phase[k] = im[k].atan2(re[k]);
            let mut delta = phase[k] - self.last_phase[k] - k as f64 * expected;
            self.last_phase[k] = phase[k];
            delta -= 2.0 * PI * (delta / (2.0 * PI)).round();
            freq[k] = (k as f64 + OSAMP as f64 * delta / (2.0 * PI)) * freq_per_bin;
        }

        if self.params.is_none() {
            self.listen(&re, &im);
        }

        if let Some(p) = self.params {
            let env = log_envelope(&magn);
            let moved = warp(&env, p.formant, p.alpha);
            let mut sre = vec![0.0; N];
            let mut sim = vec![0.0; N];
            // Identity phase locking (Laroche & Dolson): every spectral peak
            // moves as one block to its new frequency; the bins around it
            // keep their phase RELATIVE to the peak. Without it the bins of
            // one harmonic drift apart and partly cancel -- the "phasey",
            // swirling sound that costs intelligibility.
            let peaks: Vec<usize> = (2..BINS - 2)
                .filter(|&k| magn[k] > magn[k - 1] && magn[k] >= magn[k + 1]
                    && magn[k] > magn[k - 2] && magn[k] >= magn[k + 2])
                .collect();
            for (n, &kp) in peaks.iter().enumerate() {
                let lo = if n == 0 { 0 } else { valley(&magn, peaks[n - 1], kp) + 1 };
                let hi = if n + 1 == peaks.len() { BINS - 1 } else { valley(&magn, kp, peaks[n + 1]) };
                let target = (kp as f64 * p.pitch).round() as isize;
                if target <= 0 || target as usize >= BINS {
                    continue;
                }
                let tp = target as usize;
                let shift = target - kp as isize;
                // The peak's own phase advances at its new frequency.
                self.sum_phase[tp] = (self.sum_phase[tp]
                    + 2.0 * PI * freq[kp] * p.pitch * HOP as f64 / RATE) % (2.0 * PI);
                let anchor = self.sum_phase[tp];
                for k in lo..=hi {
                    let t = k as isize + shift;
                    if t <= 0 || t as usize >= BINS {
                        continue;
                    }
                    let t = t as usize;
                    let m = magn[k] / env[k].exp() * moved[t].exp() * lowpass(t as f64 * freq_per_bin);
                    let ph = anchor + phase[k] - phase[kp];
                    sre[t] += m * ph.cos();
                    sim[t] += m * ph.sin();
                }
            }
            fft(&mut sre, &mut sim, true);
            for k in 0..N {
                // fft's inverse divides by N, so N puts it back; Hann
                // analysis and synthesis at 75 % overlap sum to 1.5.
                self.accum[k] += 2.0 * self.window[k] * sre[k] * N as f64
                    / ((N / 2) as f64 * OSAMP as f64 * 1.5);
            }
        }

        self.out_fifo[..HOP].copy_from_slice(&self.accum[..HOP]);
        self.accum.copy_within(HOP.., 0);
        for v in &mut self.accum[2 * N - HOP..] {
            *v = 0.0;
        }
        self.in_fifo.copy_within(HOP.., 0);
    }

    /// Before the direction is known: find this frame's pitch, if voiced,
    /// and decide once there are enough. Output stays silent meanwhile.
    fn listen(&mut self, re: &[f64], im: &[f64]) {
        if let Some(f0) = pitch_of(re, im, &self.window_ac) {
            self.f0s.push(f0);
        }
        if self.f0s.len() >= VOICED_TO_DECIDE {
            let mut sorted = self.f0s.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let median = sorted[sorted.len() / 2];
            sorted.zeroize();
            self.f0s.zeroize();
            let direction: i8 = if median < F0_SPLIT { 1 } else { -1 };
            DIRECTION.store(direction, Ordering::Relaxed);
            self.params = Some(Params::for_direction(&self.draws, direction));
        }
    }
}

/// The lowest bin strictly between peaks [a] and [b] (a region boundary).
fn valley(magn: &[f64], a: usize, b: usize) -> usize {
    (a + 1..b).min_by(|x, y| magn[*x].partial_cmp(&magn[*y]).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(a)
}

/// The pitch of a windowed frame from its spectrum (autocorrelation by
/// inverse FFT of the power), or None when unvoiced or too quiet.
fn pitch_of(re: &[f64], im: &[f64], window_ac: &[f64]) -> Option<f64> {
    let mut pr: Vec<f64> = (0..N).map(|k| re[k] * re[k] + im[k] * im[k]).collect();
    let mut pi = vec![0.0; N];
    fft(&mut pr, &mut pi, true);
    let r0 = pr[0];
    // About -55 dBFS RMS through the window: quieter is not speech.
    if r0 / window_ac[0] < 3e-6 {
        return None;
    }
    let (lo, hi) = ((RATE / 400.0) as usize, (RATE / 60.0) as usize);
    let norm = |lag: usize| pr[lag] / window_ac[lag] / (r0 / window_ac[0]);
    let mut best = lo;
    for lag in lo..=hi {
        if norm(lag) > norm(best) {
            best = lag;
        }
    }
    if norm(best) < 0.45 {
        return None;
    }
    // Prefer the shortest period the correlation supports (no octave drop).
    for div in [3usize, 2] {
        let short = best / div;
        if short >= lo && norm(short) > 0.85 * norm(best) {
            best = short;
            break;
        }
    }
    Some(RATE / best as f64)
}

/// The smooth log-magnitude envelope (cepstral smoothing, lifted twice to
/// ride the harmonic peaks rather than the valleys between them).
fn log_envelope(magn: &[f64]) -> Vec<f64> {
    let lm: Vec<f64> = magn.iter().map(|m| (m + 1e-9).ln()).collect();
    let smooth = |target: &[f64]| -> Vec<f64> {
        let mut r = vec![0.0; N];
        let mut i = vec![0.0; N];
        for k in 0..BINS {
            r[k] = target[k];
            if k > 0 && k < N / 2 {
                r[N - k] = target[k];
            }
        }
        fft(&mut r, &mut i, true);
        for v in r.iter_mut().take(N - LIFTER + 1).skip(LIFTER) {
            *v = 0.0;
        }
        let mut z = vec![0.0; N];
        fft(&mut r, &mut z, false);
        r.truncate(BINS);
        r
    };
    let mut env = smooth(&lm);
    for _ in 0..2 {
        let lifted: Vec<f64> = lm.iter().zip(&env).map(|(a, b)| a.max(*b)).collect();
        env = smooth(&lifted);
    }
    env
}

/// The envelope moved along frequency: what was at (normalised) w moves to
/// formant * w^alpha. Read backwards from each output bin.
fn warp(env: &[f64], formant: f64, alpha: f64) -> Vec<f64> {
    let top = (BINS - 1) as f64;
    (0..BINS)
        .map(|k| {
            let w = k as f64 / top;
            let src = (w / formant).max(0.0).powf(1.0 / alpha).min(1.0);
            let pos = src * top;
            let i = (pos as usize).min(BINS - 2);
            let t = pos - i as f64;
            env[i] * (1.0 - t) + env[i + 1] * t
        })
        .collect()
}

fn lowpass(hz: f64) -> f64 {
    let start = LOWPASS_HZ - 1_000.0;
    if hz <= start {
        1.0
    } else if hz >= LOWPASS_HZ {
        0.0
    } else {
        0.5 + 0.5 * (PI * (hz - start) / 1_000.0).cos()
    }
}

// ── Python ───────────────────────────────────────────────────────────────────

/// One call's voice mask. Feed it the microphone's 16-bit PCM; it returns as
/// many bytes, masked and LATENCY samples late (silence until it is ready).
#[pyclass(name = "LiveVoiceMask", module = "otrv4_core")]
pub struct LiveVoiceMask {
    core: Core,
}

#[pymethods]
impl LiveVoiceMask {
    #[new]
    fn py_new() -> Self {
        LiveVoiceMask { core: Core::new() }
    }

    /// Mask little-endian 16-bit mono PCM at 24 kHz.
    fn process<'py>(&mut self, py: Python<'py>, pcm: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if pcm.len() % 2 != 0 {
            return Err(PyValueError::new_err("PCM must be whole 16-bit samples"));
        }
        let mut input: Vec<f64> = pcm
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]) as f64 / 32768.0)
            .collect();
        let core = &mut self.core;
        let mut output = py.detach(|| core.process(&input));
        input.zeroize();
        let mut bytes = Vec::with_capacity(pcm.len());
        for v in &output {
            // A soft knee, then a hard limit: a shifted spectrum can peak
            // above the input's.
            let s = if v.abs() > 0.8 { v.signum() * (0.8 + 0.2 * ((v.abs() - 0.8) / 0.2).tanh()) } else { *v };
            bytes.extend_from_slice(&((s * 32767.0).round().clamp(-32768.0, 32767.0) as i16).to_le_bytes());
        }
        output.zeroize();
        let out = PyBytes::new(py, &bytes);
        bytes.zeroize();
        Ok(out)
    }

    /// Whether the mask is speaking yet (the direction is known).
    #[getter]
    fn ready(&self) -> bool {
        self.core.ready()
    }

    /// Added delay, in samples at 24 kHz.
    #[staticmethod]
    fn latency_samples() -> usize {
        LATENCY
    }

    /// Forget the remembered direction (another person uses this device).
    #[staticmethod]
    fn forget_direction() {
        DIRECTION.store(0, Ordering::Relaxed);
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LiveVoiceMask>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// DIRECTION is process-wide; tests that rely on it take this.
    static DIRECTION_TESTS: Mutex<()> = Mutex::new(());

    /// A voiced vowel: harmonics of [f0] under three formants, 0.25 peak.
    fn vowel(f0: f64, seconds: f64) -> Vec<f64> {
        let n = (seconds * RATE) as usize;
        let formant = |f: f64| -> f64 {
            [(700.0, 130.0), (1_200.0, 150.0), (2_600.0, 250.0)]
                .iter()
                .map(|(c, bw)| (-((f - c) / bw).powi(2)).exp())
                .sum::<f64>()
                + 0.02
        };
        let harmonics: Vec<(f64, f64)> = (1..)
            .map(|h| h as f64 * f0)
            .take_while(|f| *f < 5_000.0)
            .map(|f| (f, formant(f)))
            .collect();
        let norm: f64 = harmonics.iter().map(|(_, a)| a).sum();
        (0..n)
            .map(|i| {
                let t = i as f64 / RATE;
                0.25 * harmonics.iter().map(|(f, a)| a * (2.0 * PI * f * t).sin()).sum::<f64>() / norm
            })
            .collect()
    }

    /// Time-domain pitch of the tail of [x]: the SHORTEST period whose
    /// autocorrelation is within 10 % of the best (no octave slips).
    fn measured_f0(x: &[f64]) -> f64 {
        let tail = &x[x.len() - 4_800..];
        let (lo, hi) = ((RATE / 400.0) as usize, (RATE / 60.0) as usize);
        let ac = |lag: usize| tail.iter().zip(&tail[lag..]).map(|(a, b)| a * b).sum::<f64>();
        let peak = (lo..=hi).map(ac).fold(f64::MIN, f64::max);
        let best = (lo..=hi)
            .filter(|&l| ac(l) >= 0.9 * peak && ac(l) >= ac(l - 1) && ac(l) >= ac(l + 1))
            .next()
            .unwrap();
        RATE / best as f64
    }

    /// The log spectral envelope of the last half second (magnitudes
    /// averaged over frames).
    fn envelope_of(x: &[f64]) -> Vec<f64> {
        let mut magn = vec![0.0; BINS];
        let tail = &x[x.len() - 12_000..];
        for start in (0..=tail.len() - N).step_by(HOP) {
            let mut re: Vec<f64> = tail[start..start + N].iter().enumerate()
                .map(|(k, v)| v * (0.5 - 0.5 * (2.0 * PI * k as f64 / N as f64).cos())).collect();
            let mut im = vec![0.0; N];
            fft(&mut re, &mut im, false);
            for k in 0..BINS {
                magn[k] += re[k].hypot(im[k]);
            }
        }
        log_envelope(&magn)
    }

    /// By how much the formants moved from [input] to [output]: the
    /// frequency stretch of the input's envelope that best matches the
    /// output's over 200-3500 Hz (correlation, searched 0.70-1.40).
    fn formant_stretch(input: &[f64], output: &[f64]) -> f64 {
        let (ei, eo) = (envelope_of(input), envelope_of(output));
        let hz = RATE / N as f64;
        let bins: Vec<usize> = ((200.0 / hz) as usize..(3_500.0 / hz) as usize).collect();
        let at = |env: &[f64], f: f64| -> f64 {
            let pos = (f / hz).clamp(0.0, (BINS - 2) as f64);
            let i = pos as usize;
            env[i] + (env[i + 1] - env[i]) * (pos - i as f64)
        };
        let corr = |s: f64| -> f64 {
            let a: Vec<f64> = bins.iter().map(|&k| eo[k]).collect();
            let b: Vec<f64> = bins.iter().map(|&k| at(&ei, k as f64 * hz / s)).collect();
            let (ma, mb) = (a.iter().sum::<f64>() / a.len() as f64, b.iter().sum::<f64>() / b.len() as f64);
            let num: f64 = a.iter().zip(&b).map(|(x, y)| (x - ma) * (y - mb)).sum();
            let da: f64 = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>().sqrt();
            let db: f64 = b.iter().map(|y| (y - mb).powi(2)).sum::<f64>().sqrt();
            num / (da * db)
        };
        (70..=140).map(|i| i as f64 / 100.0)
            .max_by(|a, b| corr(*a).partial_cmp(&corr(*b)).unwrap())
            .unwrap()
    }

    fn rms(x: &[f64]) -> f64 {
        (x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64).sqrt()
    }

    #[test]
    fn a_low_voice_goes_up_and_a_high_voice_goes_down() {
        let _g = DIRECTION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        DIRECTION.store(0, Ordering::Relaxed);
        let mut low = Core::new();
        let out = low.process(&vowel(110.0, 2.0));
        assert!(low.ready());
        let f = measured_f0(&out);
        assert!((140.0..=170.0).contains(&f), "110 Hz became {f} Hz");
        let up = formant_stretch(&vowel(110.0, 2.0), &out);
        assert!((1.03..=1.35).contains(&up), "formants moved by {up}, not up");

        DIRECTION.store(0, Ordering::Relaxed);
        let mut high = Core::new();
        let out = high.process(&vowel(220.0, 2.0));
        let f = measured_f0(&out);
        assert!((145.0..=180.0).contains(&f), "220 Hz became {f} Hz");
        let down = formant_stretch(&vowel(220.0, 2.0), &out);
        assert!((0.70..=0.97).contains(&down), "formants moved by {down}, not down");
        DIRECTION.store(0, Ordering::Relaxed);
    }

    #[test]
    fn nothing_of_the_real_voice_comes_out_before_the_mask_is_ready() {
        let _g = DIRECTION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        DIRECTION.store(0, Ordering::Relaxed);
        let mut core = Core::new();
        let input = vowel(120.0, 0.25); // fewer voiced frames than needed
        let out = core.process(&input);
        assert!(!core.ready());
        assert!(out.iter().all(|v| *v == 0.0));
        DIRECTION.store(0, Ordering::Relaxed);
    }

    #[test]
    fn the_next_call_starts_masked_and_sounds_different() {
        let _g = DIRECTION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        DIRECTION.store(1, Ordering::Relaxed);
        let input = vowel(110.0, 1.0);
        let (mut a, mut b) = (Core::new(), Core::new());
        assert!(a.ready() && b.ready());
        let (oa, ob) = (a.process(&input), b.process(&input));
        assert!(rms(&oa[LATENCY..]) > 0.01);
        let diff: f64 = oa.iter().zip(&ob).map(|(x, y)| (x - y).abs()).sum();
        assert!(diff > 1.0, "two calls drew the same mask");
        DIRECTION.store(0, Ordering::Relaxed);
    }

    #[test]
    fn identity_settings_keep_the_level() {
        let input = vowel(150.0, 1.0);
        let out = Core::with_params(1.0, 1.0, 1.0).process(&input);
        let ratio = rms(&out[N..]) / rms(&input[N..]);
        assert!((0.7..1.4).contains(&ratio), "level ratio {ratio}");
    }

    #[test]
    fn silence_stays_silent_and_nothing_is_lost_or_added() {
        let mut core = Core::with_params(1.4, 1.15, 1.0);
        let out = core.process(&vec![0.0; 9_000]);
        assert_eq!(out.len(), 9_000);
        assert!(out.iter().all(|v| v.abs() < 1e-9));
    }

    #[test]
    fn nothing_above_the_cut_is_sent() {
        let input: Vec<f64> = (0..24_000).map(|i| 0.2 * (2.0 * PI * 9_000.0 * i as f64 / RATE).sin()
            + 0.2 * (2.0 * PI * 500.0 * i as f64 / RATE).sin()).collect();
        let out = Core::with_params(1.0, 1.0, 1.0).process(&input);
        let tail = &out[out.len() - N..];
        let mut re: Vec<f64> = tail.iter().enumerate()
            .map(|(k, v)| v * (0.5 - 0.5 * (2.0 * PI * k as f64 / N as f64).cos())).collect();
        let mut im = vec![0.0; N];
        fft(&mut re, &mut im, false);
        let bin = |hz: f64| (hz / (RATE / N as f64)).round() as usize;
        assert!(re[bin(9_000.0)].hypot(im[bin(9_000.0)]) < 0.01 * re[bin(500.0)].hypot(im[bin(500.0)]));
    }

    #[test]
    fn it_keeps_up_with_a_call_with_room_to_spare() {
        if cfg!(debug_assertions) {
            return; // timing means nothing in a debug build
        }
        let input = vowel(130.0, 10.0);
        let mut core = Core::with_params(1.4, 1.15, 1.0);
        let start = std::time::Instant::now();
        let _ = core.process(&input);
        let took = start.elapsed().as_secs_f64();
        // 10 s of audio; a phone is several times slower than CI.
        assert!(took < 1.0, "10 s of call audio took {took:.2} s");
    }





}
