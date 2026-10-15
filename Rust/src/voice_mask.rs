// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Voice notes that do not carry the speaker's voice.
//!
//! Owner (2026-10-15): "can we morph voice notes advanced enough where ai
//! detection cannot identify or link voice note to specific user in real
//! life? similar to how money heist Netflix show the professor morph his
//! voice."
//!
//! WHAT A PITCH SHIFTER DOES NOT DO
//! ================================
//! The voice changers of the early 2000s -- and the box the Professor holds
//! to the phone -- move the pitch, sometimes the formants, by one fixed
//! amount. A fixed, known transform is undone by applying its inverse, and a
//! speaker-recognition model trained on shifted speech ("an informed
//! attacker", in the VoicePrivacy Challenge's terms) recognises the speaker
//! through it. What identifies a voice is not mostly its pitch: it is the
//! shape of the vocal tract (formant positions), the glottal source (pulse
//! shape, breathiness, jitter), the intonation and the rhythm, and the
//! microphone and room it was recorded in.
//!
//! WHAT THIS DOES (every step on the device, nothing stored)
//! ==========================================================
//!   1. Resample to 16 kHz mono. Everything above 8 kHz -- where much of the
//!      microphone's and the speaker's fine detail lives -- is gone.
//!   2. Channel normalisation: the recording's long-term spectrum (the
//!      microphone, the room, the distance) is replaced by a FIXED reference
//!      (for Disguise and Synthetic, the standard long-term speech spectrum,
//!      applied at the end of step 7).
//!   3. A noise gate: room tone and background between words are removed.
//!   4. Short-time spectra (32 ms, 8 ms hop); each frame's smooth spectral
//!      ENVELOPE (the vocal tract) by cepstral liftering.
//!   5. The envelope is warped along frequency twice: the McAdams warp
//!      (the VoicePrivacy Challenge baseline B2) and a bilinear vocal-tract-
//!      length warp. Every formant moves, by a different amount,
//!      non-linearly. (Until rc.76 the McAdams warp moved the poles of an
//!      LPC filter, which rang like a whistle -- see "the spectral path".)
//!   6. DISGUISE: the speaker's own harmonics, pitch-shifted (resample +
//!      WSOLA), under the warped envelope; the speaking rate changed too.
//!   7. SYNTHETIC throws the speaker's source away and puts a generated one
//!      under the warped envelope: a monotone pulse train with a little
//!      jitter, breath above ~3 kHz, noise where the speaker was unvoiced.
//!      No glottal pulse shape, breathiness or intonation of the speaker's
//!      is left. It sounds like a vocoder. It is the strongest setting.
//!      Both end on a FIXED reference spectral balance.
//!   8. Loudness is normalised, so level is no cue either.
//!
//! EVERY NOTE GETS ITS OWN, SECRET SETTINGS
//! ========================================
//! The warp, the pitch, the rate and the synthetic pitch are drawn afresh for
//! each note from the OS random generator, inside this function, and never
//! leave it: they are not returned, logged or stored. So there is no single
//! transform to invert, and two notes by the same person do not sound like
//! the same disguised voice -- they cannot be linked to each other by voice
//! either.
//!
//! WHAT NO VOICE CHANGER CAN PROMISE
//! =================================
//! This makes voice-based identification and linking much harder; it cannot
//! make it impossible, and nothing honest claims to. WHAT is said -- words,
//! phrasing, dialect, background events -- is untouched: a voice note saying
//! "it's me, from the office" identifies its sender whatever it sounds like.
//! DISGUISE keeps more of the speaker's own timing and expression than
//! SYNTHETIC does. Where it really matters, type instead.
//!
//! Not cryptography: this module holds no key. The note it produces is sent
//! as an ordinary encrypted file transfer (`filetransfer.rs`).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, RngCore, SeedableRng};
use std::f64::consts::PI;
use zeroize::Zeroize;

/// The output sample rate.
pub const RATE: u32 = 16_000;
/// The longest note accepted, in seconds.
pub const MAX_SECONDS: usize = 300;

const FRAME: usize = 480; // 30 ms
const HOP: usize = FRAME / 2;
const ORDER: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Clean-up only (level, tilt, gate). The speaker's own voice.
    Natural,
    /// Formants warped, pitch and rate moved, all at random.
    Disguise,
    /// As Disguise, with a generated source instead of the speaker's.
    Synthetic,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "natural" => Some(Mode::Natural),
            "disguise" => Some(Mode::Disguise),
            "synthetic" => Some(Mode::Synthetic),
            _ => None,
        }
    }
}

/// One note's transform. Drawn per note; never leaves this module.
#[derive(Clone, Copy, Debug, Zeroize)]
struct Params {
    alpha: f64,
    /// A linear vocal-tract-length change on top of the McAdams warp.
    scale: f64,
    /// Formant bandwidth expansion: broader formants carry less of the
    /// speaker's fine spectral detail.
    gamma: f64,
    pitch: f64,
    rate: f64,
    f0: f64,
    drift: f64,
    /// The spectral path's second vocal-tract warp (bilinear all-pass
    /// coefficient), on top of the McAdams warp.
    warp: f64,
}

fn draw(mode: Mode, rng: &mut StdRng) -> Params {
    let alpha = if rng.gen_bool(0.5) {
        rng.gen_range(0.72..0.84)
    } else {
        rng.gen_range(1.14..1.26)
    };
    // rc.77: a little narrower than before (0.70..0.84 / 1.20..1.45): the
    // extremes sounded like a cartoon, and the warped envelope now moves the
    // voice more than the pitch has to.
    let pitch = if rng.gen_bool(0.5) {
        rng.gen_range(0.74..0.86)
    } else {
        rng.gen_range(1.18..1.38)
    };
    let scale = rng.gen_range(0.94..1.16);
    let gamma = rng.gen_range(0.975..0.99);
    let rate = rng.gen_range(0.92..1.08);
    let f0 = rng.gen_range(95.0..185.0);
    let drift = rng.gen_range(0.0..(2.0 * PI));
    let warp = if rng.gen_bool(0.5) { 1.0 } else { -1.0 } * rng.gen_range(0.08..0.16);
    match mode {
        Mode::Natural => Params { alpha: 1.0, scale: 1.0, gamma: 1.0, pitch: 1.0, rate: 1.0, f0, drift, warp: 0.0 },
        _ => Params { alpha, scale, gamma, pitch, rate, f0, drift, warp },
    }
}

// -- small DSP pieces ------------------------------------------------------------

fn hann(n: usize) -> Vec<f64> {
    (0..n).map(|i| 0.5 - 0.5 * (2.0 * PI * i as f64 / n as f64).cos()).collect()
}

fn sinc(x: f64) -> f64 {
    if x.abs() < 1e-12 { 1.0 } else { (PI * x).sin() / (PI * x) }
}

/// Windowed-sinc resampling by an arbitrary ratio.
pub fn resample(x: &[f64], from: f64, to: f64) -> Vec<f64> {
    if x.is_empty() || (from - to).abs() < 1e-9 {
        return x.to_vec();
    }
    const W: isize = 16;
    let step = from / to;
    let cutoff = (to / from).min(1.0) * 0.95;
    let n_out = ((x.len() as f64) / step).floor() as usize;
    let mut out = Vec::with_capacity(n_out);
    for n in 0..n_out {
        let t = n as f64 * step;
        let base = t.floor() as isize;
        let mut acc = 0.0;
        let mut norm = 0.0;
        for k in (base - W + 1)..=(base + W) {
            if k < 0 || k as usize >= x.len() {
                continue;
            }
            let d = t - k as f64;
            let win = 0.5 + 0.5 * (PI * d / (W as f64 + 1.0)).cos();
            let h = cutoff * sinc(cutoff * d) * win;
            acc += x[k as usize] * h;
            norm += h;
        }
        out.push(if norm.abs() > 1e-9 { acc / norm } else { 0.0 });
    }
    out
}

fn autocorr(x: &[f64], order: usize) -> Vec<f64> {
    (0..=order)
        .map(|lag| x.iter().zip(x.iter().skip(lag)).map(|(a, b)| a * b).sum())
        .collect()
}

/// Levinson-Durbin: r -> a (a[0] = 1). None for a silent frame.
fn levinson(r: &[f64], order: usize) -> Option<Vec<f64>> {
    if r[0] <= 1e-9 {
        return None;
    }
    let mut a = vec![0.0; order + 1];
    a[0] = 1.0;
    let mut err = r[0];
    for i in 1..=order {
        let mut acc = r[i];
        for j in 1..i {
            acc += a[j] * r[i - j];
        }
        let k = -acc / err;
        let prev = a.clone();
        for j in 1..i {
            a[j] = prev[j] + k * prev[i - j];
        }
        a[i] = k;
        err *= 1.0 - k * k;
        if err <= 1e-12 {
            return None;
        }
    }
    Some(a)
}

fn lpc(frame: &[f64], order: usize) -> Option<Vec<f64>> {
    let mut r = autocorr(frame, order);
    // White-noise correction and a lag window, for well-conditioned filters.
    r[0] *= 1.0001;
    for (i, v) in r.iter_mut().enumerate().skip(1) {
        let g = 2.0 * PI * 60.0 * i as f64 / RATE as f64;
        *v *= (-0.5 * g * g).exp();
    }
    levinson(&r, order)
}

/// y = A(z) x  (FIR, zero initial state).
fn fir(a: &[f64], x: &[f64]) -> Vec<f64> {
    (0..x.len())
        .map(|n| a.iter().enumerate().take(n + 1).map(|(k, c)| c * x[n - k]).sum())
        .collect()
}

/// y = x / A(z)  (IIR, zero initial state).
fn iir(a: &[f64], x: &[f64]) -> Vec<f64> {
    let mut y = vec![0.0; x.len()];
    for n in 0..x.len() {
        let mut acc = x[n];
        for k in 1..a.len().min(n + 1) {
            acc -= a[k] * y[n - k];
        }
        y[n] = acc;
    }
    y
}

// -- McAdams: move every formant by warping the LPC pole angles ---------------

#[derive(Clone, Copy, Debug)]
struct C(f64, f64);

impl C {
    fn add(self, o: C) -> C { C(self.0 + o.0, self.1 + o.1) }
    fn sub(self, o: C) -> C { C(self.0 - o.0, self.1 - o.1) }
    fn mul(self, o: C) -> C { C(self.0 * o.0 - self.1 * o.1, self.0 * o.1 + self.1 * o.0) }
    fn div(self, o: C) -> C {
        let d = o.0 * o.0 + o.1 * o.1;
        C((self.0 * o.0 + self.1 * o.1) / d, (self.1 * o.0 - self.0 * o.1) / d)
    }
    fn abs(self) -> f64 { self.0.hypot(self.1) }
}

/// Roots of z^p + a[1] z^(p-1) + ... + a[p] (Durand-Kerner).
fn roots(a: &[f64]) -> Option<Vec<C>> {
    let p = a.len() - 1;
    let mut z: Vec<C> = Vec::with_capacity(p);
    let seed = C(0.4, 0.9);
    let mut cur = C(1.0, 0.0);
    for _ in 0..p {
        cur = cur.mul(seed);
        z.push(cur);
    }
    let eval = |x: C| a.iter().fold(C(0.0, 0.0), |acc, &c| acc.mul(x).add(C(c, 0.0)));
    for _ in 0..800 {
        let mut moved = 0.0f64;
        for i in 0..p {
            let mut den = C(1.0, 0.0);
            for j in 0..p {
                if i != j {
                    den = den.mul(z[i].sub(z[j]));
                }
            }
            if den.abs() < 1e-300 {
                return None;
            }
            let step = eval(z[i]).div(den);
            z[i] = z[i].sub(step);
            moved = moved.max(step.abs());
        }
        if moved < 1e-12 {
            return Some(z);
        }
    }
    let worst = z.iter().map(|&r| eval(r).abs()).fold(0.0, f64::max);
    if worst < 1e-6 { Some(z) } else { None }
}

/// The McAdams transform of an LPC filter: each complex pole's angle φ
/// becomes scale * φ^alpha, and its radius is multiplied by gamma (broader
/// formants). Radii stay below 1, so the filter stays stable.
fn mcadams(a: &[f64], alpha: f64, scale: f64, gamma: f64) -> Vec<f64> {
    if (alpha - 1.0).abs() < 1e-9 && (scale - 1.0).abs() < 1e-9 && (gamma - 1.0).abs() < 1e-9 {
        return a.to_vec();
    }
    let Some(rs) = roots(a) else { return a.to_vec() };
    let mut poly = vec![C(1.0, 0.0)];
    let mut push = |r: C| {
        let mut next = vec![C(0.0, 0.0); poly.len() + 1];
        for (i, &c) in poly.iter().enumerate() {
            next[i] = next[i].add(c);
            next[i + 1] = next[i + 1].sub(c.mul(r));
        }
        poly = next;
    };
    for r in rs {
        let mag = (r.abs() * gamma).min(0.995);
        if r.1 > 1e-9 {
            let phi = r.1.atan2(r.0);
            let warped = (scale * phi.powf(alpha)).clamp(0.01, PI - 0.01);
            push(C(mag * warped.cos(), mag * warped.sin()));
            push(C(mag * warped.cos(), -mag * warped.sin()));
        } else if r.1.abs() <= 1e-9 {
            push(C((r.0 * gamma).clamp(-0.995, 0.995), 0.0));
        }
    }
    if poly.len() != a.len() || poly.iter().any(|c| !c.0.is_finite()) {
        return a.to_vec();
    }
    poly.iter().map(|c| c.0).collect()
}

// -- time and pitch ---------------------------------------------------------------

/// WSOLA: change duration by [factor] (> 1 longer) keeping pitch.
fn wsola(x: &[f64], factor: f64) -> Vec<f64> {
    let n_out = ((x.len() as f64) * factor) as usize;
    if x.len() < FRAME * 2 || (factor - 1.0).abs() < 1e-6 {
        return resample(x, 1.0, factor); // too short to matter: plain stretch
    }
    let win = hann(FRAME);
    let tol: isize = 160;
    let mut out = vec![0.0; n_out + FRAME];
    let mut prev_end: isize = 0; // where the natural continuation starts in x
    let mut j = 0usize;
    loop {
        let out_pos = j * HOP;
        if out_pos >= n_out {
            break;
        }
        let nominal = (out_pos as f64 / factor) as isize;
        let mut best = nominal;
        if j > 0 {
            let mut best_score = f64::MIN;
            for d in -tol..=tol {
                let s = nominal + d;
                if s < 0 || (s as usize) + FRAME > x.len() || (prev_end as usize) + FRAME > x.len() {
                    continue;
                }
                let mut score = 0.0;
                for k in (0..HOP / 2).map(|i| i * 2) {
                    score += x[s as usize + k] * x[prev_end as usize + k];
                }
                if score > best_score {
                    best_score = score;
                    best = s;
                }
            }
        }
        let start = best.clamp(0, (x.len() - FRAME) as isize) as usize;
        for k in 0..FRAME {
            out[out_pos + k] += x[start + k] * win[k];
        }
        prev_end = (start + HOP) as isize;
        j += 1;
    }
    out.truncate(n_out);
    out
}

/// Pitch times [pitch], duration times [rate].
fn shift(x: &[f64], pitch: f64, rate: f64) -> Vec<f64> {
    if (pitch - 1.0).abs() < 1e-9 && (rate - 1.0).abs() < 1e-9 {
        return x.to_vec();
    }
    let squeezed = resample(x, pitch, 1.0); // length / pitch: pitch up by `pitch`
    wsola(&squeezed, pitch * rate)
}

fn voicing(frame: &[f64]) -> f64 {
    let e: f64 = frame.iter().map(|v| v * v).sum();
    if e <= 1e-9 {
        return 0.0;
    }
    let lo = (RATE / 400) as usize;
    let hi = (RATE / 60) as usize;
    (lo..hi.min(frame.len() - 1))
        .map(|lag| frame.iter().zip(frame.iter().skip(lag)).map(|(a, b)| a * b).sum::<f64>() / e)
        .fold(0.0, f64::max)
}

/// A new source: a monotone pulse train where the speaker was voiced, noise
/// where not, at the speaker's frame energy and nothing else of theirs.
fn synthetic_source(e: &[f64], params: &Params, rng: &mut StdRng) -> Vec<f64> {
    let frames = e.len() / HOP + 1;
    let mut rms = vec![0.0; frames];
    let mut voiced = vec![0.0; frames];
    for i in 0..frames {
        let s = i * HOP;
        let end = (s + FRAME).min(e.len());
        if end <= s + 8 {
            continue;
        }
        let f = &e[s..end];
        rms[i] = (f.iter().map(|v| v * v).sum::<f64>() / f.len() as f64).sqrt();
        voiced[i] = if voicing(f) > 0.3 { 1.0 } else { 0.0 };
    }
    let mut out = vec![0.0; e.len()];
    let mut phase = 0.0f64;
    for (n, sample) in out.iter_mut().enumerate() {
        let pos = n as f64 / HOP as f64;
        let i = (pos as usize).min(frames - 1);
        let next = (i + 1).min(frames - 1);
        let t = pos - i as f64;
        let g = rms[i] * (1.0 - t) + rms[next] * t;
        let v = voiced[i] * (1.0 - t) + voiced[next] * t;
        let seconds = n as f64 / RATE as f64;
        let f0 = params.f0 * (1.0 + 0.02 * (2.0 * PI * 0.25 * seconds + params.drift).sin());
        phase += f0 / RATE as f64;
        let period = RATE as f64 / f0;
        let pulse = if phase >= 1.0 {
            phase -= 1.0;
            period.sqrt()
        } else {
            0.0
        };
        let noise: f64 = rng.gen_range(-1.0..1.0) * 1.7;
        *sample = g * (v * (0.92 * pulse + 0.08 * noise) + (1.0 - v) * noise);
    }
    out
}

// -- the whole note ---------------------------------------------------------------

fn frame_rms(x: &[f64]) -> Vec<f64> {
    (0..x.len() / HOP + 1)
        .map(|i| {
            let s = i * HOP;
            let end = (s + FRAME).min(x.len());
            if end <= s {
                return 0.0;
            }
            (x[s..end].iter().map(|v| v * v).sum::<f64>() / (end - s) as f64).sqrt()
        })
        .collect()
}

/// Gains per sample from a frame-energy noise gate.
fn gate(x: &[f64]) -> Vec<f64> {
    let rms = frame_rms(x);
    let mut sorted: Vec<f64> = rms.iter().copied().filter(|v| *v > 0.0).collect();
    if sorted.is_empty() {
        return vec![0.0; x.len()];
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let floor = sorted[sorted.len() / 10].max(1e-5);
    let peak = sorted[sorted.len() * 95 / 100];
    let open = (floor * 3.0).max(peak * 0.03);
    let target: Vec<f64> = rms.iter().map(|&r| if r >= open { 1.0 } else { 0.0 }).collect();
    // Hold open 100 ms after speech, and smooth.
    let hold = 7;
    let mut held = target.clone();
    for i in 0..target.len() {
        if target[i] > 0.0 {
            for h in held.iter_mut().take((i + hold).min(target.len())).skip(i.saturating_sub(2)) {
                *h = 1.0;
            }
        }
    }
    (0..x.len())
        .map(|n| {
            let pos = n as f64 / HOP as f64;
            let i = (pos as usize).min(held.len() - 1);
            let next = (i + 1).min(held.len() - 1);
            let t = pos - i as f64;
            let g = held[i] * (1.0 - t) + held[next] * t;
            0.02 + 0.98 * g
        })
        .collect()
}

/// The level speech is measured against: the 95th percentile of the frame
/// levels, not the maximum. One unstable frame of the warped filter (a
/// spike) used to set "loud", so trim cut away everything below 5% of the
/// spike -- about 1 note in 200 came out at a third of its length, or was
/// refused as "no speech".
fn speech_peak(rms: &[f64]) -> f64 {
    let mut sorted: Vec<f64> = rms.iter().copied().filter(|v| v.is_finite() && *v > 0.0).collect();
    if sorted.is_empty() {
        return 0.0;
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted[(sorted.len() * 95 / 100).min(sorted.len() - 1)]
}

fn trim(x: &mut Vec<f64>) {
    let rms = frame_rms(x);
    let peak = speech_peak(&rms);
    if peak <= 0.0 {
        x.clear();
        return;
    }
    let first = rms.iter().position(|&r| r > peak * 0.05).unwrap_or(0);
    let last = rms.iter().rposition(|&r| r > peak * 0.05).unwrap_or(rms.len() - 1);
    let start = first.saturating_sub(5) * HOP;
    let end = ((last + 6) * HOP + FRAME).min(x.len());
    if start < end {
        *x = x[start..end].to_vec();
    }
}

fn normalise(x: &mut [f64]) {
    let rms = frame_rms(x);
    let peak = speech_peak(&rms);
    let active: Vec<f64> = rms.into_iter().filter(|&r| r > peak * 0.1).collect();
    if active.is_empty() {
        return;
    }
    let level = (active.iter().map(|r| r * r).sum::<f64>() / active.len() as f64).sqrt();
    let gain = 0.1 / level.max(1e-9); // -20 dBFS
    for v in x.iter_mut() {
        *v = (*v * gain).tanh() * 0.98;
    }
}

// -- the spectral path (Disguise, Synthetic) ------------------------------------
//
// Device report (2026-10-15, rc.76): "disguise and synthetic sound like a
// whistle". Measured on the reference clip: Synthetic put 80 % of its energy
// above 4 kHz (speech: 12 %), with narrow peaks there. The cause was the
// LPC pole warp: McAdams with alpha > 1 and a scale up to 1.16 pushed
// formant poles towards Nyquist, where they were clamped at radius 0.995 --
// a resonator that rings -- and each 30 ms frame was filtered from a zero
// state, so the ringing restarted every frame. A real phone microphone
// (noise, room) made it worse than the clean test clips did.
//
// The spectral path cannot ring, because it never builds a resonator:
//   1. STFT (32 ms, 8 ms hop). Each frame's ENVELOPE (the vocal tract) is a
//      cepstrally smoothed log spectrum ("true envelope": lifted to the
//      peaks), so it is smooth by construction.
//   2. The envelope is warped along frequency: the McAdams warp (what was
//      at angle phi moves to scale * phi^alpha), then a bilinear (all-pass)
//      vocal-tract-length warp. Every formant moves, non-linearly.
//   3. DISGUISE: the speaker's harmonics are pitch-shifted (resample +
//      WSOLA), their own envelope divided out and the warped one put in.
//      SYNTHETIC: a generated pulse train (monotone, slight drift) and
//      noise, shaped the same way: none of the speaker's source remains.
//   4. A FIXED reference balance: every note's long-term spectrum is
//      pulled to the standard long-term speech spectrum (flat to 500 Hz,
//      then -5 dB per octave), within +/- 12 dB. Brightness, microphone
//      and the speaker's own spectral colour are not cues any more.
// Settings are drawn per note as before and never leave this function.

const SN: usize = 512;
const SH: usize = 128;
const BINS: usize = SN / 2 + 1;
const LIFTER: usize = 28;

/// In-place complex FFT (radix 2, [re].len() a power of two).
fn fft(re: &mut [f64], im: &mut [f64], inverse: bool) {
    let n = re.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let ang = 2.0 * PI / len as f64 * if inverse { 1.0 } else { -1.0 };
        let (wr, wi) = (ang.cos(), ang.sin());
        for start in (0..n / len).map(|k| k * len) {
            let (mut cr, mut ci) = (1.0, 0.0);
            for k in 0..len / 2 {
                let (a, b) = (start + k, start + k + len / 2);
                let tr = re[b] * cr - im[b] * ci;
                let ti = re[b] * ci + im[b] * cr;
                re[b] = re[a] - tr;
                im[b] = im[a] - ti;
                re[a] += tr;
                im[a] += ti;
                let nr = cr * wr - ci * wi;
                ci = cr * wi + ci * wr;
                cr = nr;
            }
        }
        len <<= 1;
    }
    if inverse {
        for v in re.iter_mut().chain(im.iter_mut()) {
            *v /= n as f64;
        }
    }
}

/// Spectrum of SN real samples: BINS (re, im) pairs.
fn rfft(x: &[f64]) -> (Vec<f64>, Vec<f64>) {
    let mut re = x.to_vec();
    re.resize(SN, 0.0);
    let mut im = vec![0.0; SN];
    fft(&mut re, &mut im, false);
    re.truncate(BINS);
    im.truncate(BINS);
    (re, im)
}

/// SN real samples from BINS (re, im) pairs (Hermitian completion).
fn irfft(re: &[f64], im: &[f64]) -> Vec<f64> {
    let mut r = vec![0.0; SN];
    let mut i = vec![0.0; SN];
    for k in 0..BINS {
        r[k] = re[k];
        i[k] = im[k];
        if k > 0 && k < SN / 2 {
            r[SN - k] = re[k];
            i[SN - k] = -im[k];
        }
    }
    fft(&mut r, &mut i, true);
    r
}

fn sqrt_hann() -> Vec<f64> {
    (0..SN).map(|i| (0.5 - 0.5 * (2.0 * PI * i as f64 / SN as f64).cos()).sqrt()).collect()
}

/// Frames of (re, im) spectra; the signal is padded by SN on each side.
fn stft(x: &[f64], win: &[f64]) -> Vec<(Vec<f64>, Vec<f64>)> {
    let mut padded = vec![0.0; SN];
    padded.extend_from_slice(x);
    padded.extend(std::iter::repeat_n(0.0, SN));
    (0..(padded.len() - SN) / SH)
        .map(|i| {
            let f: Vec<f64> = (0..SN).map(|k| padded[i * SH + k] * win[k]).collect();
            rfft(&f)
        })
        .collect()
}

fn istft(frames: &[(Vec<f64>, Vec<f64>)], n: usize, win: &[f64]) -> Vec<f64> {
    let total = frames.len() * SH + SN;
    let mut out = vec![0.0; total];
    let mut norm = vec![0.0; total];
    for (i, (re, im)) in frames.iter().enumerate() {
        let f = irfft(re, im);
        for k in 0..SN {
            out[i * SH + k] += f[k] * win[k];
            norm[i * SH + k] += win[k] * win[k];
        }
    }
    (0..n).map(|k| {
        let j = k + SN;
        if j < total && norm[j] > 1e-6 { out[j] / norm[j] } else { 0.0 }
    }).collect()
}

/// A frame's smooth log-magnitude envelope (cepstral, lifted to the peaks).
fn log_envelope(re: &[f64], im: &[f64]) -> Vec<f64> {
    let lm: Vec<f64> = (0..BINS).map(|k| (re[k].hypot(im[k]) + 1e-7).ln()).collect();
    let smooth = |target: &[f64]| -> Vec<f64> {
        let zero = vec![0.0; BINS];
        let mut c = irfft(target, &zero);
        for v in c.iter_mut().take(SN - LIFTER + 1).skip(LIFTER) {
            *v = 0.0;
        }
        rfft(&c).0
    };
    let mut env = smooth(&lm);
    for _ in 0..4 {
        let lifted: Vec<f64> = lm.iter().zip(&env).map(|(a, b)| a.max(*b)).collect();
        env = smooth(&lifted);
    }
    env
}

/// The envelope moved along frequency by the bilinear warp [a] (> 0:
/// formants up, < 0: down). Ends stay put.
fn warp_log_envelope(env: &[f64], a: f64) -> Vec<f64> {
    (0..BINS).map(|k| {
        let w = PI * k as f64 / (BINS - 1) as f64;
        let src = w + 2.0 * (-a * w.sin()).atan2(1.0 + a * w.cos());
        let pos = (src / PI * (BINS - 1) as f64).clamp(0.0, (BINS - 1) as f64);
        let i = (pos as usize).min(BINS - 2);
        let t = pos - i as f64;
        env[i] * (1.0 - t) + env[i + 1] * t
    }).collect()
}

/// The McAdams warp on the ENVELOPE: what was at angle phi moves to
/// scale * phi^alpha. Read backwards: output angle w takes the envelope at
/// (w / scale)^(1 / alpha). No pole is built, so nothing can ring.
fn mcadams_log_envelope(env: &[f64], alpha: f64, scale: f64) -> Vec<f64> {
    (0..BINS).map(|k| {
        let w = PI * k as f64 / (BINS - 1) as f64;
        let src = (w / scale).max(0.0).powf(1.0 / alpha);
        let pos = (src / PI * (BINS - 1) as f64).clamp(0.0, (BINS - 1) as f64);
        let i = (pos as usize).min(BINS - 2);
        let t = pos - i as f64;
        env[i] * (1.0 - t) + env[i + 1] * t
    }).collect()
}

/// The note's long-term spectrum pulled to the standard speech spectrum.
fn reference_balance(frames: &mut [(Vec<f64>, Vec<f64>)]) {
    let energy: Vec<f64> = frames.iter()
        .map(|(re, im)| re.iter().zip(im).map(|(a, b)| a * a + b * b).sum())
        .collect();
    let mut sorted = energy.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let Some(&median) = sorted.get(sorted.len() / 2) else { return };
    let mut lt = vec![1e-12; BINS];
    for ((re, im), e) in frames.iter().zip(&energy) {
        if *e > median {
            for k in 0..BINS {
                lt[k] += re[k] * re[k] + im[k] * im[k];
            }
        }
    }
    let smooth9 = |v: &[f64]| -> Vec<f64> {
        (0..v.len()).map(|k| {
            let lo = k.saturating_sub(4);
            let hi = (k + 5).min(v.len());
            v[lo..hi].iter().sum::<f64>() / (hi - lo) as f64
        }).collect()
    };
    let lt = smooth9(&lt);
    let reference: Vec<f64> = (0..BINS).map(|k| {
        let f = k as f64 * RATE as f64 / SN as f64;
        let db = if f < 500.0 { 0.0 } else { -5.0 * (f / 500.0).log2() };
        10f64.powf(db / 10.0)
    }).collect();
    let scale = lt.iter().sum::<f64>() / reference.iter().sum::<f64>();
    let gain_db: Vec<f64> = (0..BINS)
        .map(|k| (10.0 * (reference[k] * scale / lt[k]).log10()).clamp(-12.0, 12.0))
        .collect();
    let gain_db = smooth9(&gain_db);
    for (re, im) in frames.iter_mut() {
        for k in 0..BINS {
            let g = 10f64.powf(gain_db[k] / 20.0);
            re[k] *= g;
            im[k] *= g;
        }
    }
}

/// The source for SYNTHETIC: a monotone pulse train with a slow drift where
/// the speaker was voiced, noise where not. None of the speaker's source.
fn synthetic_excitation(x: &[f64], params: &Params, rng: &mut StdRng) -> Vec<f64> {
    let n = x.len();
    let frames = n / HOP + 1;
    let mut voiced = vec![0.0; frames];
    for (i, v) in voiced.iter_mut().enumerate() {
        let s = i * HOP;
        let end = (s + FRAME).min(n);
        if end > s + 8 && voicing(&x[s..end]) > 0.3 {
            *v = 1.0;
        }
    }
    // Voicing per sample, smoothed over 25 ms so it does not click.
    let raw: Vec<f64> = (0..n).map(|k| voiced[(k / HOP).min(frames - 1)]).collect();
    let mut vv = vec![0.0; n];
    let half = 200usize;
    let mut acc = 0.0;
    for k in 0..n + half {
        if k < n {
            acc += raw[k];
        }
        if k > 2 * half && k - 2 * half - 1 < n {
            acc -= raw[k - 2 * half - 1];
        }
        if k >= half && k - half < n {
            vv[k - half] = acc / (2 * half + 1) as f64;
        }
    }
    // MIXED excitation, as real voices are: harmonic below ~3 kHz, breath
    // above it. A pure pulse train is harmonic to 8 kHz -- clean lines up
    // there read as a buzz or a whistle. Each period also varies by a
    // little (jitter), as no glottis is a metronome.
    let mut out = vec![0.0; n];
    let mut phase = 0.0f64;
    let mut glottal = 0.0f64;
    let mut jitter = 1.0f64;
    let (mut lp1, mut lp2, mut nlp1, mut nlp2) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    let c = (-2.0 * PI * 3000.0 / RATE as f64).exp();
    for (k, sample) in out.iter_mut().enumerate() {
        let t = k as f64 / RATE as f64;
        let f0 = params.f0 * jitter * (1.0 + 0.03 * (2.0 * PI * 0.3 * t + params.drift).sin());
        phase += f0 / RATE as f64;
        let pulse = if phase >= 1.0 {
            phase -= 1.0;
            jitter = 1.0 + rng.gen_range(-0.012..0.012);
            1.0
        } else {
            0.0
        };
        glottal = pulse + 0.9 * glottal; // a soft glottal tilt
        // Two one-pole low-passes at ~3 kHz: harmonics below, breath above.
        lp1 = (1.0 - c) * glottal + c * lp1;
        lp2 = (1.0 - c) * lp1 + c * lp2;
        let noise: f64 = rng.gen_range(-1.0..1.0) * 0.3;
        nlp1 = (1.0 - c) * noise + c * nlp1;
        nlp2 = (1.0 - c) * nlp1 + c * nlp2;
        let breath = noise - nlp2;
        *sample = vv[k] * (lp2 + 0.6 * breath) + (1.0 - vv[k]) * noise;
    }
    out
}

fn spectral_mask(x: &[f64], params: &Params, mode: Mode, rng: &mut StdRng) -> Vec<f64> {
    let n = x.len();
    let win = sqrt_hann();
    let original = stft(x, &win);
    let source = match mode {
        Mode::Synthetic => synthetic_excitation(x, params, rng),
        _ => {
            let mut s = shift(x, params.pitch, 1.0);
            s.resize(n, 0.0);
            s
        }
    };
    let carrier = stft(&source, &win);
    // NOT ONE TRANSFORM PER NOTE: the warps also move, smoothly and at
    // random, through the note -- a fresh random value every 0.25 s for
    // each, interpolated. Owner (2026-10-15): "use true random entropy so AI
    // can't reverse the audio". With only per-note settings, a note could in
    // principle be undone by searching the few settings' ranges (they are in
    // this open source); with a random path through them, drawn from the OS
    // generator, there are dozens of unknowns per second of speech, and the
    // smoothing, the envelope, the reference balance and (in Synthetic) the
    // replaced source discard information that no setting brings back.
    let frames_n = original.len().min(carrier.len());
    let knot = (RATE as usize / 4) / SH; // frames per 0.25 s
    let knots = frames_n / knot.max(1) + 2;
    let path_a: Vec<f64> = (0..knots).map(|_| rng.gen_range(-1.0..1.0)).collect();
    let path_w: Vec<f64> = (0..knots).map(|_| rng.gen_range(-1.0..1.0)).collect();
    let along = |path: &[f64], fi: usize| -> f64 {
        let pos = fi as f64 / knot.max(1) as f64;
        let i = (pos as usize).min(path.len() - 2);
        let t = pos - i as f64;
        let s = 0.5 - 0.5 * (PI * t).cos();
        path[i] * (1.0 - s) + path[i + 1] * s
    };
    let mut frames: Vec<(Vec<f64>, Vec<f64>)> = original.iter().zip(carrier.iter()).enumerate()
        .map(|(fi, ((xr, xi), (yr, yi)))| {
            let alpha = params.alpha * (1.0 + 0.03 * along(&path_a, fi));
            let warp = params.warp + 0.025 * along(&path_w, fi);
            // Two warps on the smooth envelope: McAdams (non-linear, the
            // VoicePrivacy B2 transform) then a bilinear length warp.
            // Measured with a speaker-recognition network (VOICE_NOTES.md):
            // either alone left the speaker more recognisable.
            let env = log_envelope(xr, xi);
            let target = warp_log_envelope(&mcadams_log_envelope(&env, alpha, params.scale), warp);
            let own = log_envelope(yr, yi);
            let mut re = yr.clone();
            let mut im = yi.clone();
            for k in 0..BINS {
                let g = (target[k] - own[k]).clamp(-30.0, 30.0).exp();
                re[k] *= g;
                im[k] *= g;
            }
            (re, im)
        })
        .collect();
    reference_balance(&mut frames);
    let y = istft(&frames, n, &win);
    if (params.rate - 1.0).abs() > 1e-3 { wsola(&y, params.rate) } else { y }
}

/// Mask one note. [pcm] is mono f64 at [rate]; returns mono f64 at [RATE].
fn mask_f64(pcm: &[f64], rate: u32, mode: Mode, rng: &mut StdRng) -> Vec<f64> {
    let mut params = draw(mode, rng);
    let y = mask_with_params(pcm, rate, mode, &params, rng);
    // The settings are secret: not returned, not logged, and wiped here.
    params.zeroize();
    y
}

fn mask_with_params(pcm: &[f64], rate: u32, mode: Mode, params: &Params, rng: &mut StdRng) -> Vec<f64> {
    let mut x = resample(pcm, rate as f64, RATE as f64);
    if x.len() < FRAME {
        return Vec::new();
    }
    // High-pass at about 80 Hz (and DC).
    let mut prev_in = 0.0;
    let mut prev_out = 0.0;
    let r = (-2.0 * PI * 80.0 / RATE as f64).exp();
    for v in x.iter_mut() {
        let y = *v - prev_in + r * prev_out;
        prev_in = *v;
        prev_out = y;
        *v = y;
    }
    // Gate before anything is measured, so room tone measures nothing.
    let gains = gate(&x);
    for (v, g) in x.iter_mut().zip(gains.iter()) {
        *v *= g;
    }
    // Disguise and Synthetic: the spectral path (rc.77). Natural keeps the
    // LPC clean-up below, unchanged.
    if mode != Mode::Natural {
        let mut y = spectral_mask(&x, params, mode, rng);
        x.zeroize();
        trim(&mut y);
        normalise(&mut y);
        if y.iter().any(|v| !v.is_finite()) {
            return Vec::new();
        }
        return y;
    }
    // Channel: remove the recording's own long-term tilt...
    let win = hann(FRAME);
    let mut avg = vec![0.0; 3];
    let mut n_frames = 0;
    let mut s = 0;
    while s + FRAME <= x.len() {
        let f: Vec<f64> = (0..FRAME).map(|k| x[s + k] * win[k]).collect();
        for (a, b) in avg.iter_mut().zip(autocorr(&f, 2)) {
            *a += b;
        }
        n_frames += 1;
        s += HOP;
    }
    if n_frames > 0 {
        if let Some(tilt) = levinson(&avg, 2) {
            x = fir(&tilt, &x);
        }
    }
    // Source/filter, frame by frame.
    let n_frames = (x.len() - FRAME) / HOP + 1;
    let mut filters: Vec<Vec<f64>> = Vec::with_capacity(n_frames);
    let mut source = vec![0.0; x.len()];
    for i in 0..n_frames {
        let s = i * HOP;
        let f: Vec<f64> = (0..FRAME).map(|k| x[s + k] * win[k]).collect();
        let a = lpc(&f, ORDER).unwrap_or_else(|| {
            let mut z = vec![0.0; ORDER + 1];
            z[0] = 1.0;
            z
        });
        for (k, v) in fir(&a, &f).into_iter().enumerate() {
            source[s + k] += v;
        }
        filters.push(mcadams(&a, params.alpha, params.scale, params.gamma));
    }
    // A new pitch and rate for the source; or a new source altogether.
    let mut src = shift(&source, params.pitch, params.rate);
    if mode == Mode::Synthetic {
        src = synthetic_source(&src, params, rng);
    }
    // ...the warped vocal tract over it, on the stretched time line.
    let mut y = vec![0.0; src.len() + FRAME];
    let out_frames = src.len().saturating_sub(FRAME) / HOP + 1;
    for j in 0..out_frames {
        let s = j * HOP;
        if s + FRAME > src.len() {
            break;
        }
        let i = ((j as f64 / params.rate).round() as usize).min(filters.len() - 1);
        let f: Vec<f64> = (0..FRAME).map(|k| src[s + k] * win[k]).collect();
        for (k, v) in iir(&filters[i], &f).into_iter().enumerate() {
            y[s + k] += v;
        }
    }
    y.truncate(src.len());
    // ...and the fixed reference tilt.
    let mut prev = 0.0;
    for v in y.iter_mut() {
        *v += 0.6 * prev;
        prev = *v;
    }
    trim(&mut y);
    normalise(&mut y);
    if y.iter().any(|v| !v.is_finite()) {
        return Vec::new();
    }
    y
}

/// Mask s16le mono [pcm] at [rate]; s16le mono at [RATE]. Every call
/// draws its own settings from the operating system's random generator
/// (`getrandom`: the kernel CSPRNG, seeded from the device's hardware
/// entropy) -- the same source as every encryption key in this core. There
/// is no way to choose them: production has no seed parameter at all.
pub fn mask(pcm: &[u8], rate: u32, mode: Mode) -> Result<Vec<u8>, &'static str> {
    mask_with(pcm, rate, mode, None)
}

/// [mask], with a fixed seed for the unit tests. Outside `cfg(test)` a seed
/// is ignored and the OS generator is used, so no build can be made to
/// give every note the same voice by passing one.
fn mask_with(pcm: &[u8], rate: u32, mode: Mode, seed: Option<[u8; 32]>) -> Result<Vec<u8>, &'static str> {
    if !pcm.len().is_multiple_of(2) {
        return Err("PCM is not whole 16-bit samples");
    }
    if !(8_000..=96_000).contains(&rate) {
        return Err("unsupported sample rate");
    }
    if pcm.len() / 2 > rate as usize * MAX_SECONDS {
        return Err("voice note too long");
    }
    let mut seed = match seed {
        Some(s) if cfg!(test) => s,
        _ => {
            // Fail closed: a note is refused, never masked with weak or
            // predictable settings, if the OS cannot supply randomness.
            let mut s = [0u8; 32];
            OsRng.try_fill_bytes(&mut s).map_err(|_| "no system randomness")?;
            s
        }
    };
    let mut rng = StdRng::from_seed(seed);
    seed.zeroize();
    let mut input: Vec<f64> = pcm
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]) as f64 / 32768.0)
        .collect();
    let mut y = mask_f64(&input, rate, mode, &mut rng);
    input.zeroize();
    let mut out = Vec::with_capacity(y.len() * 2);
    for v in &y {
        let s = (v * 32767.0).round().clamp(-32768.0, 32767.0) as i16;
        out.extend_from_slice(&s.to_le_bytes());
    }
    y.zeroize();
    Ok(out)
}

/// Python: `voice_mask(pcm, sample_rate, mode) -> bytes`. No seed: the
/// settings are always the OS generator's (see [mask]).
/// [mode] is "natural", "disguise" or "synthetic". Returns 16 kHz s16le
/// mono; empty if there was no speech.
#[pyfunction]
#[pyo3(signature = (pcm, sample_rate, mode))]
pub fn voice_mask<'py>(py: Python<'py>, pcm: &[u8], sample_rate: u32, mode: &str)
                       -> PyResult<Bound<'py, PyBytes>> {
    let mode = Mode::parse(mode).ok_or_else(|| PyValueError::new_err("unknown voice mode"))?;
    let pcm = pcm.to_vec();
    let out = py.detach(move || mask(&pcm, sample_rate, mode)).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &out))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(voice_mask, m)?)?;
    m.add("VOICE_MASK_RATE", RATE)?;
    m.add("VOICE_MASK_MAX_SECONDS", MAX_SECONDS)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic "speaker": a pulse train at [f0] through formant
    /// resonators, voiced in bursts like syllables.
    fn speaker(f0: f64, formants: &[f64], seconds: f64) -> Vec<f64> {
        let n = (RATE as f64 * seconds) as usize;
        let mut x = vec![0.0; n];
        let period = RATE as f64 / f0;
        let mut next = 0.0;
        for (i, v) in x.iter_mut().enumerate() {
            if i as f64 >= next {
                *v = 1.0;
                next += period;
            }
        }
        for &f in formants {
            let r: f64 = 0.97;
            let th = 2.0 * PI * f / RATE as f64;
            let a = [1.0, -2.0 * r * th.cos(), r * r];
            x = iir(&a, &x);
        }
        let peak = x.iter().fold(0.0f64, |m, v| m.max(v.abs()));
        for (i, v) in x.iter_mut().enumerate() {
            let t = i as f64 / RATE as f64;
            let syllable = if (t * 4.0).fract() < 0.7 { 1.0 } else { 0.0 };
            *v = *v / peak * 0.5 * syllable;
        }
        x
    }

    fn to_pcm(x: &[f64]) -> Vec<u8> {
        x.iter().flat_map(|v| ((v * 32767.0) as i16).to_le_bytes()).collect()
    }

    fn from_pcm(b: &[u8]) -> Vec<f64> {
        b.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]]) as f64 / 32768.0).collect()
    }

    /// The strongest spectral peak of a long-term LPC envelope, in Hz.
    fn first_formant(x: &[f64]) -> f64 {
        let a = lpc(&x[..x.len().min(RATE as usize)], 12).unwrap();
        let mut best = (0.0, 0.0);
        for hz in (15..150).map(|i| i * 10) {
            let w = 2.0 * PI * hz as f64 / RATE as f64;
            let (mut re, mut im) = (0.0, 0.0);
            for (k, c) in a.iter().enumerate() {
                re += c * (w * k as f64).cos();
                im -= c * (w * k as f64).sin();
            }
            let gain = 1.0 / (re * re + im * im);
            if gain > best.1 {
                best = (hz as f64, gain);
            }
        }
        best.0
    }

    fn pitch(x: &[f64]) -> f64 {
        // The loudest 100 ms, then the SHORTEST lag whose correlation is
        // near the best one (a subharmonic is never preferred).
        let start = (0..x.len().saturating_sub(1600).div_ceil(400)).map(|i| i * 400)
            .max_by(|&a, &b| {
                let e = |s: usize| x[s..s + 1600].iter().map(|v| v * v).sum::<f64>();
                e(a).partial_cmp(&e(b)).unwrap()
            })
            .unwrap();
        let seg = &x[start..start + 1600];
        let lo = (RATE / 400) as usize;
        let hi = (RATE / 50) as usize;
        let r: Vec<f64> = (0..hi)
            .map(|lag| seg.iter().zip(seg.iter().skip(lag)).map(|(a, b)| a * b).sum())
            .collect();
        let best = r[lo..hi].iter().copied().fold(f64::MIN, f64::max);
        let lag = (lo + 1..hi - 1)
            .find(|&l| r[l] >= 0.85 * best && r[l] >= r[l - 1] && r[l] >= r[l + 1])
            .unwrap_or(lo);
        RATE as f64 / lag as f64
    }

    #[test]
    fn levinson_and_mcadams_identity() {
        let x = speaker(120.0, &[700.0, 1200.0], 0.5);
        let a = lpc(&x[1000..1480], ORDER).unwrap();
        assert_eq!(mcadams(&a, 1.0, 1.0, 1.0), a);
        let warped = mcadams(&a, 0.8, 1.1, 0.95);
        assert_eq!(warped.len(), a.len());
        assert!(warped.iter().all(|v| v.is_finite()));
        assert!(warped.iter().zip(&a).any(|(p, q)| (p - q).abs() > 1e-3));
    }

    #[test]
    fn resample_keeps_a_tone() {
        let x: Vec<f64> = (0..48_000).map(|n| (2.0 * PI * 440.0 * n as f64 / 48_000.0).sin()).collect();
        let y = resample(&x, 48_000.0, 16_000.0);
        assert!((y.len() as i64 - 16_000).abs() <= 1);
        let tone: f64 = 2.0 * PI * 440.0 / 16_000.0;
        let err: f64 = (100..15_900).map(|n| (y[n] - (tone * n as f64).sin()).abs()).fold(0.0, f64::max);
        assert!(err < 0.05, "{}", err);
    }

    #[test]
    fn natural_keeps_the_voice_disguise_moves_it() {
        let x = speaker(120.0, &[600.0, 1700.0], 3.0);
        let seed = [7u8; 32];
        let nat = from_pcm(&mask_with(&to_pcm(&x), RATE, Mode::Natural, Some(seed)).unwrap());
        let dis = from_pcm(&mask_with(&to_pcm(&x), RATE, Mode::Disguise, Some(seed)).unwrap());
        assert!((pitch(&nat) - 120.0).abs() < 8.0, "natural pitch {}", pitch(&nat));
        let moved = (pitch(&dis) / 120.0).ln().abs();
        assert!(moved > 0.12, "disguised pitch {}", pitch(&dis));
        assert!((first_formant(&dis) - first_formant(&nat)).abs() > 40.0,
                "formant {} vs {}", first_formant(&dis), first_formant(&nat));
    }

    #[test]
    fn every_note_draws_its_own_settings() {
        let x = speaker(140.0, &[500.0, 1500.0], 2.0);
        let a = mask_with(&to_pcm(&x), RATE, Mode::Disguise, None).unwrap();
        let b = mask_with(&to_pcm(&x), RATE, Mode::Disguise, None).unwrap();
        assert_ne!(a, b);
        let pa = from_pcm(&a);
        let pb = from_pcm(&b);
        assert!(!pa.is_empty() && !pb.is_empty());
    }

    #[test]
    fn synthetic_replaces_the_source_pitch() {
        let low = speaker(90.0, &[600.0, 1700.0], 3.0);
        let high = speaker(220.0, &[600.0, 1700.0], 3.0);
        let seed = [3u8; 32];
        let a = from_pcm(&mask_with(&to_pcm(&low), RATE, Mode::Synthetic, Some(seed)).unwrap());
        let b = from_pcm(&mask_with(&to_pcm(&high), RATE, Mode::Synthetic, Some(seed)).unwrap());
        // Same settings, very different speakers' pitch: the same output pitch.
        let (pa, pb) = (pitch(&a), pitch(&b));
        assert!((pa / pb).ln().abs() < 0.1, "{} vs {}", pa, pb);
    }

    #[test]
    fn silence_and_bad_input() {
        assert!(mask_with(&[0u8; 32_000], RATE, Mode::Disguise, None).unwrap().len() < 32_000);
        assert!(mask_with(&[1u8; 3], RATE, Mode::Disguise, None).is_err());
        assert!(mask_with(&[0u8; 100], 1000, Mode::Disguise, None).is_err());
        let too_long = vec![0u8; (RATE as usize * (MAX_SECONDS + 1)) * 2];
        assert!(mask_with(&too_long, RATE, Mode::Disguise, None).is_err());
    }

    #[test]
    fn level_is_normalised() {
        let quiet: Vec<f64> = speaker(130.0, &[700.0, 1100.0], 2.0).iter().map(|v| v * 0.05).collect();
        let y = from_pcm(&mask_with(&to_pcm(&quiet), RATE, Mode::Disguise, Some([1u8; 32])).unwrap());
        let peak = frame_rms(&y).into_iter().fold(0.0, f64::max);
        assert!(peak > 0.05 && peak < 0.5, "{}", peak);
    }

    #[test]
    fn fft_round_trip() {
        let x: Vec<f64> = (0..SN).map(|n| ((n * 7919) % 101) as f64 / 50.0 - 1.0).collect();
        let (re, im) = rfft(&x);
        let back = irfft(&re, &im);
        let err = x.iter().zip(&back).map(|(a, b)| (a - b).abs()).fold(0.0, f64::max);
        assert!(err < 1e-9, "{}", err);
        // A 1 kHz tone lands in its bin.
        let tone: Vec<f64> = (0..SN).map(|n| (2.0 * PI * 1000.0 * n as f64 / RATE as f64).sin()).collect();
        let (re, im) = rfft(&tone);
        let peak = (0..BINS).max_by(|&a, &b| re[a].hypot(im[a]).partial_cmp(&re[b].hypot(im[b])).unwrap()).unwrap();
        assert_eq!(peak, 32);
    }

    /// [speaker] plus breath, as a real voice has: white noise at about
    /// -24 dB under the voice, in the same syllables (deterministic).
    fn breathy(f0: f64, formants: &[f64], seconds: f64) -> Vec<f64> {
        let mut x = speaker(f0, formants, seconds);
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for v in x.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let noise = (state >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0;
            if *v != 0.0 {
                *v += 0.03 * noise;
            }
        }
        x
    }

    /// Share of the energy above 4 kHz, and how much of the energy above
    /// 3 kHz sits in its 3 strongest bins (a whistle is one line there;
    /// speech spreads it), over the louder frames, weighted by that energy.
    fn whistle(y: &[f64]) -> (f64, f64) {
        let win = sqrt_hann();
        let frames = stft(y, &win);
        let mut e: Vec<(f64, usize)> = frames.iter().enumerate()
            .map(|(i, (re, im))| (re.iter().zip(im).map(|(a, b)| a * a + b * b).sum(), i)).collect();
        e.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        let (mut hi, mut all, mut top, mut band_all) = (0.0, 0.0, 0.0, 0.0);
        for &(_, i) in e.iter().take(e.len() * 4 / 10) {
            let (re, im) = &frames[i];
            let p: Vec<f64> = (0..BINS).map(|k| re[k] * re[k] + im[k] * im[k]).collect();
            all += p.iter().sum::<f64>();
            hi += p[128..].iter().sum::<f64>();
            let mut band: Vec<f64> = p[96..].to_vec();
            band.sort_by(|a, b| b.partial_cmp(a).unwrap());
            top += band[..3].iter().sum::<f64>();
            band_all += band.iter().sum::<f64>();
        }
        (hi / all, top / band_all)
    }

    #[test]
    fn no_whistle() {
        // Device report rc.76: Synthetic put 80 % of its energy above 4 kHz.
        let x = breathy(130.0, &[650.0, 1500.0, 2600.0], 3.0);
        for seed in 0..12u8 {
            for mode in [Mode::Disguise, Mode::Synthetic] {
                let y = from_pcm(&mask_with(&to_pcm(&x), RATE, mode, Some([seed; 32])).unwrap());
                let (hf, peak) = whistle(&y);
                assert!(hf < 0.25, "{:?} seed {}: {:.0} % above 4 kHz", mode, seed, hf * 100.0);
                // Measured: speech 0.24, the rc.76 Synthetic whistle 0.56.
                assert!(peak < 0.40, "{:?} seed {}: {:.2} of the 3-8 kHz energy in 3 lines",
                        mode, seed, peak);
            }
        }
    }
}
