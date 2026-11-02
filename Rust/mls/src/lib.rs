// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! MLS (RFC 9420) group encryption for OTRv4Plus, on the core's own crypto.
//!
//! Stage 2 of docs/MLS_FEASIBILITY.md: the provider and in-process groups. No
//! transport, no persistence, no UI yet.
//!
//! No `unsafe` anywhere: the pure-Rust `ml-kem` crate supplies seeded key
//! generation, so the former PQClean FFI in `mlkem` is gone.
#![forbid(unsafe_code)]

pub mod client;
pub mod group_voice;
pub mod hpke;
pub mod mlkem;
pub mod provider;
pub mod storage;

pub use client::{Event, MlsClient, MlsError};
pub use provider::{CoreCrypto, CoreProvider, SignatureKeyPair, CIPHERSUITE};
