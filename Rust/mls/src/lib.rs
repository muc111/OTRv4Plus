// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! MLS (RFC 9420) group encryption for OTRv4Plus, on the core's own crypto.
//!
//! Stage 2 of MLS_FEASIBILITY.md: the provider and in-process groups. No
//! transport, no persistence, no UI yet.
//!
//! `unsafe` is denied everywhere except the one PQClean call in `mlkem`.
#![deny(unsafe_code)]

pub mod hpke_backend;
pub mod mlkem;
pub mod provider;

pub use provider::{CoreCrypto, CoreProvider, SignatureKeyPair, CIPHERSUITE};
