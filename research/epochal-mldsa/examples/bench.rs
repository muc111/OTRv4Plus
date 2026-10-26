// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Cost per member-epoch, as medians over many runs (ANALYSIS.md §5, §7).
//! `cargo run --release --example bench [runs]` prints a Markdown table.

use std::time::{Duration, Instant};

use epochal_mldsa::*;

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time<T>(runs: usize, mut f: impl FnMut(usize) -> T) -> Duration {
    median((0..runs).map(|i| {
        let t = Instant::now();
        std::hint::black_box(f(i));
        t.elapsed()
    }).collect())
}

fn main() {
    let runs: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(200);
    let g = |n: u64| GroupEpoch { group_id: b"bench@conference.example.test".to_vec(), epoch_id: n,
                                  authenticator: [n as u8; 32] };
    let mut s = EpochSigner::new(b"alice@example.test", [9; 32], 1);
    let mut pks = Vec::new();
    let keygen = time(runs, |i| {
        let n = i as u64 + 1;
        pks.push(s.epoch_keygen(n, &g(n)).unwrap());
    });
    let msg = vec![0x5Au8; 256];
    let sigs: Vec<_> = (0..runs).map(|i| sign(s.signing_key(i as u64 + 1).unwrap(), &msg)).collect();
    let signing = time(runs, |i| sign(s.signing_key(i as u64 + 1).unwrap(), &msg));
    let verifying = time(runs, |i| verify(&pks[i], &msg, &sigs[i]));
    let binding = time(runs, |i| verify_group_binding(&pks[i], &g(i as u64 + 1)));
    let mut board = ReleaseBoard::default();
    let release = time(runs - 1, |i| board.publish(s.release_epoch_key(i as u64 + 1).unwrap()));
    let forge = time(runs - 1, |i| board.forge_with_released_key(b"alice@example.test", i as u64 + 1, &msg));
    println!("| Operation (ML-DSA-87, median of {runs}) | Time |");
    println!("|---|---|");
    println!("| epoch_keygen (chain step + KeyGen_internal + binding tag) | {keygen:?} |");
    println!("| sign (hedged, with context) | {signing:?} |");
    println!("| verify | {verifying:?} |");
    println!("| verify_group_binding | {binding:?} |");
    println!("| release_epoch_key | {release:?} |");
    println!("| forge_with_released_key (rebuild from seed + sign) | {forge:?} |");
    println!();
    println!("| Size | Bytes |");
    println!("|---|---|");
    println!("| pk_N | {} |", pks[0].vk.encode().len());
    println!("| binding tag | 32 |");
    println!("| signature | {} |", sigs[0].bytes.len());
    println!("| release (seed) | 32 |");
}
