//! Build-time release guard for the `test-only-kdf` feature.
//!
//! `test-only-kdf` compiles in `RustSMPVault::load` / `load_by_handle`, which
//! let Python read stored SMP secrets straight back out of the vault.  That is
//! the exact boundary the vault exists to enforce, so a wheel built with the
//! feature must never be shippable.
//!
//! Cargo.toml carried a comment proposing
//!
//!     #[cfg(all(feature = "test-only-kdf", feature = "extension-module"))]
//!     compile_error!(...)
//!
//! but that combination is also the *documented* way to build the wheel the
//! Python internals tests need, so adding it verbatim would make those tests
//! unrunnable.  A `compile_error!` cannot distinguish "a developer deliberately
//! asked for the test wheel" from "a release job enabled the feature by
//! accident", because it cannot read the environment.
//!
//! A build script can.  The rule enforced here:
//!
//!   building with `test-only-kdf` fails unless OTRV4PLUS_ALLOW_TEST_GATES=1
//!   is set explicitly in the environment.
//!
//! Fail-closed: the default outcome for any build that turns the feature on --
//! including one that inherits it transitively -- is a hard build failure.
//! Opting in is a deliberate, greppable, per-invocation act that a release
//! pipeline will not perform by accident.
//!
//! The complementary check on the other side of the boundary is
//! tests/test_release_guard.py, which asserts that the artifact actually
//! installed exposes no gated API.

fn main() {
    guard_test_only_kdf();
    guard_legacy_dake_keys();
    warn_if_cdylib_will_be_dropped();
}

/// Refuse to "succeed" at building a Python extension that has no `.so`.
///
/// `Cargo.toml` declares `crate-type = ["cdylib", "rlib"]`. When the target
/// statically links the C runtime, rustc cannot build a cdylib, so it drops
/// that crate type, prints one line about it among the compile output, and
/// **exits 0**. `target/release/` then holds `libotrv4_core.rlib` and
/// `libotrv4_core.d` and no `.so`, and the next step in the README:
///
///     cp target/release/libotrv4_core.so ../otrv4_core.so
///
/// fails with "No such file or directory", several steps and several minutes
/// from the cause. That is exactly how it was reported, twice.
///
/// **musl targets enable `crt-static` by default**, so this is the ordinary
/// outcome on Alpine rather than an exotic one. `.cargo/config.toml` turns it
/// off for the musl triples -- but cargo finds that file by walking up from
/// the directory it was INVOKED in, so it is skippable, and this is the
/// backstop for when it has been skipped.
///
/// **Hard error, not a warning, when `extension-module` is on.** That feature
/// means "I am building the Python extension"; finishing without one is not a
/// success worth reporting, and a warning was not enough -- it scrolls past in
/// several hundred lines of compile output exactly like rustc's own
/// `dropping unsupported crate type` line, which is what already went unread.
///
/// Without the feature -- `cargo test`, which wants only the rlib -- it stays
/// a warning, because failing there would take the Rust test suite with it.
fn warn_if_cdylib_will_be_dropped() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_FEATURE");
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    if !features.split(',').any(|f| f == "crt-static") {
        return;
    }
    let target = std::env::var("TARGET").unwrap_or_default();
    // Positional args rather than inline captures (`{target}`): this file is
    // compiled standalone by the test suite with plain `rustc`, which defaults
    // to an older edition where inline captures render as the literal text
    // "{target}" -- so a broken message would still have looked fine.
    let fix = format!(
        "crt-static is enabled for {}, so rustc drops the cdylib and \
         NO libotrv4_core.so is produced -- only the .rlib. The next step, \
         `cp target/release/libotrv4_core.so ..`, then fails with 'No such \
         file or directory'.\n\n\
         Fix, either one:\n  \
           * run cargo from inside Rust/, so Rust/.cargo/config.toml applies \
             -crt-static for you (cargo finds that file from the directory it \
             is invoked in, not from the manifest); or\n  \
           * build with RUSTFLAGS=\"-C target-feature=-crt-static\".\n\n\
         musl targets turn crt-static on by default, which is why this is the \
         usual outcome on Alpine.",
        target
    );
    if std::env::var_os("CARGO_FEATURE_EXTENSION_MODULE").is_some() {
        panic!("\n\n{}\n", fix);
    }
    for line in fix.lines() {
        println!("cargo:warning={}", line);
    }
}

/// M3: the legacy DAKE surface that returns session keys to Python as PyBytes.
///
/// Same fail-closed shape as the vault gate below: enabling the feature is a
/// build error unless the opt-in is explicit, so a release pipeline cannot turn
/// it on by accident or inherit it transitively.
fn guard_legacy_dake_keys() {
    println!("cargo:rerun-if-env-changed=OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS");

    if std::env::var_os("CARGO_FEATURE_LEGACY_DAKE_KEYS").is_none() {
        return;
    }
    let allowed = std::env::var("OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS")
        .map(|v| v == "1")
        .unwrap_or(false);
    if !allowed {
        panic!(
            "\n\
             ============================================================\n\
             REFUSING TO BUILD: `legacy-dake-keys` is enabled.\n\
             ============================================================\n\
             This feature compiles the legacy DAKE surface back in:\n\
             Dakeresult's root_key / chain_key_a / chain_key_b / brace_key /\n\
             mac_key getters, and PyDake::generate_dake2 / process_dake2 /\n\
             get_session_keys.  Those hand session key material to Python as\n\
             PyBytes.  An artifact built this way must not be distributed.\n\
             \n\
             The live path does not need it: generate_dake2_output and\n\
             process_dake2_output move keys Rust-to-Rust into the ratchet\n\
             through an opaque DakeOutput.\n\
             \n\
             If you are building for a test that genuinely exercises the legacy\n\
             surface, say so explicitly:\n\
             \n\
             OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1 cargo build \\\n\
                 --features legacy-dake-keys\n\
             ============================================================\n"
        );
    }
    println!("cargo:warning=OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1: legacy DAKE session-key \
              APIs are EXPOSED to Python. This artifact must not be distributed.");
}

fn guard_test_only_kdf() {
    println!("cargo:rerun-if-env-changed=OTRV4PLUS_ALLOW_TEST_GATES");

    let feature_on = std::env::var_os("CARGO_FEATURE_TEST_ONLY_KDF").is_some();
    if !feature_on {
        return;
    }

    let allowed = std::env::var("OTRV4PLUS_ALLOW_TEST_GATES")
        .map(|v| v == "1")
        .unwrap_or(false);

    if !allowed {
        panic!(
            "\n\
             ============================================================\n\
             REFUSING TO BUILD: `test-only-kdf` is enabled.\n\
             ============================================================\n\
             This feature compiles RustSMPVault::load and load_by_handle into\n\
             the module, which lets Python read stored SMP secrets back out.\n\
             An artifact built this way must never be distributed.\n\
             \n\
             If you are building the wheel for the Python internals tests,\n\
             say so explicitly:\n\
             \n\
             OTRV4PLUS_ALLOW_TEST_GATES=1 maturin build --release \\\n\
                 --features pyo3/extension-module,test-only-kdf\n\
             \n\
             If you did NOT intend to enable this feature, something in the\n\
             build turned it on -- find it rather than setting the variable.\n\
             ============================================================\n"
        );
    }

    println!("cargo:warning=OTRV4PLUS_ALLOW_TEST_GATES=1: building with test-only-kdf; \
              vault read-back is EXPOSED. This artifact must not be distributed.");
}
