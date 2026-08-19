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
