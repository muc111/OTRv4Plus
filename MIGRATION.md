# MIGRATION.md — patch for v10.7.5

The existing `MIGRATION.md` contains a "Build & Test" block around lines 225-236 that still invokes the C-extension build commands.  Apply the targeted edit below; do not wholesale-replace the file.

---

## Edit — replace the build block

**Find:**

```
## Build & Test

```bash
# Production build:
cd ~/OTRv4Plus && \
    python setup_otr4.py build_ext --inplace && \
    bash build_ed448.sh; \
    cd Rust && \
    cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so && \
```

**Replace with:**

```
## Build & Test

As of v10.7.5 OTRv4+ is Rust-core-only — no C extensions to build.

```bash
# Production build:
cd ~/OTRv4Plus/Rust && \
    cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so && \
    cd ..

# Verification:
cd Rust && cargo test --release --no-default-features --features pq-rust
# Expected: 20 passed, 0 failed.

python3 -c "import ast; ast.parse(open('otrv4+.py').read()); print('AST OK')"
PYTHONMALLOC=malloc python otrv4+.py --debug
```

The `python setup_otr4.py build_ext --inplace` and `bash build_ed448.sh` commands are removed.  Both were for the C extensions retired in Phase 5.3k.
