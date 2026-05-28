# CONTRIBUTING.md — patch for v10.7.5

Single-line edit at line 33.

**Find:**

```
Open an issue first to discuss. The single-file Python design is intentional — new features should be integrated there unless they require a C extension (e.g., new PQ primitive) or Rust crate (e.g., new secret type).
```

**Replace with:**

```
Open an issue first to discuss.  The single-file Python design is intentional — new features should be integrated there unless they require a new Rust crate or a new module in the Rust core (e.g., a new cryptographic primitive, a new secret type).  The C-extension path mentioned in earlier versions of this document was retired at v10.7.5 (Phase 5.3k); new C code is no longer accepted into the project.
```
