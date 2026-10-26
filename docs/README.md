# Documentation

Start with the [README](../README.md); [TECHNICAL.md](TECHNICAL.md) is the full
reference. Everything else is grouped below. Audits and reports are dated
records: they describe the code as it was when they were written.

## Protocol and design

- [SPEC.md](SPEC.md): OTRv4+ protocol specification (1:1)
- [SPEC_GROUP.md](SPEC_GROUP.md): group protocol specification
- [TECHNICAL.md](TECHNICAL.md): how everything works, build details
- [CRYPTO_SOURCE_OF_TRUTH.md](CRYPTO_SOURCE_OF_TRUTH.md): which code owns each primitive
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md): properties the code must keep
- [MLS_SECURITY_HARDENING.md](MLS_SECURITY_HARDENING.md): MLS+ (post-quantum groups) and call hardening
- [OTRV4PLUS_CAPABILITY.md](OTRV4PLUS_CAPABILITY.md): capability discovery
- [TRANSPORT_POLICY.md](TRANSPORT_POLICY.md): which networks carry what
- [VOICE_MEDIA_PATH.md](VOICE_MEDIA_PATH.md), [VOICE_LATENCY_BUDGET.md](VOICE_LATENCY_BUDGET.md): calls over I2P
- [VOICE_NOTES.md](VOICE_NOTES.md): voice notes and the synthetic voice
- [TRADE.md](TRADE.md): the Monero courier
- [FEATURES.md](FEATURES.md), [ROADMAP.md](ROADMAP.md), [WHY.md](WHY.md)

## Android

- [ANDROID_ENCRYPTION_ARCHITECTURE.md](ANDROID_ENCRYPTION_ARCHITECTURE.md): the three encryption systems and their boundary
- [ANDROID_CHAT_ARCHITECTURE.md](ANDROID_CHAT_ARCHITECTURE.md), [ANDROID_I2P_ARCHITECTURE.md](ANDROID_I2P_ARCHITECTURE.md)
- [ANDROID_CHAT_DELETION.md](ANDROID_CHAT_DELETION.md), [ANDROID_WIPE_AND_EXIT.md](ANDROID_WIPE_AND_EXIT.md)

## Running a server

- [SERVER_HARDENING.md](SERVER_HARDENING.md): hardening Prosody
- [SECURITY_SESSIONS.md](SECURITY_SESSIONS.md): one account, one device
- [PROSODY_USER_DISCOVERY.md](PROSODY_USER_DISCOVERY.md): the People list
- [STRESS_TEST.md](STRESS_TEST.md): load-testing your own server

## Development

- [DEVELOPMENT.md](DEVELOPMENT.md): running the tests, conventions
- [VERSIONING.md](VERSIONING.md): version numbers
- [MIGRATION.md](MIGRATION.md): upgrading old data
- [ASSETS.md](ASSETS.md): artwork provenance
- [SECURITY_ISSUES.md](SECURITY_ISSUES.md): tracked security issues
- [DENIABILITY_LAYERS.md](DENIABILITY_LAYERS.md): what each deniability mechanism denies and still proves (for reviewers)
- [PQC_DECISIONS.md](PQC_DECISIONS.md): post-quantum choices for the deniability work, with rationale
- [AUDIT_SUMMARY.md](AUDIT_SUMMARY.md): the audit and hardening pass of 2026-10-26, what it removed and what it fixed
- [AUDIT_CLAIM_MATRIX.md](AUDIT_CLAIM_MATRIX.md): every protection claimed, its code, its test, its residual
- [AUDIT_TEST_INTEGRITY.md](AUDIT_TEST_INTEGRITY.md): what each claim test shows, with mutation results
- [AUDIT_THREAT_MODEL.md](AUDIT_THREAT_MODEL.md): the threat model walked against the code
- [CRYPTOGRAPHER_QUESTIONS.md](CRYPTOGRAPHER_QUESTIONS.md): the questions only a cryptographer can answer

## Test plans

- [PHYSICAL_TEST_PLAN.md](PHYSICAL_TEST_PLAN.md), [TWO_DEVICE_TEST.md](TWO_DEVICE_TEST.md)
- [ANDROID_DEVICE_TEST.md](ANDROID_DEVICE_TEST.md), [ANDROID_MESSAGING_DEVICE_TEST.md](ANDROID_MESSAGING_DEVICE_TEST.md), [ANDROID_CALL_AND_FILE_DEVICE_TEST.md](ANDROID_CALL_AND_FILE_DEVICE_TEST.md)
- [FILE_TRANSFER_TEST_PLAN.md](FILE_TRANSFER_TEST_PLAN.md), [VOICE_SOAK_TEST.md](VOICE_SOAK_TEST.md)

## Audits and reports (dated records)

- Security and crypto: [CRYPTO_AUDIT_2026-09.md](CRYPTO_AUDIT_2026-09.md), [SECURITY_AUDIT_2026-10-11.md](SECURITY_AUDIT_2026-10-11.md), [GROUP_CRYPTO_AUDIT.md](GROUP_CRYPTO_AUDIT.md), [RUST_AUTHORITY_AUDIT.md](RUST_AUTHORITY_AUDIT.md), [RUST_SECURITY_PATCHES.md](RUST_SECURITY_PATCHES.md), [MAC_FIX_REVIEW.md](MAC_FIX_REVIEW.md), [MAC_KEY_REVELATION_AUDIT.md](MAC_KEY_REVELATION_AUDIT.md), [SKIP_AUDIT.md](SKIP_AUDIT.md), [AUDIT_HANDOFF.md](AUDIT_HANDOFF.md), [CHANGES.md](CHANGES.md)
- Android: [ANDROID_ARCHITECTURE_AUDIT.md](ANDROID_ARCHITECTURE_AUDIT.md), [ANDROID_STORAGE_AUDIT.md](ANDROID_STORAGE_AUDIT.md), [ANDROID_FOUNDATION_REPORT.md](ANDROID_FOUNDATION_REPORT.md), [ANDROID_PHASE2_REPORT.md](ANDROID_PHASE2_REPORT.md), [ANDROID_XMPP_MILESTONE.md](ANDROID_XMPP_MILESTONE.md), [ANDROID_I2P_FEASIBILITY.md](ANDROID_I2P_FEASIBILITY.md)
- Voice and transport: [VOICE_AUDIT_REPORT.md](VOICE_AUDIT_REPORT.md), [VOICE_PATH_INVESTIGATION.md](VOICE_PATH_INVESTIGATION.md), [AUDIO_BACKEND_REPORT.md](AUDIO_BACKEND_REPORT.md), [OPUS_AUDIT.md](OPUS_AUDIT.md), [TRANSPORT_AUDIT.md](TRANSPORT_AUDIT.md)
- Other: [SMP_UX_AUDIT.md](SMP_UX_AUDIT.md), [LICENSING_AUDIT.md](LICENSING_AUDIT.md), [MONERO_ESCROW_AUDIT.md](MONERO_ESCROW_AUDIT.md), [MLS_FEASIBILITY.md](MLS_FEASIBILITY.md), [FEASIBILITY_REPORT.md](FEASIBILITY_REPORT.md) (Qubes OS)
