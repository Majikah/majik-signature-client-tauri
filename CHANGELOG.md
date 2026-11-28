# Changelog

## 1.6.0

- Align the facade package version with the Rust client and Tauri plugin at 1.6.0.
- Expose native detached batch signing and trusted-key MJKSMAP streaming verification.
- Add bounded client-side IPC preflight checks and adversarial boundary tests.
- Align streaming chunk limits with the Rust client's 64 MiB maximum.
- Expand JSDoc, wire DTO documentation, README usage and the facade-specific SECURITY.md.

## 1.5.1 - 2026-11-27

- Add native system-profile and recommended-streaming-configuration methods.
- Support optional/null chunk-size overrides up to 128 MiB, with automatic mode when omitted.
- Add strict override mode and retry-aware progress metadata.
- Document adaptive allocation fallback and the system recommendation policy.

