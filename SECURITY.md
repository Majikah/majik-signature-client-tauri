# Security Policy

This policy covers the TypeScript package @majikah/majik-signature-client-tauri. It describes the security properties of this facade and its boundary with the native Tauri plugin. It is not the security policy for the cryptographic core or the Rust client.

## Supported versions

| Version | Status |
| --- | --- |
| 1.6.x | Current supported release line; use the latest patch |
| Earlier versions | Upgrade to the latest supported release |

This project is independently maintained. Security response and fixes are best-effort, not a contractual SLA.

## Reporting a vulnerability

Please do not disclose exploitable issues in public GitHub issues. Use GitHub Private Vulnerability Reporting:

- https://github.com/Majikah/majik-signature-client-tauri/security/advisories/new
- Or email business@majikah.solutions with SECURITY in the subject.

Include the affected package version, host OS, Tauri version, relevant facade method/command, reproducible steps and potential impact. Redact private keys, mnemonic phrases, passphrases, personal files and production database contents.

## What this package does

- Provides typed TypeScript methods and camelCase DTOs for the native tauri-plugin-majik-signature-client IPC command surface.
- Subscribes to the plugin's state and streaming progress event channels.
- Performs early client-side validation for known IPC limits to improve feedback and prevent accidental oversized requests.
- Does not implement signing algorithms, key storage, file canonicalization, hashing, signature parsing or verification. Those operations are performed by the Rust client and cryptographic dependencies inside the host process.

Client-side validation is not a security boundary. A modified webview, custom transport or direct Tauri invoke call can bypass it. The Rust plugin must independently validate every IPC payload before native file access or cryptographic work. The Rust plugin's SECURITY.md describes those authoritative checks.

## Security boundary and assumptions

- Native paths are interpreted by the Rust plugin with the host process's filesystem permissions. This facade does not sandbox, canonicalize or authorize a path.
- The host application must restrict Tauri capabilities to trusted webviews and grant only the minimum plugin commands required. The plugin's default permission set enables the full command surface.
- The plugin does not provide confidentiality. Signing and verification do not encrypt file content.
- MJKSMAP streaming verification requires trusted signer material from an account, contact or address; the streaming API does not accept self-reported envelope keys as its trust source.
- Progress events are advisory UI metadata, not proof that a file operation completed successfully. Always use the returned command result and handle errors.
- This package does not independently retain signing keys or plaintext documents. The native Rust client is responsible for key and storage handling.
- No independent third-party security audit or certification is claimed.

## Client-side preflight limits

The facade mirrors the current Rust plugin 1.6.0 input bounds for fast rejection:

| Input | Limit |
| --- | --- |
| Streaming operation ID | 1–128 restricted ASCII characters |
| Native path | 4,096 UTF-16 code units |
| Streaming chunk size | 64 KiB–64 MiB |
| Batch entries | 1–10,000 |
| Manifest/native path | 4,096 UTF-16 code units per value |
| MIME metadata | 1,024 UTF-16 code units |
| Aggregate batch path/MIME metadata | 8 MiB |
| Expected signers | 1,000 entries |
| Inline detached envelope metadata | 16 MiB before base64 decode |

The native plugin additionally limits active or queued streaming operations to four and MJKSMAP verification input to 64 MiB. The Rust client enforces optional maxBytes and maxBytesPerFile limits against canonical input bytes. These controls reduce accidental resource exhaustion but do not eliminate all denial-of-service risks.

## Testing scope

This repository tests the TypeScript facade's command mapping and client-side input preflight. Adapter-level enforcement tests belong in tauri-plugin-majik-signature-client. Core cryptographic vectors, malformed envelope parsing and format-specific adversarial tests belong in the Rust client and majik-signature repositories; this facade intentionally does not duplicate those suites.
