# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0] — 2026-06-03

### Added
- Parallel brute-force recovery using `multiprocessing.Pool` across all CPU cores
- Support for up to 3 unknown/corrupted characters via `?` placeholder syntax
- Deterministic candidate ordering: `Pool.map()` preserves submission order regardless of core completion order
- Automatic `fork`/`spawn` context selection per platform (Linux/Android use `fork`; Windows/macOS use `spawn`)
- Single-worker fast path for ≤256 candidates (avoids IPC overhead for 1-unknown searches)
- Full address derivation for all three formats: P2PKH (Legacy `1...`), P2SH-P2WPKH (SegWit wrapped `3...`), P2WPKH (Native SegWit `bc1q...`)
- Compression flag detection and reporting
- Network detection from version byte (`0x80` mainnet / `0xEF` testnet)
- ANSI-colored terminal output with structured layout
- Progress reporting per worker chunk during brute-force
- Throughput metric (candidates/second) at end of recovery run
- `SECURITY.md` — dedicated private key handling guidance
- `docs/QUICKSTART.md` — 2-minute fast-track setup guide
- `docs/HOW_IT_WORKS.md` — algorithm deep-dive for developers
- `docs/GLOSSARY.md` — 80+ blockchain and Bitcoin technical terms
- `docs/INDEX.md` — complete package index and navigation guide

### Changed
- Repository structure: `QUICKSTART.md` and `INDEX.md` moved to `docs/` for a cleaner root

---

## [1.0.0] — Initial release

### Added
- WIF validation: length check, Base58 character set check, Base58Check checksum verification
- Key extraction: version byte parsing, raw 32-byte private key, compression flag
- Public key derivation via `ecdsa` library (secp256k1 scalar multiplication)
- P2PKH (Legacy) address derivation
- Diagnostic output on validation failure (wrong length, invalid characters, checksum mismatch with hex diff)
- Single-process, single-threaded design
- Android (Termux) as primary target platform

---

[Unreleased]: https://github.com/ussdking-sys/wif-forensic/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/ussdking-sys/wif-forensic/releases/tag/v2.0.0
[1.0.0]: https://github.com/ussdking-sys/wif-forensic/releases/tag/v1.0.0
