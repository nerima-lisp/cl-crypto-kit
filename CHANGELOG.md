# Changelog

## [0.2.0] - 2026-10-19

- Added deterministic ECDSA P-256/SHA-256 signing, Ed25519 signing, and APIs to derive public keys from private keys.

## [0.1.1] - 2026-10-19

- Optimized one-shot MD5, SHA-1, and SHA-256 digest processing while preserving streaming APIs.
- Added padding-boundary, multi-block, 16 MiB, and split-update property coverage.
- Added a reproducible 16 MiB digest comparison benchmark.
- Added the macOS aarch64 Nix target.

## [0.1.0] - 2026-10-17

- Added `digest-hex` for lowercase hexadecimal digests and `octets-to-hex` for converting octets to lowercase hexadecimal.
- Added MD5, SHA-1, SHA-256, SHA-384, and SHA-512 digest operations.
- Added HMAC, HKDF, AES-GCM, and ChaCha20-Poly1305 primitives.
- Added AES, ChaCha20, Poly1305, X25519, and CSPRNG primitives.
- Added ECDH key exchange and RSA, Ed25519, and ECDSA signature verification.
- Added NIST, RFC, and Wycheproof vector coverage to the ASDF test system.
