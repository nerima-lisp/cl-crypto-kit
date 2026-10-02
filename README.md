# cl-crypto-kit

Pure Common Lisp cryptographic primitives for SBCL on macOS and Linux. Public
octet data uses `(simple-array (unsigned-byte 8) (*))`.

Supported digests are `:sha1`, `:sha256`, `:sha384`, and `:sha512`. Each has a
one-shot `digest` operation and the incremental `make-digest`,
`digest-update`, `digest-copy`, and `digest-final` operations.

## API

- Digests: `digest`, `make-digest`, `digest-update`, `digest-copy`,
  `digest-final`, and `digest-length` for `:sha1`, `:sha256`, `:sha384`, and
  `:sha512`.
- Authentication and derivation: `hmac`, `hkdf-extract`, `hkdf-expand`, and
  `constant-time-equal`.
- AEAD: `aead-seal` and `aead-open` for `:aes-128-gcm`, `:aes-256-gcm`, and
  `:chacha20-poly1305`. Authentication failure signals
  `aead-authentication-failure`.
- QUIC primitives: `aes-encrypt-block` and `chacha20-keystream`.
- Key exchange: `x25519`, `x25519-base`, `p256-generate-keypair`, and
  `p256-ecdh`.
- Signature verification: `verify-signature` for ECDSA P-256/P-384, RSA
  PKCS#1 v1.5/PSS, and Ed25519, with the corresponding public-key constructors.
- Entropy: `random-octets`, backed by `/dev/urandom`.

## Constant-time scope

X25519, AES, ChaCha20, Poly1305, GHASH, and authentication-tag comparison use
fixed-width operations and avoid secret-dependent branches and table lookups.
This is a source-level property, not a claim about all compiler or hardware
behavior. Ed25519 is exposed for verification only. RSA and ECDSA signature
verification operate on public inputs and use bignum arithmetic, so they are
not constant-time.

## Verification

The check runs NIST, RFC, and Wycheproof vectors, including tampering-rejection
cases. Performance is hardware- and SBCL-dependent; this project does not
publish a stable benchmark number. Measure a target deployment with the
provided implementation and workload.

```sh
nix flake check --all-systems
```

## License

MIT. See [LICENSE](LICENSE).
