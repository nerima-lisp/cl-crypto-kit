# cl-crypto-kit

Pure Common Lisp cryptographic primitives for SBCL. The verified target is
Linux x86_64. Public octet data uses `(simple-array (unsigned-byte 8) (*))`.

## Getting started

From the repository root, load the system with ASDF, then use the `crypto-kit`
package:

```lisp
(require :asdf)
(asdf:load-asd #p"cl-crypto-kit.asd")
(asdf:load-system "cl-crypto-kit")
(crypto-kit:digest-hex :sha256 (make-array 0 :element-type '(unsigned-byte 8)))
(crypto-kit:digest :sha256 (make-array 0 :element-type '(unsigned-byte 8)))
```

The Nix development shell provides SBCL and the test dependencies. Run the
full vector suite with:

```sh
nix run .#test
```

## API

- Digests: `digest`, `make-digest`, `digest-update`, `digest-copy`,
  `digest-final`, and `digest-length` for `:md5`, `:sha1`, `:sha256`, `:sha384`,
  and `:sha512`. The one-shot `digest` function returns octets. `:md5` and `:sha1`
  are available for compatibility; neither should be used where collision
  resistance is required ([RFC 6151](https://www.rfc-editor.org/rfc/rfc6151),
  [NIST hash function policy](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions)).
- Hexadecimal output: `digest-hex` takes `(algorithm octets)` and returns a
  lowercase hexadecimal string. `octets-to-hex` takes `(octets)` and returns a
  lowercase hexadecimal string. For streaming digests, pass `(digest-final state)`
  to `octets-to-hex`.
- Authentication and derivation: `hmac`, `hkdf-extract`, `hkdf-expand`, and
  `constant-time-equal`.
- AEAD: `aead-seal` and `aead-open` for `:aes-128-gcm`, `:aes-192-gcm`,
  `:aes-256-gcm`, and
  `:chacha20-poly1305`. Authentication failure signals
  `aead-authentication-failure`.
  Callers must not reuse a nonce with the same key.
- QUIC primitives: `aes-encrypt-block`, `chacha20-block`, and
  `chacha20-keystream`.
- Key exchange: `x25519`, `x25519-base`, `p256-generate-keypair`, and
  `p256-ecdh`.
- Signature verification: `verify-signature` for ECDSA P-256/P-384, RSA
  PKCS#1 v1.5/PSS, and Ed25519, with `make-ec-public-key`,
  `make-rsa-public-key`, and `make-ed25519-public-key`.
- Entropy: `random-octets`, backed by `/dev/urandom`.

## Constant-time scope

X25519, AES, ChaCha20, Poly1305, GHASH, and authentication-tag comparison use
fixed-width operations and avoid secret-dependent branches and table lookups.
This is a source-level property, not a claim about all compiler or hardware
behavior. Ed25519 is exposed for verification only. RSA and ECDSA signature
verification operate on public inputs and use bignum arithmetic, so they are
not constant-time.

## Verification

The ASDF test suite runs NIST, RFC, and Wycheproof vectors, including
tampering-rejection cases. `nix flake check --all-systems` runs that suite and
the OpenSSL hash comparison. The flake declares only the Linux x86_64 target.
Performance is hardware- and SBCL-dependent; this project does not publish a
stable benchmark number. Measure a target deployment with the provided
implementation and workload.

```sh
nix flake check --all-systems
```

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT. See [LICENSE](LICENSE).
