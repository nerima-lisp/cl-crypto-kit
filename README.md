# cl-crypto-kit

Pure Common Lisp cryptographic primitives for SBCL. The flake declares checks
for macOS aarch64 and Linux x86_64. Public octet data uses
`(simple-array (unsigned-byte 8) (*))`.

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
- Signature creation: `(make-ec-private-key :p256 scalar-octets)` accepts a
  32-byte scalar from one through the P-256 order minus one;
  `(make-ed25519-private-key seed)` accepts a 32-byte seed.
  Both constructors copy their input; their key objects redact private bytes
  when printed.
  `(private-key-public-key key)` derives the corresponding public key.
  `(sign-message scheme key message)` supports `:ecdsa-p256-sha256` and
  `:ed25519`, returning DER signature octets for ECDSA and a 64-byte signature
  for Ed25519. Invalid keys, unsupported schemes, and non-octet messages signal
  `crypto-error`.
- Signature verification: `(verify-signature scheme public-key message signature)`
  supports `:ecdsa-p256-sha256`, `:ecdsa-p384-sha384`,
  `:rsa-pkcs1-sha256`, `:rsa-pkcs1-sha384`, `:rsa-pkcs1-sha512`,
  `:rsa-pss-rsae-sha256`, `:rsa-pss-rsae-sha384`, `:rsa-pss-rsae-sha512`,
  and `:ed25519`. P-384 and RSA are verification-only in this API. Create
  wrappers with `(make-ec-public-key curve point)` using `:p256` or `:p384`
  and uncompressed SEC1 point octets (65 or 97 bytes),
  `(make-rsa-public-key modulus exponent)` using integer parameters, or
  `(make-ed25519-public-key octets)` using a 32-byte encoded key. ECDSA
  signatures use DER, RSA signatures use modulus-sized octets, and Ed25519
  signatures use 64 octets. The wrapper constructors do not validate their
  arguments. Verification returns `t` for valid signatures and `nil` for
  invalid signatures or EC/Ed25519 octet encodings; invalid RSA modulus or
  exponent values, unsupported schemes, and wrong key wrapper types signal
  `crypto-error`.
- Entropy: `random-octets`, backed by `/dev/urandom`.

## Constant-time scope

X25519, AES, ChaCha20, Poly1305, GHASH, and authentication-tag comparison use
fixed-width operations and avoid secret-dependent branches and table lookups.
`constant-time-equal` checks every position up to the longer input length; input
lengths are public. P-256 ECDSA signing uses fixed-length loops for accepted
nonce and private-scalar arithmetic ([P-256 implementation](src/p256.lisp),
[ECDSA signer](src/ecdsa.lisp)). Ed25519 scalar operations use fixed-length
loops and masks to select results ([Ed25519 implementation](src/ed25519.lisp)).
RFC 6979 retries if its HMAC candidate is
zero or at least the P-256 group order, which occurs about once in 2^32 draws.
The retry count can vary, but under HMAC's PRF model it is independent of the
accepted nonce. If a candidate has r=0 or s=0 (about 2^-256 per draw), signing
retries after fixed-flow arithmetic; this can add latency but reveals only that
the discarded candidate was invalid, not the final k or d. DER encoding branches
only on accepted public r and s. These are source-level observations, not
guarantees about compiled code or SBCL timing. RSA and ECDSA verification use
public inputs and bignum arithmetic.

## Verification

The ASDF test suite runs NIST, RFC, and Wycheproof vectors, including
tampering-rejection cases. On Ubuntu x86_64, CI runs that suite and compares
hashes against OpenSSL. CI does not run the flake's aarch64-darwin check.

```sh
nix flake check
```

## Digest benchmark

Run the reproducible 16 MiB comparison against the current Aitools digest source
with:

```sh
sbcl --noinform --script scripts/benchmark-digest.lisp /path/to/aitools/digest.lisp
```

The benchmark uses a deterministic xorshift32 input seeded with `0x6d2b79f5`,
two warmups per implementation, two reference/reference noise pairs, and seven
alternating implementation pairs. It forces a full GC before every sample and
reports medians, paired wins, and the median absolute reference/reference
difference. On SBCL, one-shot MD5 uses SBCL's bundled `sb-md5`; other
implementations retain the Common Lisp MD5 path.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT. See [LICENSE](LICENSE).
