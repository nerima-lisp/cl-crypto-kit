# cl-crypto-kit

Hash, HMAC, and HKDF primitives for Common Lisp. The public API accepts and
returns `(simple-array (unsigned-byte 8) (*))` octet vectors.

Supported digests are `:sha1`, `:sha256`, `:sha384`, and `:sha512`. Each has a
one-shot `digest` operation and the incremental `make-digest`,
`digest-update`, `digest-copy`, and `digest-final` operations.

```lisp
(crypto-kit:digest :sha256 #(97 98 99))
(crypto-kit:hmac :sha256 key message)
(crypto-kit:hkdf-expand :sha256 prk info 32)
```

## Verification

```sh
nix flake check
```

## License

MIT. See [LICENSE](LICENSE).
