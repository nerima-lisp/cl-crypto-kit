# Wycheproof RSA signature fixtures

These public verification fixtures are copied from C2SP Wycheproof `testvectors_v1`
at commit `3fa63dd0344abb611f1fb1d77e119938603ea230`.

They contain public keys, messages, signatures, and expected verification results.
They do not contain private keys. The files are distributed under the upstream
Apache-2.0 license.

| Fixture | Tests | Results |
| --- | ---: | --- |
| `rsa_signature_2048_sha256_test.json` | 259 | valid=9, acceptable=1, invalid=249 |
| `rsa_signature_3072_sha256_test.json` | 259 | valid=8, acceptable=1, invalid=250 |
| `rsa_pss_2048_sha256_mgf1_0_test.json` | 103 | valid=61, invalid=42 |
| `rsa_pss_2048_sha256_mgf1_32_test.json` | 108 | valid=63, invalid=45 |
| `rsa_pss_3072_sha256_mgf1_32_test.json` | 108 | valid=63, invalid=45 |
| `rsa_pss_4096_sha256_mgf1_32_test.json` | 108 | valid=63, invalid=45 |

The current upstream catalogue also provides other RSA hashes and key sizes;
this fixture set is intentionally limited to SHA-256 and the key sizes needed
for the RSA signature work. Run
`t/fixtures/fetch-wycheproof-rsa.sh --output-dir t/fixtures/wycheproof-rsa` to
retrieve the exact pinned files again and verify their SHA-256 digests, JSON
shape, counts, and absence of private keys.
