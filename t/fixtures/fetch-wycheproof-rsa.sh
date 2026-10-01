#!/usr/bin/env bash
set -euo pipefail

# Fetch public-key RSA signature vectors without checking the generated JSON into
# the repository. The commit and hashes make the fixture set reproducible.
readonly wycheproof_commit="3fa63dd0344abb611f1fb1d77e119938603ea230"
readonly base_url="https://raw.githubusercontent.com/C2SP/wycheproof/${wycheproof_commit}/testvectors_v1"

if [[ ${1:-} != "--output-dir" || -z ${2:-} || ${3:-} != "" ]]; then
    printf 'usage: %s --output-dir DIRECTORY\n' "$0" >&2
    exit 2
fi

readonly output_dir=$2
readonly temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/wycheproof-rsa.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT

vectors=(
    "rsa_signature_2048_sha224_test.json|81b9da6e58f8a55ccc02b96f64a1d84d93100b9767dddbc906cee52d4c7daeac|258"
    "rsa_signature_2048_sha256_test.json|94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393|259"
    "rsa_signature_2048_sha384_test.json|c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d|258"
    "rsa_signature_2048_sha512_test.json|16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef|259"
    "rsa_pss_2048_sha1_mgf1_20_test.json|96d13ecdc356a24aec01dcbef7c5a15458b78373283113c294a60f8ddf717b29|88"
    "rsa_pss_2048_sha256_mgf1_0_test.json|b22a8d9a2e7e47f681d0ff1d1a55455daaf325d989c64ad005f848bd50b9b4c0|103"
    "rsa_pss_2048_sha256_mgf1_32_test.json|7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c|108"
    "rsa_pss_2048_sha512_256_mgf1_32_test.json|5682afaef4c4013dbd5c89d73b234f5a10e2eaaa6c3b54927d711cd893214e58|115"
    "rsa_pss_3072_sha256_mgf1_32_test.json|cca48433e6d1accb57f65b3396c4f4dd93c776467101c3f0948e74c283fd4749|108"
    "rsa_pss_4096_sha256_mgf1_32_test.json|e627cbf5139a01e0a446c4fe15911f6268224fdd3ef4a1eb714b3942b5686410|108"
)

mkdir -p "$output_dir"
for vector in "${vectors[@]}"; do
    IFS='|' read -r filename expected_sha256 expected_count <<< "$vector"
    temporary_file="$temporary_dir/$filename"
    curl --fail --location --silent --show-error --retry 2 \
        "$base_url/$filename" --output "$temporary_file"
    actual_sha256=$(shasum -a 256 "$temporary_file" | awk '{print $1}')
    [[ $actual_sha256 == "$expected_sha256" ]] || {
        printf '%s: sha256 mismatch\n' "$filename" >&2
        exit 1
    }
    actual_count=$(jq '[.testGroups[].tests[]] | length' "$temporary_file")
    [[ $actual_count == "$expected_count" ]] || {
        printf '%s: expected %s tests, got %s\n' "$filename" "$expected_count" "$actual_count" >&2
        exit 1
    }
    if jq -e '[.. | objects | keys[]] | any(. == "d" or . == "p" or . == "q" or . == "dmp1" or . == "dmq1" or . == "iqmp")' "$temporary_file" >/dev/null; then
        printf '%s: private-key field found\n' "$filename" >&2
        exit 1
    fi
    cp "$temporary_file" "$output_dir/$filename"
    printf '%s: %s vectors, sha256 %s\n' "$filename" "$actual_count" "$actual_sha256"
done
