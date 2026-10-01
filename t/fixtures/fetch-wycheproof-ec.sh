#!/usr/bin/env bash
set -euo pipefail

readonly wycheproof_commit="3fa63dd0344abb611f1fb1d77e119938603ea230"
readonly base_url="https://raw.githubusercontent.com/C2SP/wycheproof/${wycheproof_commit}/testvectors_v1"
if [[ ${1:-} != "--output-dir" || -z ${2:-} || ${3:-} != "" ]]; then
    printf 'usage: %s --output-dir DIRECTORY\n' "$0" >&2
    exit 2
fi
readonly output_dir=$2
readonly temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/wycheproof-ec.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT

vectors=(
    "ecdh_secp256r1_test.json|cdb8bd5d1206fddb6618c69ffa18f303b4752caba321d348d4aacae3f20cbec4|612"
    "ecdh_secp256r1_ecpoint_test.json|648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886|355"
    "ecdsa_secp256r1_sha256_test.json|182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332|484"
    "ecdsa_secp384r1_sha384_test.json|8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc|504"
)
mkdir -p "$output_dir"
for vector in "${vectors[@]}"; do
    IFS='|' read -r filename expected_sha256 expected_count <<< "$vector"
    temporary_file="$temporary_dir/$filename"
    curl --fail --location --silent --show-error --retry 2 "$base_url/$filename" -o "$temporary_file"
    actual_sha256=$(shasum -a 256 "$temporary_file" | awk '{print $1}')
    [[ $actual_sha256 == "$expected_sha256" ]] || { printf '%s: sha256 mismatch\n' "$filename" >&2; exit 1; }
    actual_count=$(jq '[.testGroups[].tests[]] | length' "$temporary_file")
    [[ $actual_count == "$expected_count" ]] || { printf '%s: expected %s tests, got %s\n' "$filename" "$expected_count" "$actual_count" >&2; exit 1; }
    cp "$temporary_file" "$output_dir/$filename"
    printf '%s: %s vectors, sha256 %s\n' "$filename" "$actual_count" "$actual_sha256"
done
