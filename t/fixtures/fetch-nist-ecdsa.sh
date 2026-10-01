#!/usr/bin/env bash
set -euo pipefail

readonly source_url="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3ecdsatestvectors.zip"
readonly source_sha256="e0d9bee3f760ca3fabb82bd43dd04c13ee64ca9e0b719c6ea64fd52c9f0dd929"
if [[ ${1:-} != "--output-dir" || -z ${2:-} || ${3:-} != "" ]]; then
    printf 'usage: %s --output-dir DIRECTORY\n' "$0" >&2
    exit 2
fi
readonly output_dir=$2
readonly temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/nist-ecdsa.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT
mkdir -p "$output_dir"
curl --fail --location --silent --show-error --retry 2 "$source_url" -o "$temporary_dir/ec.zip"
actual_sha256=$(shasum -a 256 "$temporary_dir/ec.zip" | awk '{print $1}')
[[ $actual_sha256 == "$source_sha256" ]] || { printf 'NIST ECDSA ZIP: sha256 mismatch\n' >&2; exit 1; }
unzip -p "$temporary_dir/ec.zip" SigVer.rsp > "$output_dir/SigVer.rsp"
printf 'SigVer.rsp: source sha256 %s\n' "$actual_sha256"
