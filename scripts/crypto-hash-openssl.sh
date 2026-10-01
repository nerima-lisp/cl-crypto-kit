#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export CL_SOURCE_REGISTRY="$root//"
for command in openssl sbcl; do command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }; done
file=$(mktemp)
trap 'rm -f "$file"' EXIT
for alg in sha1 sha256 sha384 sha512; do
  for n in 0 1 2 3 63 64 65 127 128 129 1023 1024 1025 16383 16384 16385 32768; do
    if [[ "$n" == 0 ]]; then : >"$file"; else openssl rand "$n" >"$file"; fi
    expected=$(openssl dgst -"$alg" "$file" | awk '{print $NF}')
    actual=$(sbcl --noinform --non-interactive --load "$root/scripts/crypto-hash-openssl.lisp" -- "$alg" "$file" | tail -1 | tr '[:upper:]' '[:lower:]')
    [[ "$actual" == "$expected" ]] || { echo "digest mismatch $alg/$n" >&2; exit 1; }
    key=$(openssl rand -hex 131)
    expected=$(openssl dgst -"$alg" -mac HMAC -macopt "hexkey:$key" "$file" | awk '{print $NF}')
    actual=$(sbcl --noinform --non-interactive --load "$root/scripts/crypto-hash-openssl.lisp" -- "$alg" "$file" "$key" | tail -1 | tr '[:upper:]' '[:lower:]')
    [[ "$actual" == "$expected" ]] || { echo "HMAC mismatch $alg/$n" >&2; exit 1; }
  done
done
echo "OpenSSL random digest/HMAC cross-check passed: 136 comparisons (4 algorithms x 17 lengths x digest/HMAC)"
