#!/usr/bin/env bash
# Build wt for every platform the Homebrew formula installs on, as <output-dir>/wt-<tag>-<os>-<arch>.tar.gz.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <tag> <output-dir>" >&2
  exit 64
fi

TAG="$1"
OUTPUT_DIR="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

mkdir -p "$OUTPUT_DIR"
cp "${ROOT}/LICENSE" "${BUILD_DIR}/LICENSE"

for platform in darwin-arm64 darwin-amd64 linux-arm64 linux-amd64; do
  echo "Building ${platform}"
  CGO_ENABLED=0 GOOS="${platform%-*}" GOARCH="${platform#*-}" \
    go build -C "$ROOT" -trimpath -ldflags="-s -w" -o "${BUILD_DIR}/wt" .
  tar -czf "${OUTPUT_DIR}/wt-${TAG}-${platform}.tar.gz" -C "$BUILD_DIR" wt LICENSE
done
