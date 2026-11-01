#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <tag> <asset-dir> <output-file>" >&2
  exit 64
fi

TAG="$1"
ASSET_DIR="$2"
OUTPUT_FILE="$3"

if [[ ! "$TAG" =~ ^v[0-9] ]]; then
  echo "tag must start with v, for example v1.0.0" >&2
  exit 65
fi

# asset prints the url and sha256 of the release asset scripts/build-release.sh built for one platform
asset() {
  local name="wt-${TAG}-$1.tar.gz" sha
  # errexit is off inside command substitutions, so a missing asset has to fail explicitly
  sha="$(shasum -a 256 "${ASSET_DIR}/${name}" | cut -d ' ' -f 1)" || return
  printf '      url "https://github.com/gugahoi/wt/releases/download/%s/%s"\n' "$TAG" "$name"
  printf '      sha256 "%s"' "$sha"
}

DARWIN_ARM64="$(asset darwin-arm64)"
DARWIN_AMD64="$(asset darwin-amd64)"
LINUX_ARM64="$(asset linux-arm64)"
LINUX_AMD64="$(asset linux-amd64)"

mkdir -p "$(dirname "$OUTPUT_FILE")"

cat >"$OUTPUT_FILE" <<FORMULA
class Wt < Formula
  desc "Git worktree manager with fzf pickers and tmux/Rex sessions"
  homepage "https://github.com/gugahoi/wt"
  license "MIT"

  on_macos do
    on_arm do
${DARWIN_ARM64}
    end
    on_intel do
${DARWIN_AMD64}
    end
  end

  on_linux do
    on_arm do
${LINUX_ARM64}
    end
    on_intel do
${LINUX_AMD64}
    end
  end

  def install
    bin.install "wt"
  end

  test do
    assert_match "Git Worktree Manager", shell_output("#{bin}/wt --help")
  end
end
FORMULA
