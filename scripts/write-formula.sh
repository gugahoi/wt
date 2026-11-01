#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <tag> <sha256> <output-file>" >&2
    exit 64
fi

TAG="$1"
SHA256="$2"
OUTPUT_FILE="$3"

if [[ ! "$TAG" =~ ^v[0-9] ]]; then
    echo "tag must start with v, for example v1.0.0" >&2
    exit 65
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

cat >"$OUTPUT_FILE" <<FORMULA
class Wt < Formula
  desc "Git worktree manager with fzf pickers and tmux/Rex sessions"
  homepage "https://github.com/gugahoi/wt"
  url "https://github.com/gugahoi/wt/archive/refs/tags/${TAG}.tar.gz"
  sha256 "${SHA256}"
  license "MIT"

  depends_on "fzf"
  depends_on "gh"
  depends_on "jq"

  def install
    bin.install "bin/wt"
  end

  test do
    assert_match "Git Worktree Manager", shell_output("#{bin}/wt --help")
  end
end
FORMULA
