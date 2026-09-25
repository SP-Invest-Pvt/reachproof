#!/usr/bin/env bash
# Clone the public log4shell-vulnerable-app at a pinned commit, as an external test case.
set -euo pipefail
cd "$(dirname "$0")/.."
DEST=examples/real-world/log4shell-vulnerable-app/src
if [ ! -d "$DEST/.git" ]; then
  git clone -q https://github.com/christophetd/log4shell-vulnerable-app.git "$DEST"
  git -C "$DEST" checkout -q c962aabb31a6af0a77f0e9bbc7100e175c7c04e1
fi
echo "External test case ready in $DEST"
