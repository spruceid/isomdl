#!/bin/bash

set -e

Red="\033[0;31m"
NC="\e[0m" # No Color

tmp="/tmp/test-md-includes"
rm -rf "$tmp"
marker="test-42-42-42"
mkdir "$tmp"
echo "$marker" > "$tmp/test.rs"
echo '<!-- INCLUDE-RUST: '"$tmp"'/test.rs -->' > "$tmp/test.md"
echo '```rust' >> "$tmp/test.md"
echo '```' >> "$tmp/test.md"
../update-md-includes.sh "$tmp/test.md"
count=$(awk -v text="$marker" 'BEGIN {count=0} {count += gsub(text, "")} END {print count}' "$tmp/test.md")
if [ "$count" -ne 1 ]; then
  echo -e "${Red}failed${NC}"
  exit 1
fi