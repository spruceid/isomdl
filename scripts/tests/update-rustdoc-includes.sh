#!/bin/bash

set -e

Green="\e[0;32m"
Red="\033[0;31m"
NC="\e[0m" # No Color

tmp="/tmp/test-rustdoc-includes"
rm -rf "$tmp"
marker="test-42-42-42"
mkdir "$tmp"
echo "$marker" > "$tmp/test.rs"
echo '//! <!-- INCLUDE-RUST: '"$tmp"'/test.rs -->' > "$tmp/test2.rs"
echo '//! ```' >> "$tmp/test2.rs"
echo '//! ```' >> "$tmp/test2.rs"
echo '//! <!-- INCLUDE-RUST: '"$tmp"'/test.rs -->' >> "$tmp/test2.rs"
echo '//! ```ignore' >> "$tmp/test2.rs"
echo '//! ```' >> "$tmp/test2.rs"
echo '  // <!-- INCLUDE-RUST: '"$tmp"'/test.rs -->' >> "$tmp/test2.rs"
echo '  // ```' >> "$tmp/test2.rs"
echo '  // ```' >> "$tmp/test2.rs"
echo '  // <!-- INCLUDE-RUST: '"$tmp"'/test.rs -->' >> "$tmp/test2.rs"
echo '  // ```ignore' >> "$tmp/test2.rs"
echo '  // ```' >> "$tmp/test2.rs"
../update-rustdoc-includes.sh "$tmp"
count=$(awk -v text="$marker" 'BEGIN {count=0} {count += gsub(text, "")} END {print count}' "$tmp/test2.rs")
if [ "$count" -ne 4 ]; then
  echo -e "${Red}failed${NC}"
  exit 1
fi