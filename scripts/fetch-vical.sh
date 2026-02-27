#!/usr/bin/env bash
set -euo pipefail

VICAL_DIR="$(cd "$(dirname "$0")/../test/vical" && pwd)"
BASE_URL="https://vical.dts.aamva.org"

# Scrape the current VICAL filename from the /currentVical page.
name=$(curl -sf "$BASE_URL/currentVical" \
  | grep -oE 'vc-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]+' \
  | head -1)

if [[ -z "$name" ]]; then
  echo "error: failed to parse current VICAL name" >&2
  exit 1
fi

dest="$VICAL_DIR/aamva-vical-${name#vc-}.cbor"

if [[ -f "$dest" ]]; then
  echo "already up to date: $(basename "$dest")"
  exit 0
fi

echo "downloading $name ..."
curl -sf -o "$dest" "$BASE_URL/vical/vc/$name"
echo "saved $(basename "$dest") ($(wc -c < "$dest" | tr -d ' ') bytes)"
