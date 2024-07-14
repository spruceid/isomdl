#!/bin/bash

set -e

Green="\e[0;32m"
Yellow="\e[0;33m"
NC="\e[0m" # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_DIR="$(pwd)"

echo -e "${Green}Running examples ...${NC}"
ignore_marker='#[spruceid(ignore)]'
find "$SCRIPT_DIR" -type f -name "*.rs" | while read -r file; do
  filename=$(basename "$file")
  basename="${filename%.*}"

  if grep -Fq "$ignore_marker" "$file"; then
    echo -e "example $basename ... ${Yellow}ignored${NC}"
  else
    parent_dir=$(dirname "$file")
    # Set the current directory to the parent directory of the file
    cd "$parent_dir" || exit
    echo -e "example $basename ..."
    cargo run --example "$basename" $1 -- $args
    echo -e "${Green}ok${NC}"
  fi

  # Return to the original directory to continue the loop
  cd - > /dev/null
done

cd "$CURRENT_DIR"