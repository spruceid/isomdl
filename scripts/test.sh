#!/bin/bash

set -e

Green="\e[0;32m"
Yellow="\e[0;33m"
NC="\e[0m" # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_DIR="$(pwd)"

echo -e "${Green}Testing scripts ...${NC}"
find "$SCRIPT_DIR/tests" -type f -name "*.sh" | while read -r file; do
  filename=$(basename "$file")
  basename="${filename%.*}"
  if grep -q '#[spruceid(ignore)]' "$file"; then
      echo -e "example $basename ... ${Yellow}ignored${NC}"
      continue
  fi
  parent_dir=$(dirname "$file")

  # Set the current directory to the parent directory of the file
  cd "$parent_dir" || exit

  echo -e "test $basename ..."
  "$file"
  echo -e "${Green}ok${NC}"

  # Return to the original directory to continue the loop
  cd - > /dev/null
done

cd "$CURRENT_DIR"