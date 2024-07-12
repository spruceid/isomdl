#!/bin/bash

set -e

# Function to process each include block
process_include_blocks() {
    local start_path=$1
    local start_marker
    local include_file
    local include_content
    local inside_include_block=0
    local inside_code_block=0

    cd "$start_path" || exit

    find . -type f -name "*.rs" | while read -r file; do
      file=$(realpath "$file")
      if ! grep -q '<!-- INCLUDE-RUST' "$file"; then
          continue
      fi
      parent_dir=$(dirname "$file")

      # Set the current directory to the parent directory of the file
      cd "$parent_dir" || exit

      temp_file=$(mktemp)
      while IFS= read -r line || [ -n "$line" ]; do
          if [[ $inside_include_block -eq 0 && "$line" == *"<!-- INCLUDE-RUST: "* ]]; then
              start_marker="$line"
              include_file=$(echo "$line" | sed -n 's/.*<!-- INCLUDE-RUST: \(.*\) -->.*/\1/p')
              echo "Processing '$file' include block for: '$include_file'"
              include_content=$(<"$include_file")
              echo "$start_marker" >> "$temp_file"
              inside_include_block=1
          elif [[ $inside_include_block -eq 1 && $inside_code_block -eq 1 && ("$line" == '//! ```' || "$line" == *'// ```') ]]; then
              echo "$line" >> "$temp_file"
              inside_include_block=0
              inside_code_block=0
          elif [[ $inside_include_block -eq 1 && ("$line" == '//! ```'* || "$line" == *'// ```'*) ]]; then
              echo "$line" >> "$temp_file"
              case "$line" in
                '//! ```'*)
                  prefix='//! '
                  ;;
                *'/// ```'*)
                  prefix='/// '
                  ;;
              esac
              if [[ -n "$prefix" ]]; then
                escaped_prefix=$(echo "$prefix" | sed 's/[&/\]/\\&/g')
                include_content=$(echo "$include_content" | sed "s/^/$escaped_prefix/")
              fi
              echo "$include_content" >> "$temp_file"
              inside_code_block=1
          elif [[ $inside_include_block -eq 0 || $inside_code_block -eq 0 ]]; then
              echo "$line" >> "$temp_file"
          fi
      done < "$file"
      # strip trailing spaces from lines starting with '//! '
      temp_file2=$(mktemp)
      sed -E 's/^(\/\/!?)[[:space:]]+$/\1/' "$temp_file" > "$temp_file2"
      mv "$temp_file2" "$temp_file"
      if ! cmp -s "$file" "$temp_file"; then
          mv "$temp_file" "$file"
      else
          rm "$temp_file"
      fi

      # Return to the original directory to continue the loop
      cd - > /dev/null
    done
}

START_PATH=$1
process_include_blocks "$START_PATH"

