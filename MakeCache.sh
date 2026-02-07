#!/bin/bash

OUTPUT="offlinexmb.cache"
ROOT="$(cd "$(dirname "$0")" && pwd)"

# Build clean timestamp
D=$(date +"%Y-%m-%d")
T=$(date +"%H-%M-%S")

# Write manifest header
{
    echo "CACHE MANIFEST"
    echo "# Saaqi HOST 5.05 Created on Date: $D - Time: $T"
    echo
    echo "CACHE:"
} > "$OUTPUT"

# Enumerate files
find "$ROOT" -type f | while read -r FILE; do

    # Make path relative
    REL="${FILE#$ROOT/}"

    # Skip output file itself
    if [[ "$REL" == "$OUTPUT" ]]; then
        continue
    fi

    # Exclusions
    if echo "$REL" | grep -Ei \
        '\.bat$|\.exe$|\.mp4$|\.cache$|\.txt$|\.sh$|\.md$|\.gitignore$|\.vscode|\.git|LICENSE|ESP-VERSION|media' \
        > /dev/null; then
        continue
    fi

    echo "$REL" >> "$OUTPUT"
done

# Network section
{
    echo
    echo "NETWORK:"
    echo "*"
} >> "$OUTPUT"

echo
echo "$OUTPUT created successfully."
sleep 2
