#!/usr/bin/env bash
# toplevel.sh <layout_name_no_ext> <layout_dir>
#
# Reconstruction (not the original author's file — the original lived at
# /home/hoang/Documents/Achilles/toplevel.sh and is not available here).
#
# Given a layout name, walks the chain of "who includes this layout"
# (@layout/<name> references in other layout XML files) up to the point
# where no other layout includes it -- i.e. the top-level / screen-level
# layout. Prints one layout name (no extension) per line.
#
# Verify this against known-good examples before trusting results.

GREP="${GREP:-ggrep}"
if ! "$GREP" --version >/dev/null 2>&1; then GREP=grep; fi

set -euo pipefail

target="$1"
laydir="$2"
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

including=$(find "$laydir" -type f -name "*.xml" -exec "$GREP" -lE "@layout/${target}\b" {} \; \
    | xargs -L 1 -r basename | sed 's/\.xml$//' | sort -u)

if [ -z "$including" ]; then
    # Nobody includes this layout -> it IS top-level
    echo "$target"
else
    while IFS= read -r parent; do
        [ "$parent" = "$target" ] && continue   # guard against self-reference loops
        "$self" "$parent" "$laydir"
    done <<< "$including"
fi
