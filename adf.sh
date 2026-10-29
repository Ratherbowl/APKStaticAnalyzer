#!/usr/bin/env bash

# Default to GNU grep from Homebrew on Mac (ggrep).
# Fall back to plain grep on Linux. Override with: GREP=grep ./adf.sh
GREP="${GREP:-ggrep}"
if ! command -v "$GREP" >/dev/null 2>&1; then
    GREP=grep
fi

# Use gtimeout on Mac (Homebrew coreutils), timeout on Linux.
TIMEOUT_CMD="${TIMEOUT_CMD:-gtimeout}"
if ! command -v "$TIMEOUT_CMD" >/dev/null 2>&1; then
    TIMEOUT_CMD=timeout
fi
apkpath=$1
apkfile=$(basename -- "$apkpath")
apkdir="${apkfile%.*}"
outdir=output
VERBS=("upload" "validate" "verify" "fetch" "submit" "add" "provide")
NOUNS=("document" "certificate" "covid" "health" "status" "record" "test")

# Build regex patterns for all combinations of verbs and nouns
patterns=""
for v in "${VERBS[@]}"; do
    for n in "${NOUNS[@]}"; do
        patterns+=".*${v}.*${n}.*|"
    done
done

# Remove the trailing pipe from the final string
patterns="${patterns%|}"
model=$outdir/$apkdir/mapping_model.dot

TIMELIMIT=45

# EDIT THIS if your local paths differ:
SEMANTICS="/home/darcole/AAR/AccountDeletionAnalyzer_Ubuntu/pyStatParser/pyStatParser/semantics.py"
TOPLEVEL_SH="$(cd "$(dirname "$0")" && pwd)/toplevel.sh"

ere_quote() {
    sed 's/[]\.|$(){}?+*^]/\\&/g' <<< "$*"
}

# Escapes a string for safe use as a Graphviz DOT node label/name.
# Matched AD strings come from real app text and can contain literal
# double quotes or backslashes
dot_escape() {
#    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' <<< "$*"
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's|[\\&/]|\\&|g' <<< "$*"
}

[ ! -d $outdir ] && mkdir -p $outdir

# Decompile apk file
[ ! -d "$outdir/$apkdir" ] && apktool d $apkpath -o $outdir/$apkdir

# Convert images to text only the first time
if [ ! -f "$model" ]; then
    find $outdir/$apkdir -type f -exec file {} \; | awk -F: '{if ($2 ~/image/) print $1}' | while IFS= read -r img; do
        tesseract "$img" "${img%.*}.txt"
    done
fi

# Find and validate AD strings
[ ! -z "$patterns" ] && while IFS='|' read -ra pats ; do
    for p in "${pats[@]}"; do
        valid=""
        while IFS= read -r line; do
            if "$TIMEOUT_CMD" $TIMELIMIT python3 "$SEMANTICS" "$line" "$p" 2>/dev/null | "$GREP" -q 'TP'; then
                valid+="$line"$'\n'
            fi
        done < <("$GREP" --color=never -Pio "(?<=>)$p(?=<)" $outdir/$apkdir/res/values/strings.xml)

        if [ ! -z "$valid" ]; then
            adstr+=$'\n'
            adstr+="$valid"
            adstr+=$'\n'
        fi
    done
done <<< "$patterns"
adstr=$(awk 'NF && !seen[$0]++' <<<"$adstr")  # Remove blank lines and duplicated lines

#### Build a mapping model ####
>$model
echo 'digraph G {' >> $model    # start dot graph

# { AD strings -> name attributes }
[ ! -z "$adstr" ] && while IFS= read -r ads ; do
    adsq=$(ere_quote "$ads")
    adsd=$(dot_escape "$ads")
    attr=$("$GREP" --color=never -Po "(?<=name=\").*(?=\">$adsq<)" $outdir/$apkdir/res/values/strings.xml)
    if [ ! -z "$attr" ]; then
        echo "$attr" | sed "s/^/\"adstr::$adsd\" -> \"nattr::/g" | sed "s/$/\"/g" >> $model
        nameattrs+=$'\n'
        nameattrs+="$attr"
        nameattrs+=$'\n'
    fi
done <<< "$adstr"
nameattrs=$(awk 'NF && !seen[$0]++' <<<"$nameattrs")

# { AD strings -> layouts }
[ ! -z "$adstr" ] && while IFS= read -r ads ; do
    adsq=$(ere_quote "$ads")
    adsd=$(dot_escape "$ads")
    lays=$(find $outdir/$apkdir/res/layout/ -type f -exec "$GREP" -l "$adsq" {} \; | xargs -L 1 -r basename)
    if [ ! -z "$lays" ]; then
        echo "$lays" | sed "s/^/\"adstr::$adsd\" -> \"lay::/g" | sed "s/$/\"/g" >> $model
        layouts+=$'\n'
        layouts+="$lays"
        layouts+=$'\n'
    fi
done <<< "$adstr"
layouts=$(awk 'NF && !seen[$0]++' <<<"$layouts")

# { AD strings -> images }
[ ! -z "$adstr" ] && while IFS= read -r ads ; do
    adsq=$(ere_quote "$ads")
    adsd=$(dot_escape "$ads")
    imgs=$(find $outdir/$apkdir/res/ -type f -name "*.txt" ! -name "*.txt.txt" -exec "$GREP" -l "$adsq" {} \; | xargs -L 1 -r basename)
    if [ ! -z "$imgs" ]; then
        echo "$imgs" | sed "s/^/\"adstr::$adsd\" -> \"img::/g" | sed "s/$/\"/g" >> $model
        images+=$'\n'
        images+="$imgs"
        images+=$'\n'
    fi
    imgs=$(find $outdir/$apkdir/assets/ -type f -name "*.txt" ! -name "*.txt.txt" -exec "$GREP" -l "$adsq" {} \; | xargs -L 1 -r basename)
    if [ ! -z "$imgs" ]; then
        echo "$imgs" | sed "s/^/\"adstr::$adsd\" -> \"img::/g" | sed "s/$/\"/g" >> $model
        images+=$'\n'
        images+="$imgs"
        images+=$'\n'
    fi
done <<< "$adstr"
images=$(awk 'NF && !seen[$0]++' <<<"$images")

# { AD strings -> html }
# Todo

# { name Attributes -> layouts }
[ ! -z "$nameattrs" ] && while IFS= read -r att ; do
    lays=$(find $outdir/$apkdir/res/layout/ -type f -name "*.xml" -exec "$GREP" -l "@string/$att" {} \; | xargs -L 1 -r basename)
    if [ ! -z "$lays" ]; then
        echo "$lays" | sed "s/^/\"nattr::$att\" -> \"lay::/g" | sed "s/$/\"/g" >> $model
        layouts+=$'\n'
        layouts+="$lays"
        layouts+=$'\n'
    fi
done <<< "$nameattrs"
layouts=$(awk 'NF && !seen[$0]++' <<<"$layouts")

# { name Attributes -> fragments }
# Uses the symbolic smali field reference (R$string;->NAME:I) instead of the
# numeric resource id from public.xml, since compiled code references
# resources by field name, not by the raw hex constant (that constant only
# appears literally in the R$string.smali definition file itself).
[ ! -z "$nameattrs" ] && while IFS= read -r att ; do
    frags=$(find $outdir/$apkdir/ -type f -name "*.smali" -exec "$GREP" --color=never -lE "R\\\$string;->${att}:I" {} \; \
        | while IFS= read -r f; do "$GREP" --color=never -qEi "\.super.*fragment;" "$f" && basename "$f"; done)
    if [ ! -z "$frags" ]; then
        echo "$frags" | sed "s/^/\"nattr::$att\" -> \"frag::/g" | sed "s/$/\"/g" >> $model
        fragments+=$'\n'
        fragments+="$frags"
        fragments+=$'\n'
    fi
done <<< "$nameattrs"
fragments=$(awk 'NF && !seen[$0]++' <<<"$fragments")

# { name Attributes -> activities }
[ ! -z "$nameattrs" ] && while IFS= read -r att ; do
    acts=$(find $outdir/$apkdir/ -type f -name "*.smali" ! -name "R*.smali" -exec "$GREP" --color=never -lE "R\\\$string;->${att}:I" {} \; \
        | while IFS= read -r f; do "$GREP" --color=never -qEi "\.super.*fragment;" "$f" || basename "$f"; done)
    if [ ! -z "$acts" ]; then
        echo "$acts" | sed "s/^/\"nattr::$att\" -> \"act::/g" | sed "s/$/\"/g" >> $model
    fi
done <<< "$nameattrs"

# { images -> layouts }
[ ! -z "$images" ] && while IFS= read -r img ; do
    noext=${img%%.*}
    lays=$(find $outdir/$apkdir/res/layout/ -type f -name "*.xml" -exec "$GREP" -lE "@drawable/$noext" {} \; | xargs -L 1 -r basename)
    if [ ! -z "$lays" ]; then
        echo "$lays" | sed "s/^/\"img::$img\" -> \"lay::/g" | sed "s/$/\"/g" >> $model
        layouts+=$'\n'
        layouts+="$lays"
        layouts+=$'\n'
    fi
done <<< "$images"
layouts=$(awk 'NF && !seen[$0]++' <<<"$layouts")

# { images -> html }
# TODO

# { layouts -> toplevel layouts }
[ ! -z "$layouts" ] && while IFS= read -r lay ; do
    noext=${lay%%.*}
    tops=$("$TOPLEVEL_SH" "$noext" "$outdir/$apkdir/res/layout/")
    if [ ! -z "$tops" ]; then
        echo "$tops" | sed "s/^/\"lay::$lay\" -> \"toplay::/g" | sed "s/$/\.xml\"/g" >> $model
        toplayouts+=$'\n'
        toplayouts+=$(sed "s/$/\.xml/g" <<<"$tops")
        toplayouts+=$'\n'
    fi
done <<< "$layouts"
toplayouts=$(awk 'NF && !seen[$0]++' <<<"$toplayouts")

# { toplevel layouts -> fragments }
# Layout resources use R$layout;->NAME:I in compiled code, same reasoning as
# the string case above.
[ ! -z "$toplayouts" ] && while IFS= read -r toplay ; do
    noext=${toplay%%.*}
    frags=$(find $outdir/$apkdir/ -type f -name "*.smali" -exec "$GREP" --color=never -lE "R\\\$layout;->${noext}:I" {} \; \
        | while IFS= read -r f; do "$GREP" --color=never -qEi "\.super.*fragment;" "$f" && basename "$f"; done)
    if [ ! -z "$frags" ]; then
        echo "$frags" | sed "s/^/\"toplay::$toplay\" -> \"frag::/g" | sed "s/$/\"/g" >> $model
        fragments+=$'\n'
        fragments+="$frags"
        fragments+=$'\n'
    fi
done <<< "$toplayouts"
fragments=$(awk 'NF && !seen[$0]++' <<<"$fragments")

# { toplevel layouts -> activities }
[ ! -z "$toplayouts" ] && while IFS= read -r toplay ; do
    noext=${toplay%%.*}
    acts=$(find $outdir/$apkdir/ -type f -name "*.smali" ! -name "R*.smali" -exec "$GREP" --color=never -lE "R\\\$layout;->${noext}:I" {} \; \
        | while IFS= read -r f; do "$GREP" --color=never -qEi "\.super.*fragment;" "$f" || basename "$f"; done)
    if [ ! -z "$acts" ]; then
        echo "$acts" | sed "s/^/\"toplay::$toplay\" -> \"act::/g" | sed "s/$/\"/g" >> $model
    fi
done <<< "$toplayouts"

# { fragments -> activities }
[ ! -z "$fragments" ] && while IFS= read -r fra ; do
    noext=${fra%%.*}
    acts=$(find $outdir/$apkdir/ -type f -name "*.smali" ! -name "R*.smali" -exec "$GREP" --color=never -lE "$noext;-><init>\(" {} \; \
        | while IFS= read -r f; do "$GREP" --color=never -qEi "\.super.*fragment;" "$f" || basename "$f"; done)
    if [ ! -z "$acts" ]; then
        echo "$acts" | sed "s/^/\"frag::$fra\" -> \"act::/g" | sed "s/$/\"/g" >> $model
    fi
done <<< "$fragments"

echo '}' >> $model   # end dot graph

#### Style the graph by node type, then render SVG ####
# Extract every unique quoted node name used anywhere in the graph, and emit
# a styling line for it based on its "prefix::" (adstr/nattr/lay/toplay/
# frag/act/img). Graphviz applies the LAST style directive for a given node,
# so these insert cleanly right before the closing brace regardless of where
# the node was first referenced above.

styled_model="$(mktemp /tmp/mapping_model_styled.XXXXXX.dot)"
head -n -1 "$model" > "$styled_model"   # everything except the closing '}'

"$GREP" -oP '"[a-z]+::(\\.|[^"\\])*"' "$model" | sort -u | while IFS= read -r node ; do
    case "$node" in
        \"adstr::*)  color="#fde2e2"; shape="box"    ;;  # matched strings - red-ish
        \"nattr::*)  color="#fff3cd"; shape="ellipse" ;;  # resource names - yellow
        \"lay::*)    color="#d4edda"; shape="ellipse" ;;  # layouts - green
        \"toplay::*) color="#c3e6cb"; shape="ellipse" ;;  # top-level layouts - darker green
        \"img::*)    color="#e2d4f0"; shape="ellipse" ;;  # OCR'd images - purple
        \"frag::*)   color="#cce5ff"; shape="box"    ;;  # fragments - blue
        \"act::*)    color="#b8daff"; shape="box"    ;;  # activities - darker blue
        *)           color="#ffffff"; shape="ellipse" ;;
    esac
    echo "    $node [style=filled, fillcolor=\"$color\", shape=$shape];" >> "$styled_model"
done

echo '}' >> "$styled_model"

if command -v dot >/dev/null 2>&1; then
    dot -Tsvg "$styled_model" -o "${model%.dot}.svg"
else
    echo "Graphviz 'dot' not found — install with 'brew install graphviz' to auto-render the graph." >&2
fi

rm -f "$styled_model"