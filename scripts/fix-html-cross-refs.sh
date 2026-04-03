#!/bin/sh
#
# fix-html-cross-refs.sh
#
# Fix cross-references from tutorial/examples HTML to the API reference HTML,
# then strip any remaining unresolved <GTKDOCLINK> tags.
#
# Usage:
#   fix-html-cross-refs.sh <module> <api_devhelp> <html_dir> <grep> <sed>
#
#   module      - label used in log messages (e.g. "tutorial" or "examples")
#   api_devhelp - path to the API devhelp2 file (xmlsec.devhelp2)
#   html_dir    - directory containing the generated .html files
#   grep        - path to grep
#   sed         - path to sed
#

MODULE="${1:?Usage: $0 <module> <api_devhelp> <html_dir> <grep> <sed>}"
API_DEVHELP="$2"
HTML_DIR="${3:?}"
GREP="${4:-grep}"
SED="${5:-sed}"

# ---------------------------------------------------------------------------
# Step 1: Build a sed script from the API devhelp2 keyword index and apply it
#         to replace <GTKDOCLINK HREF="symbol"> with real <a href> links.
# ---------------------------------------------------------------------------
echo "-- Fixing cross-references in ${MODULE} to API docs..."
if test -f "${API_DEVHELP}"; then
    echo "-- Found API devhelp2: ${API_DEVHELP}"
    FIXXREF_SED="${HTML_DIR}/fixxref.sed"
    rm -f "${FIXXREF_SED}"
    "${GREP}" '<keyword' "${API_DEVHELP}" | \
        "${SED}" 's/.*name="\([^"(]*\)[^"]*" link="\([^"]*\)".*/\1\t\2/' | \
        "${GREP}" -v '^[[:space:]]*$' | \
        awk -F'\t' '$1 != "" && $2 != "" {
            name=$1;
            sub(/[^a-zA-Z_0-9].*$/, "", name);
            link=$2; gsub(/[[:space:]]*$/, "", link);
            if (name != "") print "s|<GTKDOCLINK HREF=\"" name "\">\\([^<]*\\)</GTKDOCLINK>|<a href=\"../api/" link "\">\\1<\\/a>|gI"
        }' >> "${FIXXREF_SED}"
    for f in $(find "${HTML_DIR}" -name "*.html" -print); do
        echo "-- Fixing cross-refs in $f..."
        test -s "${FIXXREF_SED}" && "${SED}" -i -f "${FIXXREF_SED}" "$f"
    done
else
    echo "-- WARNING: API devhelp2 not found, skipping cross-reference fix"
fi

# ---------------------------------------------------------------------------
# Step 2: Strip any remaining unresolved <GTKDOCLINK> tags.
# ---------------------------------------------------------------------------
echo "-- Cleaning up remaining unresolved cross-references in ${MODULE}..."
for f in $(find "${HTML_DIR}" -name "*.html" -print); do
    echo "-- Processing $f..."
    "${SED}" -i 's/<GTKDOCLINK[^>]*>/<font>/gI; s/<\/GTKDOCLINK[^>]*>/<\/font>/gI' "$f"
done
