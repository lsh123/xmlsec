#!/bin/sh
#
# gen-examples-md.sh — Generate Markdown files for each XML Security Library example.
#
# Usage:
#   gen-examples-md.sh <examples_src_dir> <examples_out_dir>
#
# Reads C source files and related XML files from <examples_src_dir> and writes
# one Markdown file per example into <examples_out_dir>.
# index.md is NOT regenerated — it lives as a static source file.
#

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <examples_src_dir> <examples_out_dir>" >&2
    exit 1
fi

SRC="$1"
OUT="$2"

mkdir -p "$OUT"

# write_example <out_file> <title> <description> <c_file> [xml_label xml_file ...]
# Remaining args after c_file are pairs: label file label file ...
write_example() {
    out_file="$1"
    title="$2"
    desc="$3"
    c_file="$4"
    shift 4

    {
        printf '# %s\n\n' "$title"
        printf '%s\n\n' "$desc"

        if [ -f "$SRC/$c_file" ]; then
            printf '## Source: `%s`\n\n' "$c_file"
            printf '```c\n'
            cat "$SRC/$c_file"
            printf '```\n\n'
        fi

        while [ $# -ge 2 ]; do
            xml_label="$1"
            xml_file="$2"
            shift 2
            if [ -f "$SRC/$xml_file" ]; then
                printf '## %s: `%s`\n\n' "$xml_label" "$xml_file"
                printf '```xml\n'
                cat "$SRC/$xml_file"
                printf '```\n\n'
            fi
        done
    } > "$out_file"

    echo "Generated $out_file"
}

write_example "$OUT/sign1.md" \
    "Signing a template file" \
    "Signs an XML document using a pre-created signature template file and a PEM private key." \
    "sign1.c" \
    "Template" "sign1-tmpl.xml" \
    "Result"   "sign1-res.xml"

write_example "$OUT/sign2.md" \
    "Signing a dynamically created template" \
    "Signs an XML document using a dynamically created signature template." \
    "sign2.c" \
    "Input Document" "sign2-doc.xml" \
    "Result"         "sign2-res.xml"

write_example "$OUT/sign3.md" \
    "Signing enveloped signature with X509 certificate" \
    "Creates an enveloped XML Digital Signature using an X509 certificate." \
    "sign3.c" \
    "Input Document" "sign3-doc.xml" \
    "Result"         "sign3-res.xml"

write_example "$OUT/sign4.md" \
    "Signing a node by ID with X509 certificate" \
    "Signs a specific XML node referenced by ID attribute using an X509 certificate." \
    "sign4.c" \
    "Input Document" "sign4-doc.xml" \
    "Result"         "sign4-res.xml"

write_example "$OUT/verify1.md" \
    "Verifying a signature with a single key" \
    "Verifies an XML Digital Signature using a single public key loaded from a PEM file." \
    "verify1.c"

write_example "$OUT/verify2.md" \
    "Verifying a signature with keys manager" \
    "Verifies an XML Digital Signature using a keys manager loaded with multiple keys." \
    "verify2.c"

write_example "$OUT/verify3.md" \
    "Verifying an enveloped signature with X509 certificates" \
    "Verifies an enveloped XML Digital Signature using X509 certificate chain verification." \
    "verify3.c"

write_example "$OUT/verify4.md" \
    "Verifying a signature of a node with X509 certificates" \
    "Verifies a node signature with X509 certificates." \
    "verify4.c"

write_example "$OUT/verify-saml.md" \
    "Verifying a signature with additional restrictions" \
    "Verifies an XML Digital Signature with additional restrictions (SAML-style)." \
    "verify-saml.c" \
    "Valid Template"   "verify-saml-tmpl.xml" \
    "Valid Result"     "verify-saml-res.xml" \
    "Invalid Template" "verify-saml-bad-tmpl.xml" \
    "Invalid Result"   "verify-saml-bad-res.xml"

write_example "$OUT/encrypt1.md" \
    "Encrypting data with a template file" \
    "Encrypts binary data using a pre-created encryption template file." \
    "encrypt1.c" \
    "Template" "encrypt1-tmpl.xml" \
    "Result"   "encrypt1-res.xml"

write_example "$OUT/encrypt2.md" \
    "Encrypting data with a dynamically created template" \
    "Encrypts an XML document using a dynamically created encryption template." \
    "encrypt2.c" \
    "Input Document" "encrypt2-doc.xml" \
    "Result"         "encrypt2-res.xml"

write_example "$OUT/encrypt3.md" \
    "Encrypting data with a session key" \
    "Encrypts an XML document using a session key wrapped with an RSA key from the keys manager." \
    "encrypt3.c" \
    "Input Document" "encrypt3-doc.xml" \
    "Result"         "encrypt3-res.xml"

write_example "$OUT/decrypt1.md" \
    "Decrypting data with a single key" \
    "Decrypts encrypted XML data using a single DES key loaded from a binary file." \
    "decrypt1.c"

write_example "$OUT/decrypt2.md" \
    "Decrypting data with keys manager" \
    "Decrypts encrypted XML data using a keys manager loaded with DES keys." \
    "decrypt2.c"

write_example "$OUT/decrypt3.md" \
    "Writing a custom keys manager" \
    "Demonstrates implementing a custom file-based keys store for decryption." \
    "decrypt3.c"
