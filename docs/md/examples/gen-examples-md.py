#!/usr/bin/env python3
#
# gen-examples-md.py — Generate Markdown files for each XML Security Library example.
#
# Usage:
#   python3 gen-examples-md.py <examples_src_dir> <examples_out_dir>
#
# Reads C source files and related XML files from <examples_src_dir> and writes
# one Markdown file per example into <examples_out_dir>.
# Also generates index.md with a table of contents linking to all example files.
#

import os
import sys

# Input files (C sources / XML documents) that were referenced but not found.
_missing_files = []


def _fail(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _read_file(path):
    """Read a UTF-8 text file, exiting with a clear error on failure."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as e:
        _fail(f"failed to read {path}: {e}")


def write_index(out_dir, examples):
    """Generate index.md with a table of contents for all examples."""
    out_path = os.path.join(out_dir, 'index.md')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('# XML Security Library Examples\n\n')
        f.write('The following examples demonstrate how to use the XML Security Library '
                'to sign, verify, encrypt, and decrypt XML documents.\n\n')
        f.write('## Table of Contents\n\n')
        for i, (out_file, title, desc) in enumerate(examples, 1):
            f.write(f'{i}. [{title}]({out_file}) — {desc}\n')
        f.write('\n')
    print(f'Generated {out_path}')


def write_example(src_dir, out_dir, out_file, title, desc, c_file, *xml_pairs):
    """Generate a single example Markdown file."""
    if len(xml_pairs) % 2 != 0:
        _fail(f"{out_file}: expected an even number of label/file arguments, got {len(xml_pairs)}")

    out_path = os.path.join(out_dir, out_file)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(f'# {title}\n\n')
        f.write(f'{desc}\n\n')

        c_path = os.path.join(src_dir, c_file)
        if os.path.isfile(c_path):
            f.write(f'## Source: `{c_file}`\n\n')
            f.write('```c\n')
            f.write(_read_file(c_path))
            f.write('```\n\n')
        else:
            _missing_files.append(c_path)

        for i in range(0, len(xml_pairs), 2):
            xml_label = xml_pairs[i]
            xml_file  = xml_pairs[i + 1]
            xml_path  = os.path.join(src_dir, xml_file)
            if os.path.isfile(xml_path):
                f.write(f'## {xml_label}: `{xml_file}`\n\n')
                f.write('```xml\n')
                f.write(_read_file(xml_path))
                f.write('```\n\n')
            else:
                _missing_files.append(xml_path)

    print(f'Generated {out_path}')


def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <examples_src_dir> <examples_out_dir>', file=sys.stderr)
        sys.exit(1)

    src = sys.argv[1]
    out = sys.argv[2]

    if not os.path.isdir(src):
        _fail(f"examples source directory not found: {src}")

    os.makedirs(out, exist_ok=True)

    examples = []
    listed_c_files = set()

    def ex(out_file, title, desc, c_file, *xml_pairs):
        examples.append((out_file, title, desc))
        listed_c_files.add(c_file)
        write_example(src, out, out_file, title, desc, c_file, *xml_pairs)

    ex('sign1.md',
       'Signing a template file',
       'Signs an XML document using a pre-created signature template file and a PEM private key.',
       'sign1.c',
       'Template', 'sign1-tmpl.xml',
       'Result',   'sign1-res.xml')

    ex('sign2.md',
       'Signing a dynamically created template',
       'Signs an XML document using a dynamically created signature template.',
       'sign2.c',
       'Input Document', 'sign2-doc.xml',
       'Result',         'sign2-res.xml')

    ex('sign3.md',
       'Signing an enveloped signature with an X509 certificate',
       'Creates an enveloped XML Digital Signature using an X509 certificate.',
       'sign3.c',
       'Input Document', 'sign3-doc.xml',
       'Result',         'sign3-res.xml')

    ex('sign4.md',
       'Signing a node by ID with an X509 certificate',
       'Signs a specific XML node referenced by ID attribute using an X509 certificate.',
       'sign4.c',
       'Input Document', 'sign4-doc.xml',
       'Result',         'sign4-res.xml')

    ex('verify1.md',
       'Verifying a signature with a single key',
       'Verifies an XML Digital Signature using a single public key loaded from a PEM file.',
       'verify1.c')

    ex('verify2.md',
       'Verifying a signature with a keys manager',
       'Verifies an XML Digital Signature using a keys manager loaded with multiple keys.',
       'verify2.c')

    ex('verify3.md',
       'Verifying an enveloped signature with X509 certificates',
       'Verifies an enveloped XML Digital Signature using X509 certificate chain verification.',
       'verify3.c')

    ex('verify4.md',
       'Verifying a signature of a node with X509 certificates',
       'Verifies a node signature with X509 certificates.',
       'verify4.c')

    ex('verify-saml.md',
       'Verifying a signature with additional restrictions',
       'Verifies an XML Digital Signature with additional restrictions (SAML-style).',
       'verify-saml.c',
       'Valid Template',   'verify-saml-tmpl.xml',
       'Valid Result',     'verify-saml-res.xml',
       'Invalid Template', 'verify-saml-bad-tmpl.xml',
       'Invalid Result',   'verify-saml-bad-res.xml')

    ex('encrypt1.md',
       'Encrypting data with a template file',
       'Encrypts binary data using a pre-created encryption template file.',
       'encrypt1.c',
       'Template', 'encrypt1-tmpl.xml',
       'Result',   'encrypt1-res.xml')

    ex('encrypt2.md',
       'Encrypting data with a dynamically created template',
       'Encrypts an XML document using a dynamically created encryption template.',
       'encrypt2.c',
       'Input Document', 'encrypt2-doc.xml',
       'Result',         'encrypt2-res.xml')

    ex('encrypt3.md',
       'Encrypting data with a session key',
       'Encrypts an XML document using a session key wrapped with an RSA key from the keys manager.',
       'encrypt3.c',
       'Input Document', 'encrypt3-doc.xml',
       'Result',         'encrypt3-res.xml')

    ex('decrypt1.md',
       'Decrypting data with a single key',
       'Decrypts encrypted XML data using a single DES key loaded from a binary file.',
       'decrypt1.c')

    ex('decrypt2.md',
       'Decrypting data with a keys manager',
       'Decrypts encrypted XML data using a keys manager loaded with DES keys.',
       'decrypt2.c')

    ex('decrypt3.md',
       'Writing a custom keys manager',
       'Demonstrates implementing a custom file-based keys store for decryption.',
       'decrypt3.c')

    # Warn about example sources present in the tree but missing from the list above.
    try:
        for name in sorted(os.listdir(src)):
            if name.endswith('.c') and name not in listed_c_files:
                print(f"WARNING: {name} in {src} is not documented by any example entry", file=sys.stderr)
    except OSError as e:
        print(f"WARNING: could not list {src} to cross-check examples: {e}", file=sys.stderr)

    if _missing_files:
        for path in _missing_files:
            print(f"WARNING: expected example input file not found: {path}", file=sys.stderr)

    write_index(out, examples)


if __name__ == '__main__':
    main()
