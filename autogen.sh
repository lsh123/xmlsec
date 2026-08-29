#!/bin/sh
# Run this to generate all the initial makefiles, etc.
# This is just a trivial wrapper around autoreconf and configure.

set -e

srcdir=$(dirname "$0")

echo Running autoreconf...
autoreconf -i -f "$srcdir"

echo
echo Running configure "$@" ...
"$srcdir"/configure "$@"

echo
echo "Now type 'make' to compile xmlsec."
