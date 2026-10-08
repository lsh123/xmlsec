#!/bin/sh
# Run this to generate all the initial makefiles, etc.
# This is just a trivial wrapper around autoreconf and configure.
#
# The generated configure script runs in the current working directory, so
# for an out-of-tree build create a build directory first, e.g.:
#   mkdir build
#   cd build
#   ../autogen.sh [configure options]

set -e

srcdir=$(dirname "$0")

echo Running autoreconf...
autoreconf -i -f "$srcdir"

echo
echo Running configure "$@" ...
"$srcdir"/configure "$@"

echo
echo "Now type 'make' to compile xmlsec."
