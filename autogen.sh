#!/bin/sh
# Run this to generate all the initial makefiles, etc.
# This is just a trivial wrapper around autoreconf and configure.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

echo Running autoreconf...
autoreconf -i -f $srcdir

if test x$OBJ_DIR != x; then
    mkdir -p "$OBJ_DIR"
    cd "$OBJ_DIR"
fi

echo
echo Running configure "$@" ...
$srcdir/configure "$@"

echo
echo "Now type 'make' to compile xmlsec."
