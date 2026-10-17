#!/bin/sh
set -e

# config
configure_options=""
configure_options="$configure_options --enable-static-linking --enable-crypto-dl=no"
configure_options="$configure_options --enable-manpages-build --enable-docs-build"
configure_options="$configure_options --enable-md5 --enable-ripemd160"

echo "============= Building xmlsec"
# 'make distclean' fails on a fresh checkout (no generated Makefile),
# which is fine.
make distclean || true
./autogen.sh $configure_options
make

