#!/bin/sh
set -e
#
# Usage: build_memcheck.sh <crypto> [<optional configure params>]
#

# Configuration.
script_dir=$(dirname "$0")
top_dir="${script_dir}/.."
crypto=$1

if [ x"$crypto" = x ]; then
    echo "Usage: $0 <crypto> [<optional configure params>]"
    exit 1
fi

shift

# Build parallelism (override with PARALLEL_JOBS).
parallel_jobs=${PARALLEL_JOBS:-12}
# Test log folder (override with TMPFOLDER, see tests/testrun.sh).
tmp_folder=${TMPFOLDER:-/tmp}

echo "============== Starting memcheck for ${crypto} using source root '${top_dir}'"
cd "$top_dir"
rm -rf "${tmp_folder}"/xmlsec-test*
if [ -f Makefile ]; then
    make distclean
fi
autoreconf -i -f
./configure --enable-development --enable-legacy-features --with-default-crypto=${crypto} "$@"
make -j${parallel_jobs}
make memcheck-crypto-${crypto}
