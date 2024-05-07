#!/bin/sh
#
# Usage: build_release.sh <crypto> [<optional configure params>]
#

# config
script_dir=`dirname $0`
top_dir=`realpath "${script_dir}/.."`
crypto=$1
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`
shift 

if [ x"$crypto" = x ]; then
    echo "Usage: $0 <crypto> [<optional configure params>]"
    exit 1
fi

echo "============== Starting memcheck for ${crypto} with source root: '${top_dir}'"
rm -f /tmp/*.log
make distclean
${top_dir}/autogen.sh --enable-development --with-default-crypto=${crypto} "$@"
make -j12
make memcheck-crypto-${crypto}
