#!/bin/sh

# config
configure_options=""
configure_options="$configure_options --enable-static-linking --enable-crypto-dl=no"
configure_options="$configure_options --enable-manpages-build --enable-docs-build"
configure_options="$configure_options --enable-md5 --enable-ripemd160"
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`

echo "============= Building xmlsec"
make distclean
./autogen.sh $configure_options
make

echo "============== Cleanup"
cd "$cur_pwd"

