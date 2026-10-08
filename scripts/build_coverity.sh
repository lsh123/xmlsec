#!/bin/sh
set -e

# Input parameters.
cov_token=$1
version=$2
if [ x"$cov_token" = x ] || [ x"$version" = x ]; then
    echo "Usage: $0 <token> <version>"
    exit 1
fi

# Configuration.
cov_url="https://scan.coverity.com/builds?project=xmlsec"
cov_email="aleksey@aleksey.com"
cur_pwd=`pwd`
script_pwd=$(dirname "$0")
srcdir=$(cd "$script_pwd/.." && pwd)
today=`date +%F-%H-%M-%S`
tar_file="xmlsec1-$version-$today.tar.gz"

# Restore the caller's working directory on any exit (including 'set -e'
# failures), since the script builds in the source tree.
trap 'cd "$cur_pwd"' EXIT

echo "============== Building xmlsec"
cd "$srcdir"
# Regenerate the build system so that configure always matches the current
# configure.ac, even if a stale configure was left over from a previous run.
autoreconf -i -f
./configure --enable-legacy-features --enable-ftp --enable-http --with-gcrypt
make clean
rm -rf cov-int/
cov-build --dir cov-int make -j4
tar czvf "$tar_file" cov-int

echo "============== Uploading to Coverity"
curl \
    --form token="$cov_token" \
    --form email="$cov_email" \
    --form file=@"$tar_file" \
    --form version="$version" \
    --form description="$version built on $today" \
    "$cov_url"

# Restore the caller's working directory.
cd "$cur_pwd"
