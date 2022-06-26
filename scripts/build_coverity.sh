#!/bin/sh

# input
cov_token=$1
version=$2
if [ "x$version" = "x" ]; then
    echo "Usage: $0 <token> <version>"
    exit 1
fi

# config
cov_url="https://scan.coverity.com/builds?project=xmlsec"
cov_email="aleksey@aleksey.com"
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`
tar_file="xmlsec1-$version-$today.tar.gz"

echo "============= Building xmlsec"
make clean
rm -rf cov-int/
cov-build --dir cov-int make -j4
tar czvf "$tar_file" cov-int

echo "============== Uploading to Coverity"
curl \
    --form token="$cov_token" \
    --form email="$cov_email" \
    --form file=@"$tar_file"  \
    --form version="$version" \
    --form description="$version built on $today" \
    "$cov_url"

echo "============== Cleanup"
cd "$cur_pwd"
#rm -rf "$build_root"


