#!/bin/sh 

# config
cov_url="https://scan.coverity.com/builds?project=xmlsec"
cov_email="aleksey@aleksey.com"
cov_token=$1
version=$2
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`

git_uri=git@github.com:lsh123/xmlsec.git
rpm_root=/usr/src/redhat
build_root="/tmp/xmlsec-build-area-$today"
tar_file="xmlsec1-$version-$today.tar.gz"

if [ x"$version" = x ]; then
    echo "Usage: $0 <token> <version>"
    exit 1
fi

echo "============== Creating build area $build_root for building xmlsec1-$version"
rm -rf "$build_root"
mkdir -p "$build_root"
cd "$build_root"

echo "============== Checking out the module '$git_url'"
git clone $git_uri
cd xmlsec
find . -name ".git" | xargs rm -r

echo "============== Building xmlsec1-$version with coverity"
./autogen.sh --prefix=/usr --sysconfdir=/etc
cov-build --dir cov-int make
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


