#!/bin/sh 

# config
version=$1
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`

git_uri=git@github.com:lsh123/xmlsec.git
rpm_root=/usr/src/redhat
build_root="/tmp/xmlsec-build-area-$today"
tar_file="xmlsec1-$version.tar.gz"
sig_file="xmlsec1-$version.sig"
git_version_tag=`echo $version | sed 's/\./_/g'`

if [ x"$version" = x ]; then
    echo "Usage: $0 <version>"
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

echo "============== Building xmlsec1-$version"
./autogen.sh --prefix=/usr --sysconfdir=/etc
make tar-release
# can't build rpm on ubuntu
# make rpm-release

echo "============== Signing $tar_file into $sig_file"
gpg --output "$sig_file" --detach-sig "$tar_file"

echo "============== Tagging the release $version in the github"
echo "git tag -a "xmlsec-$git_version_tag" -m 'XMLSec release $version'"
echo "git push --follow-tags"

echo "============== Move files and cleanup"
mv "$tar_file" "$sig_file" "$cur_pwd/"
cd "$cur_pwd"
#rm -rf "$build_root"


