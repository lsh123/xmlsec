#!/bin/sh 
#
# Usage: build_release.sh <version> [<release-candidate-tag>]
#


# config
version=$1
rc=$2
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`

git_uri=git@github.com:lsh123/xmlsec.git
rpm_root=/usr/src/redhat
build_root="/tmp/xmlsec-build-area-$today"
tar_file="xmlsec1-$version.tar.gz"
sig_file="xmlsec1-$version.sig"
rc_tar_file="xmlsec1-$version-$rc.tar.gz"
rc_sig_file="xmlsec1-$version-$rc.sig"
git_release_branch="xmlsec-$version-release"
git_version_tag=`echo $version | sed 's/\./_/g'`

if [ x"$version" = x ]; then
    echo "Usage: $0 <version> [<release-candidate-tag>]"
    exit 1
fi

echo "============== Creating build area $build_root for building xmlsec1-$version"
rm -rf "$build_root"
mkdir -p "$build_root"
cd "$build_root"

echo "============== Checking out the module '$git_url'"
git clone $git_uri
cd xmlsec
if [ x"$rc" != x ]; then
    echo "============== Switching to release branch '$git_release_branch' for RC build '$rc'"
    git checkout $git_release_branch
fi
find . -name ".git" | xargs rm -r

echo "============== Building xmlsec1-$version"
./autogen.sh --prefix=/usr --sysconfdir=/etc
make tar-release
# can't build rpm on ubuntu
# make rpm-release

echo "============== Moving tar file"
if [ x"$rc" = x ]; then
     mv "$tar_file" "$cur_pwd/"
else
     mv "$tar_file" "$cur_pwd/$rc_tar_file"
fi
cd "$cur_pwd"

echo "============== Signing tar file"
if [ x"$rc" = x ]; then
    gpg --output "$sig_file" --detach-sig "$tar_file"
else
    gpg --output "$rc_sig_file" --detach-sig "$rc_tar_file"
fi

if [ x"$rc" = x ]; then
     echo "============== Tagging the release $version in the github"
     echo "RUN MANUALLY: git tag -a "xmlsec-$git_version_tag" -m 'XMLSec release $version'"
     echo "RUN MANUALLY: git push --follow-tags"
fi

echo "============== Cleanup"
#rm -rf "$build_root"
