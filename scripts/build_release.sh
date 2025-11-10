#!/bin/sh
#
# Usage: build_release.sh <version> [<release-candidate-tag>]
#


# config
version=$1
rc=$2
cur_pwd=`pwd`
today=`date +%F-%H-%M-%S`

if [ x"$version" = x ]; then
    echo "Usage: $0 <version> [<release-candidate-tag>]"
    exit 1
fi

if [ x"$rc" = x ]; then
    full_version="$version"
    website_symlink_path="current"
else
    full_version="$version-$rc"
    website_symlink_path="rc"
fi

git_uri=git@github.com:lsh123/xmlsec.git
rpm_root=/usr/src/redhat
build_root="/tmp/xmlsec-build-area-$today"
build_tar_file="xmlsec1-${version}.tar.gz"
tar_file="xmlsec1-${full_version}.tar.gz"
sig_file="xmlsec1-${full_version}.sig"
git_version_tag=`echo ${full_version} | sed 's/\./_/g'`

echo "============== Creating build area $build_root for building xmlsec1-$version"
rm -rf "$build_root"
mkdir -p "$build_root"
cd "$build_root"

echo "============== Checking out the module '$git_url'"
git clone $git_uri
cd xmlsec
find . -name ".git" | xargs rm -r

echo "============== Building xmlsec1-${full_version}"
./autogen.sh --prefix=/usr --sysconfdir=/etc
make tar-release
# can't build rpm on ubuntu
# make rpm-release

echo "============== Moving tar file"
mv "${build_tar_file}" "${cur_pwd}/${tar_file}"
cd "$cur_pwd"

echo "============== Signing tar file"
gpg --output "${sig_file}" --detach-sig "${tar_file}"

echo "============== Tagging the release ${full_version} in the github"
echo "RUN MANUALLY: git tag -a "${full_version}" -m 'XMLSec release ${full_version}'"
echo "RUN MANUALLY: git tag -a "xmlsec_${git_version_tag}" -m 'XMLSec release ${full_version}'"
echo "RUN MANUALLY: git push --follow-tags"

echo "======== Publish release to website:"
echo "RUN MANUALLY: scp ${tar_file} ${sig_file} smtp.aleksey.com:"
echo "RUN MANUALLY: ssh smtp.aleksey.com"
echo "RUN MANUALLY (smtp): ./bin/push-xmlsec-docs.sh ${full_version}"
echo "RUN MANUALLY (smtp): cd /home/apps/www/aleksey.com/xmlsec/ && sudo ln -sfn xmlsec1-${full_version} ${website_symlink_path}"

echo "Verify that website is working correctly"
echo "Check windows build script, build windows version, and upload it to smtp.aleksey.com:"
echo "RUN MANUALLY (windows): scp d:\home\aleksey\distro\xmlsec1-${full_version}-win64.zip smtp.aleksey.com:"
echo "RUN MANUALLY (smtp): sudo cp ~/xmlsec1-${full_version}-win64.zip /home/apps/www/aleksey.com/xmlsec/download/win64/"
echo "RUN MANUALLY (smtp): cd /home/apps/www/aleksey.com/xmlsec/download/"
echo "Move old versions to the 'older-releases' folder"

echo "========= Publish release to github:"
echo "Download release from website, go to github releases, use newly created tag and "
echo "tarball to publish release; after that create announcement about the release in the "
echo "github dicussions"

echo "============== Cleanup"
#rm -rf "$build_root"
