#!/bin/sh 

cur_pwd=`pwd`
today=`date +%F-%T`
module=xmlsec
branch=trunk
svn_uri=svn+ssh://aleksey@svn.gnome.org/svn/$module/$branch
rpm_root=/usr/src/redhat
build_root="$rpm_root/BUILD/xmlsec-build-area-$today"
remote_root=aleksey@ftp.aleksey.com:/var/ftp/pub/xmlsec/releases

echo "Creating build area $build_root"
rm -rf "$build_root"
mkdir -p "$build_root"
cd "$build_root"

echo "Checking out the module $module"
svn checkout $svn_uri $module
cd xmlsec
find . -name ".svn" | xargs rm -r

./autogen.sh --prefix=/usr --sysconfdir=/etc
make rpm-release

tar_file=`ls xmlsec*.tar.gz`
echo "Moving sources tar file to $rpm_root/SOURCES/$tar_file"
mv $tar_file $rpm_root/SOURCES

echo "Cleanup"
cd "$cur_pwd"
rm -rf "$build_root"

