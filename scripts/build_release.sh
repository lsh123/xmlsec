#!/bin/sh 

cur_pwd=`pwd`
today=`date +%F-%T`
module=xmlsec
branch=
cvs_root=:pserver:aleksey@cvs.gnome.org:/cvs/gnome
rpm_root=/usr/src/redhat
build_root="$rpm_root/BUILD/xmlsec-build-area-$today"
remote_root=aleksey@ftp.aleksey.com:/var/ftp/pub/xmlsec/releases

echo "Creating build area $build_root"
rm -rf "$build_root"
mkdir -p "$build_root"
cd "$build_root"

if test "z$branch" != "z"; then 
    echo "Cheking out module $module from branch $branch"
    cvs -d $cvs_root -z3 co -P -r $branch $module > /dev/null
else
    echo "Cheking out module $module from tip"
    cvs -d $cvs_root -z3 co -P $module > /dev/null
fi
cd xmlsec

./autogen.sh --prefix=/usr --sysconfdir=/etc
make rpm-release

tar_file=`ls xmlsec*.tar.gz`
echo "Moving sources tar file to $rpm_root/SOURCES/$tar_file"
mv $tar_file $rpm_root/SOURCES

echo "Cleanup"
cd "$cur_pwd"
rm -rf "$build_root"
