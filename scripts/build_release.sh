#!/bin/sh 

branch=

build_root=/tmp
rpm_root=/usr/src/redhat
remote_root=ftp.aleksey.com:/var/ftp/pub/xmlsec/releases

rm -rf $build_root/xmlsec
cd $build_root

if test "z$branch" != "z"; then 
    echo "Cheking out module xmlsec from branch $branch"
    cvs -d :pserver:aleksey@cvs.gnome.org:/cvs/gnome -z3 co -P -r $branch xmlsec
else
    echo "Cheking out module xmlsec from tip"
    cvs -d :pserver:aleksey@cvs.gnome.org:/cvs/gnome -z3 co -P xmlsec
fi

cd xmlsec
version_cvs=`echo $version | sed 's/\./_/g'`
cvs tag -F xmlsec-$version_cvs
./autogen.sh --prefix=/usr --sysconfdir=/etc
rm -rf config.cache
make distclean
make rpm
mv xmlsec*.tar.gz $rpm_root/SOURCES

