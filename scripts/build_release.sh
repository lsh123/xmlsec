#!/bin/sh 

module=$1
version=$2
branch=$3
build_root=/tmp
rpm_root=/usr/src/redhat
remote_root=ftp.aleksey.com:/var/ftp/pub/$module/releases

rm -rf $build_root/$module
cd $build_root

if test "z$branch" != "z"; then 
    echo "Cheking out module $module from branch $branch"
    cvs -z3 co -r $branch $module
else
    echo "Cheking out module $module from tip"
    cvs -z3 co $module
fi

cd $module
version_cvs=`echo $version | sed 's/\./_/g'`
cvs tag -F $module-$version_cvs
rm -rf `find . -name "CVS"`

./autogen.sh --prefix=/usr --sysconfdir=/etc
rm config.cache
make dist
mv $module-$version.tar.gz $rpm_root/SOURCES
rpm -ba $module.spec

