#!/bin/sh 

module=$1
version=$2
build_root=/tmp
rpm_root=/usr/src/RPM
remote_root=ftp.aleksey.com:/var/ftp/pub/$module/releases

echo "Uploading to aleksey.com"
scp $rpm_root/SOURCES/$module-$version.tar.gz \
    $rpm_root/SRPMS/$module-$version-*.src.rpm \
    $rpm_root/RPMS/i586/$module-$version-*.i586.rpm \
    $rpm_root/RPMS/i586/$module-devel-$version-*.i586.rpm \
    $remote_root

echo "Uploading to redhat.com"
ncftpput incoming.redhat.com /libc6 \
    $rpm_root/SRPMS/$module-$version-*.src.rpm \
    $rpm_root/RPMS/i586/$module-$version-*.i586.rpm \
    $rpm_root/RPMS/i586/$module-devel-$version-*.i586.rpm
