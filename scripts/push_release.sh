#!/bin/sh 

module=$1
version=$2
build_root=/tmp
rpm_root=/usr/src/redhat
remote_root=ftp.aleksey.com:/var/ftp/pub/$module/releases
build_target=i386

echo "Uploading to aleksey.com"
scp $rpm_root/SOURCES/$module-$version.tar.gz \
    $rpm_root/SRPMS/$module-$version-*.src.rpm \
    $rpm_root/RPMS/$build_target/$module-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-devel-$version-*.$build_target.rpm \
    $remote_root

echo "Uploading to redhat.com"
ncftpput incoming.redhat.com /libc6 \
    $rpm_root/SRPMS/$module-$version-*.src.rpm \
    $rpm_root/RPMS/$build_target/$module-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-devel-$version-*.$build_target.rpm
