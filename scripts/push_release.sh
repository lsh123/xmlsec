#!/bin/sh 

version=$1
module=xmlsec1
build_root=/tmp
rpm_root=/usr/src/redhat
remote_root=aleksey@ftp.aleksey.com:/var/ftp/pub/xmlsec/releases
build_target=i386

echo "Uploading to aleksey.com"
scp $rpm_root/SOURCES/$module-$version.tar.gz \
    $rpm_root/SRPMS/$module-$version-*.src.rpm \
    $rpm_root/RPMS/$build_target/$module-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-devel-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-openssl-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-openssl-devel-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-nss-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-nss-devel-$version-*.$build_target.rpm \
    $remote_root

echo "Uploading to redhat.com"
ncftpput incoming.redhat.com /libc6 \
    $rpm_root/SRPMS/$module-$version-*.src.rpm \
    $rpm_root/RPMS/$build_target/$module-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-devel-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-openssl-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-openssl-devel-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-nss-$version-*.$build_target.rpm \
    $rpm_root/RPMS/$build_target/$module-nss-devel-$version-*.$build_target.rpm
