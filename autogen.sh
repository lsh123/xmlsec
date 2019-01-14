#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=. 

THEDIR=`pwd`
cd $srcdir
DIE=0

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile xmlsec."
	DIE=1
}

LIBTOOL="libtool"
if [ "`uname`" = "Darwin" -a -n "`type -p glibtool`" ]; then
	LIBTOOL=glibtool
fi

($LIBTOOL --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have $LIBTOOL installed to compile xmlsec."
	DIE=1
}

(autoheader --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoheader installed to compile xmlsec."
	DIE=1
}

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile xmlsec."
	DIE=1
}
(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have automake installed to compile xmlsec."
	DIE=1
}

if test "$DIE" -eq 1; then
	exit 1
fi

test -f include/xmlsec/xmldsig.h  || {
	echo "You must run this script in the top-level xmlsec directory"
	exit 1
}

if test -z "$*"; then
	echo "I am going to run ./configure with no arguments - if you wish "
        echo "to pass any to it, please specify them on the $0 command line."
fi

LIBTOOLIZE="libtoolize"
if [ "`uname`" = "Darwin" -a -n "`type -p glibtoolize`" ]; then
	LIBTOOLIZE=glibtoolize
fi
echo "Running $LIBTOOLIZE..."
$LIBTOOLIZE --copy --force
echo "Running aclocal..."
if [ -d /usr/local/share/aclocal ]; then
	aclocal --force -I m4 -I /usr/local/share/aclocal
else
	aclocal --force -I m4
fi
echo "Running autoheader..."
autoheader --force
echo "Running autoconf..."
autoconf --force
echo "Running automake..."
automake --gnu --add-missing
echo "Running autoconf..."
autoconf

cd $THEDIR

if test x$OBJ_DIR != x; then
    mkdir -p "$OBJ_DIR"
    cd "$OBJ_DIR"
fi

conf_flags="--enable-maintainer-mode" #--enable-iso-c
echo Running configure $conf_flags "$@" ...
$srcdir/configure $conf_flags "$@"

echo 
echo "Now type 'make' to compile xmlsec."
