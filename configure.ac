dnl Process this file with autoconf to produce a configure script.
AC_INIT([xmlsec1],[1.3.3],[http://www.aleksey.com/xmlsec])

XMLSEC_PACKAGE=xmlsec1
XMLSEC_VERSION_MAJOR=1
XMLSEC_VERSION_MINOR=3
XMLSEC_VERSION_SUBMINOR=3
XMLSEC_VERSION="$XMLSEC_VERSION_MAJOR.$XMLSEC_VERSION_MINOR.$XMLSEC_VERSION_SUBMINOR"
XMLSEC_VERSION_INFO=`echo $XMLSEC_VERSION | awk -F. '{ printf "%d:%d:%d", $1+$2, $3, $2 }'`
XMLSEC_VERSION_SAFE=`echo $XMLSEC_VERSION | sed 's/\./_/g'`

AC_PREREQ([2.69])
AC_LANG(C)
AC_CANONICAL_HOST

AC_SUBST(XMLSEC_VERSION)
AC_SUBST(XMLSEC_PACKAGE)
AC_SUBST(XMLSEC_VERSION_SAFE)
AC_SUBST(XMLSEC_VERSION_MAJOR)
AC_SUBST(XMLSEC_VERSION_MINOR)
AC_SUBST(XMLSEC_VERSION_SUBMINOR)
AC_SUBST(XMLSEC_VERSION_INFO)

AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE([1.7 tar-ustar subdir-objects -Wno-portability foreign])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

# Support silent build rules, requires at least automake-1.11. Disable
# by either passing --disable-silent-rules to configure or passing V=1
# to make
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl
dnl Check the environment
dnl
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AC_PROG_EGREP

LT_INIT

dnl
dnl Find programs
dnl
if test "z$RM" = "z" ; then
    AC_PATH_PROG(RM, rm, /bin/rm)
fi
AC_PATH_PROG(CP, cp, /bin/cp)
AC_PATH_PROG(MV, mv, /bin/mv)
AC_PATH_PROG(TAR, tar, /bin/tar)
AC_PATH_PROG(PERL, perl)

dnl Programs for man pahes and html docs
AC_PATH_PROG(HELP2MAN, help2man)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(MAN2HTML, man2html)
AC_PATH_PROG(GTKDOC_MKHTML, gtkdoc-mkhtml)
AC_PATH_PROG(GTKDOC_MKDB,   gtkdoc-mkdb)
AC_PATH_PROG(GTKDOC_SCAN,   gtkdoc-scan)
AM_CONDITIONAL(HAS_HELP2MAN, [test x"$HELP2MAN" != x])
AM_CONDITIONAL(HAS_MAN2HTML, [test x"$MAN2HTML" != x])
AM_CONDITIONAL(HAS_XSLTPROC, [test x"$XSLTPROC" != x])

dnl Checks for header files.
AC_HEADER_DIRENT


dnl ==========================================================================
dnl XMLSec configs
dnl ==========================================================================
XMLSEC_DEFINES=
XMLSEC_APP_DEFINES=
XMLSEC_EXTRA_LDFLAGS=
XMLSEC_CRYPTO_EXTRA_LDFLAGS=

dnl ==========================================================================
dnl Detect compiler
dnl ==========================================================================
build_with_gcc=no
build_with_clang=no
AC_MSG_CHECKING(for '$CC' compiler type)

cc_ver=`$CC -v 2>&1 | grep -i version`
case "${cc_ver}" in
  *gcc*|*GCC* )
    build_with_gcc=yes
    AC_MSG_RESULT("GCC")
    ;;

  *clang*|*CLANG* )
    build_with_clang=yes
    AC_MSG_RESULT("CLANG")
    ;;
  *)
    AC_MSG_RESULT("Other")
    ;;
esac


dnl ==========================================================================
dnl Perform host specific configuration
dnl ==========================================================================

build_on_aix=no
build_on_windows=no
build_on_mac=no
build_on_linux=no
AC_MSG_CHECKING(for build OS)

dnl should separate extra LDFLAGS for xmlsec and crypto libs ?
dnl should --enable-runtime-pseudo-reloc for mingw and cygwin ?
if test -n "$shrext"; then
  XMLSEC_SHLIBSFX="$shrext"
else
  dnl changed in libtool (between 1.5.2 and 1.5.14)
  XMLSEC_SHLIBSFX="$shrext_cmds"
fi

#
# prevent weird behaviour on gcc (see https://news.ycombinator.com/item?id=33770277)
#
CFLAGS="$CFLAGS -fno-strict-overflow -fno-strict-aliasing"

case "${host}" in
  *aix* )
    CFLAGS="${CFLAGS} -D_ALL_SOURCE"

    build_on_aix=yes
    AC_MSG_RESULT("AIX")
    ;;
  *-*-mingw*)
    dnl use libtool flags "-avoid-version" to create shared
    dnl libraries without version suffix, i.e. libxmlsec1.dll
    dnl instead libxmlsec1-NN.dll, where NN is a number.
    XMLSEC_EXTRA_LDFLAGS="$XMLSEC_EXTRA_LDFLAGS -no-undefined -avoid-version"
    XMLSEC_CRYPTO_EXTRA_LDFLAGS="$XMLSEC_CRYPTO_EXTRA_LDFLAGS -no-undefined -avoid-version"
    XMLSEC_SHLIBSFX=".dll.a"

    build_on_windows=yes
    AC_MSG_RESULT("Windows (MinGW)")
    ;;
  *-*-cygwin*)
    XMLSEC_EXTRA_LDFLAGS="$XMLSEC_EXTRA_LDFLAGS -no-undefined"
    XMLSEC_CRYPTO_EXTRA_LDFLAGS="$XMLSEC_CRYPTO_EXTRA_LDFLAGS -no-undefined"

    build_on_windows=yes
    AC_MSG_RESULT("Windows (Cygwin)")
    ;;
  *-*-darwin*)
    XMLSEC_SHLIBSFX=".dylib"

    build_on_mac=yes
    AC_MSG_RESULT("MacOSX")
    ;;
  *-*-linux*)
    build_on_linux=yes
    AC_MSG_RESULT("Linux")
    ;;
  *)
    AC_MSG_RESULT("Other")
    ;;
esac

dnl ==========================================================================
dnl Specific setup for Aleksey's development environment:
dnl	- with debug
dnl - with pedantic compiler flags
dnl - with docs build
dnl	- with static binaries
dnl	- without dynamic xmlsec-crypto loading
dnl ==========================================================================
AC_MSG_CHECKING(for development environment)
AC_ARG_ENABLE([development], [AS_HELP_STRING([--enable-development],[enable development environment (no)])])
if test "z$enable_development" = "zyes" ; then
    enable_debugging="yes"
    enable_pedantic="yes"
    enable_static_linking="yes"
    enable_manpages_build="no"
    enable_docs_build="no"
    enable_crypto_dl="no"

    dnl legacy crypto
    enable_md5="yes"

    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([disabled])
fi

dnl ==========================================================================
dnl Do we want to build manpages?
dnl ==========================================================================
AC_MSG_CHECKING(for man pages build)
AC_ARG_ENABLE([manpages_build], [AS_HELP_STRING([--enable-manpages-build],[man pages build (no)])])
if test "z$enable_manpages_build" = "zyes" ; then
    AM_CONDITIONAL(BUILD_MANPAGES, [test x"$HELP2MAN" != x])
    AC_MSG_RESULT([yes])
else
    AM_CONDITIONAL(BUILD_MANPAGES, [test "x" = "y"])
    AC_MSG_RESULT([disabled])
fi

dnl ==========================================================================
dnl Do we want to build docs?
dnl ==========================================================================
AC_MSG_CHECKING(for docs build)
AC_ARG_ENABLE([docs_build], [AS_HELP_STRING([--enable-docs-build],[docs build (no)])])
if test "z$enable_docs_build" = "zyes" ; then
    AM_CONDITIONAL(BUILD_MAN_DOCS, [test x"$PERL" != x && test x"$XSLTPROC" != x && test x"$MAN2HTML" != x])
    AM_CONDITIONAL(BUILD_API_DOCS, [test x"$PERL" != x && test x"$XSLTPROC" != x && test x"$GTKDOC_MKHTML" != x && test x"$GTKDOC_MKDB" != x && test x"$GTKDOC_SCAN" != x])
    AC_MSG_RESULT([yes])
else
    AM_CONDITIONAL(BUILD_MAN_DOCS, [test "x" = "y"])
    AM_CONDITIONAL(BUILD_API_DOCS, [test "x" = "y"])
    AC_MSG_RESULT([disabled])
fi

dnl ==========================================================================
dnl Hack for autoconf version mismatch
dnl ==========================================================================
if test "z$shrext" = "z" ; then
    AC_MSG_CHECKING(for shared library suffix)
    module=no
    eval shrext=$shrext_cmds
    AC_MSG_RESULT($shrext)
fi

dnl ==========================================================================
dnl Check for __FUNCTION__ or __func__
dnl ==========================================================================
AC_MSG_CHECKING(for __FUNCTION__ or __func__)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
	[[char *foo = __FUNCTION__;]])],
	[ac_function_exists=yes],
	[ac_function_exists=no])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
	[[char *foo = __func__;]])],
	[ac_func_exists=yes],
	[ac_func_exists=no])
if test "z$ac_func_exists" = "zyes" ; then
	AC_MSG_RESULT([__func__])
	XMLSEC_DEFINES="$XMLSEC_DEFINES -D__XMLSEC_FUNCTION__=__func__"
elif test "z$ac_function_exists" = "zyes" ; then
    AC_MSG_RESULT([__FUNCTION__])
    XMLSEC_DEFINES="$XMLSEC_DEFINES -D__XMLSEC_FUNCTION__=__FUNCTION__"
else
    AC_MSG_RESULT("no")
fi

dnl ==========================================================================
dnl Check if pkg-config is enabled and installed
dnl ==========================================================================
PKGCONFIG_FOUND="no"
AC_ARG_ENABLE([pkgconfig], [AS_HELP_STRING([--enable-pkgconfig],[enable pkgconfig for configuration (yes)])])
if test "z$enable_pkgconfig" != "zno" ; then
    PKG_PROG_PKG_CONFIG
    PKGCONFIG_FOUND="yes"
else
    PKGCONFIG_FOUND="no"
fi

dnl ==========================================================================
dnl Check if packages custom config scripts are enabled
dnl ==========================================================================
ENABLE_CUSTOM_CONFIGS="no"
AC_ARG_ENABLE([custom-configs], [AS_HELP_STRING([--enable-custom-configs],[enable package-specific custom scripts for configuration (yes)])])
if test "z$enable_custom_configs" != "zno" ; then
    ENABLE_CUSTOM_CONFIGS="yes"
else
    ENABLE_CUSTOM_CONFIGS="no"
fi

dnl ==========================================================================
dnl Check searching for typical packages folders is enabled
dnl ==========================================================================
ENABLE_FOLDERS_SEARCH="no"
AC_ARG_ENABLE([folders-search], [AS_HELP_STRING([--enable-folders-search],[enable searching for package installation in typical folders (yes)])])
if test "z$enable_folders_search" != "zno" ; then
    ENABLE_FOLDERS_SEARCH="yes"
else
    ENABLE_FOLDERS_SEARCH="no"
fi

dnl ==========================================================================
dnl Common installation locations
dnl ==========================================================================
COMMON_INCLUDE_DIR="/usr/include /usr/local/include"
COMMON_LIB_DIR="/usr/lib /usr/lib64 /usr/local/lib"
case $host in
    i*86-*-linux-gnu)   COMMON_LIB_DIR="$COMMON_LIB_DIR /usr/lib/i386-linux-gnu" ;;
    x86_64-*-linux-gnu) COMMON_LIB_DIR="$COMMON_LIB_DIR /usr/lib/x86_64-linux-gnu" ;;
    *)                  COMMON_LIB_DIR="$COMMON_LIB_DIR /usr/lib/$host" ;;
esac

dnl Macro to help find the folder that contains marker file.
dnl Usage: AX_FIND_FOLDER(RESULT_VARIABLE, MARKER_FILE, FOLDERS_LIST)
AC_DEFUN([AX_FIND_FOLDER],[
    for dir in $3 ; do
        if test -f "$dir/$2" ; then
            $1="$dir"
            break;
        fi
    done
])

dnl ==========================================================================
dnl find libxml
dnl ==========================================================================
LIBXML_MIN_VERSION="2.8.0"
LIBXML_INCLUDE_DIR="$COMMON_INCLUDE_DIR /usr/include/libxml2 /usr/local/include/libxml2 /usr/local/libxml2/include"
LIBXML_LIB_DIR="$COMMON_LIB_DIR /usr/local/libxml2/lib"
LIBXML_INCLUDE_MARKER="libxml/xmlversion.h"
LIBXML_SHARED_LIB_MARKER="libxml2$shrext"
LIBXML_STATIC_LIB_MARKER="libxml2.$libext"
LIBXML_LIBS_LIST="-lxml2"
LIBXML_CONFIG="xml2-config"

LIBXML_INCLUDE_PATH=
LIBXML_LIB_PATH=
LIBXML_CONFIG_PATH=
LIBXML_FOUND="no"
AC_ARG_WITH([libxml], [AS_HELP_STRING([--with-libxml@<:@=PFX@:>@],[libxml2 location])])
AC_ARG_WITH([libxml-src], [AS_HELP_STRING([--with-libxml-src@<:@=PFX@:>@],[libxml2 source tree location])])

dnl Priority 0: LibXML2 is disabled: hard error.
if test "z$with_libxml" = "zno" -o "z$with_libxml_src" = "zno"; then
    LIBXML_FOUND="disabled"
fi

dnl Priority 1: User specifies the path to source code
if test "z$LIBXML_FOUND" = "zno" -a "z$with_libxml_src" != "z" -a "z$with_libxml_src" != "zyes" ; then
    AC_MSG_CHECKING(for libxml2 library source tree in "$with_libxml_src" folder)
    if test [ -f "$with_libxml_src/include/$LIBXML_INCLUDE_MARKER" ] -a [ -f "$with_libxml_src/.libs/$LIBXML_SHARED_LIB_MARKER" -o -f "$with_libxml_src/.libs/$LIBXML_STATIC_LIB_MARKER"] ; then
        LIBXML_INCLUDE_PATH="$with_libxml_src/include"
        LIBXML_LIB_PATH="$with_libxml_src/.libs"
        LIBXML_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_libxml_src/include/$LIBXML_INCLUDE_MARKER" or "$with_libxml_src/.libs/$LIBXML_SHARED_LIB_MARKER" or "$with_libxml_src/.libs/$LIBXML_STATIC_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 2: User specifies path to installation
if test "z$LIBXML_FOUND" = "zno" -a "z$with_libxml" != "z" -a "z$with_libxml" != "zyes" ; then
    AC_MSG_CHECKING(for libxml2 library installation in "$with_libxml" folder)
    if test "z$ENABLE_CUSTOM_CONFIGS" = "zyes" -a -f "$with_libxml/bin/$LIBXML_CONFIG" ; then
        LIBXML_CONFIG_PATH="$with_libxml/bin/$LIBXML_CONFIG"
        LIBXML_FOUND="yes"
        AC_MSG_RESULT([yes])
    elif test [ -f "$with_libxml/include/libxml2/$LIBXML_INCLUDE_MARKER" ] -a [ -f "$with_libxml/lib/$LIBXML_SHARED_LIB_MARKER" -o -f "$with_libxml/lib/$LIBXML_STATIC_LIB_MARKER" ] ; then
        LIBXML_INCLUDE_PATH="$with_libxml/include/libxml2"
        LIBXML_LIB_PATH="$with_libxml/lib"
        LIBXML_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_libxml/bin/$LIBXML_CONFIG" tool, or "$with_libxml/include/libxml2/$LIBXML_INCLUDE_MARKER" and/or "$with_libxml/lib/$LIBXML_SHARED_LIB_MARKER" or "$with_libxml/lib/$LIBXML_STATIC_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 3: User sets both CFLAGS and LIBS flags
if test "z$LIBXML_FOUND" = "zno" -a "z$LIBXML_CFLAGS" != "z" -a "z$LIBXML_LIBS" != "z" ; then
    LIBXML_FOUND="yes"
fi

dnl Priority 4: Guess with pkg_config
if test "z$LIBXML_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" ; then
    PKG_CHECK_MODULES(LIBXML, libxml-2.0 >= $LIBXML_MIN_VERSION,
        [LIBXML_FOUND=yes],
        [LIBXML_FOUND=no])
fi

dnl Priority 5: Guess the config tool location
if test "z$LIBXML_FOUND" = "zno" -a "z$ENABLE_CUSTOM_CONFIGS" = "zyes" ; then
    AC_PATH_PROG(LIBXML_CONFIG_PATH, [$LIBXML_CONFIG], [], [$PATH])
    if test "z$LIBXML_CONFIG_PATH" != "z" ; then
        LIBXML_FOUND="yes"
    fi
fi

dnl Priority 6: Guess using a list of folders.
if test "z$LIBXML_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for libxml2 library installation in the typical folders)
    if test "z$LIBXML_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(LIBXML_INCLUDE_PATH, $LIBXML_INCLUDE_MARKER, $LIBXML_INCLUDE_DIR)
    fi
    if test "z$LIBXML_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(LIBXML_LIB_PATH, $LIBXML_SHARED_LIB_MARKER, $LIBXML_LIB_DIR)
    fi
    if test "z$LIBXML_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(LIBXML_LIB_PATH, $LIBXML_STATIC_LIB_MARKER, $LIBXML_LIB_DIR)
    fi
    if test "z$LIBXML_INCLUDE_PATH" != "z" -a "z$LIBXML_LIB_PATH" != "z" ; then
        LIBXML_FOUND="yes"
        AC_MSG_RESULT([yes ("-I$LIBXML_INCLUDE_PATH -L$LIBXML_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi

dnl Priority 7: Just try to compile/link and hope for the best
if test "z$LIBXML_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for libxml2 library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $LIBXML_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $LIBXML_LIBS $LIBXML_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <libxml/xmlversion.h>
        ]],[[
            xmlCheckVersion(0);
        ]])
    ],[
        LIBXML_FOUND=yes
        LIBXML_LIBS="$LIBXML_LIBS $LIBXML_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        LIBXML_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set CFLAGS/LIBS flags
if test "z$LIBXML_FOUND" = "zyes" ; then
    if test "z$LIBXML_CONFIG_PATH" != "z" -a "z$ENABLE_CUSTOM_CONFIGS" = "zyes" ; then
        dnl Get the values using config tool (overwrite CFLAGS/LIBS!)
        if test "z$LIBXML_CFLAGS" = "z" ; then
            LIBXML_CFLAGS="`$LIBXML_CONFIG_PATH --cflags`"
        fi
        if test "z$LIBXML_LIBS" = "z"; then
            LIBXML_LIBS="`$LIBXML_CONFIG_PATH --libs`"
        fi
        LIBXML_CONFIG=$LIBXML_CONFIG_PATH
        LIBXML_FOUND="yes"
    else
        dnl Set flags if INCLUDE_PATH or LIB_PATH are set (do NOT overwrite CFLAGS/LIBS!)
        if test "z$LIBXML_INCLUDE_PATH" != "z" ; then
            LIBXML_CFLAGS="$LIBXML_CFLAGS -I$LIBXML_INCLUDE_PATH"
        fi
        if test "z$LIBXML_LIB_PATH" != "z" ; then
            if test "z$with_gnu_ld" = "zyes" ; then
                LIBXML_LIBS="$LIBXML_LIBS -Wl,-rpath-link -Wl,$LIBXML_LIB_PATH"
            fi
            LIBXML_LIBS="$LIBXML_LIBS -L$LIBXML_LIB_PATH $LIBXML_LIBS_LIST"
        fi
    fi
fi

dnl Verify the version.
AC_MSG_CHECKING(for libxml2 library >= $LIBXML_MIN_VERSION)
if test "z$LIBXML_FOUND" = "zyes" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $LIBXML_CFLAGS"
    minvers=`echo $LIBXML_MIN_VERSION | awk -F. '{ printf "%d", ($1 * 100 + $2) * 100 + $3;}'`
    AC_EGREP_CPP(greater-than-minvers, [
        #include <libxml/xmlversion.h>
        #if LIBXML_VERSION >= $minvers
        greater-than-minvers
        #endif
    ],[
        LIBXML_FOUND=yes
    ],[
        LIBXML_FOUND=no
    ])
    CPPFLAGS=$OLD_CPPFLAGS
fi
AC_MSG_RESULT([$LIBXML_FOUND])

dnl LibXML2 is required so if we didn't find it then it is a fatal error.
if test "z$LIBXML_FOUND" != "zyes" ; then
    AC_MSG_ERROR([libxml2 library >= $LIBXML_MIN_VERSION is required for this version of $XMLSEC_PACKAGE])
fi

dnl Finally set variables
AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LIBS)
AC_SUBST(LIBXML_CONFIG)
AC_SUBST(LIBXML_MIN_VERSION)

dnl ==========================================================================
dnl find libxslt
dnl ==========================================================================
LIBXSLT_MIN_VERSION=1.0.20
LIBXSLT_INCLUDE_DIR="$COMMON_INCLUDE_DIR /usr/local/libxslt/include"
LIBXSLT_LIB_DIR="$COMMON_LIB_DIR /usr/local/libxslt/lib"
LIBXSLT_CONFIG="xslt-config"
LIBXSLT_INCLUDE_MARKER="libxslt/xsltconfig.h"
LIBXSLT_SHARED_LIB_MARKER="libxslt$shrext"
LIBXSLT_STATIC_LIB_MARKER="libxslt.$libext"
LIBXSLT_LIBS_LIST="-lxslt"

XMLSEC_NO_LIBXSLT="1"
LIBXSLT_INCLUDE_PATH=
LIBXSLT_LIB_PATH=
LIBXSLT_CONFIG_PATH=
LIBXSLT_FOUND="no"
AC_ARG_WITH([libxslt], [AS_HELP_STRING([--with-libxslt@<:@=PFX@:>@],[libxslt location])])
AC_ARG_WITH([libxslt-src], [AS_HELP_STRING([--with-libxslt-src@<:@=PFX@:>@],[libxslt source tree location])])

dnl Priority 0: Check if library is not needed
if test "z$with_libxslt" = "zno" -o "z$with_libxslt_src" = "zno" ; then
    LIBXSLT_FOUND="disabled"
fi

dnl Priority 1: User specifies the path to source code
if test "z$LIBXSLT_FOUND" = "zno" -a "z$with_libxslt_src" != "z" -a "z$with_libxslt_src" != "zyes" ; then
    AC_MSG_CHECKING(for libxslt library source tree in "$with_libxslt_src" folder)
    if test [ -f "$with_libxslt_src/$LIBXSLT_INCLUDE_MARKER" ] -a [ -f "$with_libxslt_src/libxslt/.libs/$LIBXSLT_SHARED_LIB_MARKER" -o -f "$with_libxslt_src/libxslt/.libs/$LIBXSLT_STATIC_LIB_MARKER" ] ; then
        LIBXSLT_INCLUDE_PATH="$with_libxslt_src"
        LIBXSLT_LIB_PATH="$with_libxslt_src/libxslt/.libs"
        LIBXSLT_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_libxslt_src/$LIBXSLT_INCLUDE_MARKER" and/or "$with_libxslt_src/libxslt/.libs/$LIBXSLT_SHARED_LIB_MARKER" or "$with_libxslt_src/libxslt/.libs/$LIBXSLT_STATIC_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 2: User specifies path to installation
if test "z$LIBXSLT_FOUND" = "zno" -a "z$with_libxslt" != "z" -a "z$with_libxslt" != "zyes" ; then
    AC_MSG_CHECKING(for libxslt library installation in "$with_libxslt" folder)
    if test "z$ENABLE_CUSTOM_CONFIGS" = "zyes" -a -f "$with_libxslt/bin/$LIBXSLT_CONFIG" ; then
        LIBXSLT_CONFIG_PATH="$with_libxslt/bin/$LIBXSLT_CONFIG"
        LIBXSLT_FOUND="yes"
        AC_MSG_RESULT([yes])
    elif test [ -f "$with_libxslt/include/$LIBXSLT_INCLUDE_MARKER" ] -a [ -f "$with_libxslt/lib/$LIBXSLT_SHARED_LIB_MARKER" -o -f "$with_libxslt/lib/$LIBXSLT_STATIC_LIB_MARKER" ] ; then
        LIBXSLT_INCLUDE_PATH="$with_libxslt/include"
        LIBXSLT_LIB_PATH="$with_libxslt/lib"
        LIBXSLT_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_libxslt/bin/$LIBXSLT_CONFIG" tool, or "$with_libxslt/include/$LIBXSLT_INCLUDE_MARKER" and/or "$with_libxslt/lib/$LIBXSLT_SHARED_LIB_MARKER" or "$with_libxslt/lib/$LIBXSLT_STATIC_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 3: User sets both CFLAGS and LIBS flags
if test "z$LIBXSLT_FOUND" = "zno" -a  "z$LIBXSLT_CFLAGS" != "z" -a "z$LIBXSLT_LIBS" != "z" ; then
    LIBXSLT_FOUND="yes"
fi

dnl Priority 4: Guess with pkg_config
if test "z$LIBXSLT_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" ; then
    PKG_CHECK_MODULES(LIBXSLT, libxslt >= $LIBXSLT_MIN_VERSION,
        [LIBXSLT_FOUND=yes],
        [LIBXSLT_FOUND=no])
fi

dnl Priority 5: Guess the config tool location
if test "z$LIBXSLT_FOUND" = "zno" -a "z$ENABLE_CUSTOM_CONFIGS" = "zyes" ; then
    AC_PATH_PROG(LIBXSLT_CONFIG_PATH, [$LIBXSLT_CONFIG], [], [$PATH])
    if test "z$LIBXSLT_CONFIG_PATH" != "z" ; then
        LIBXSLT_FOUND="yes"
    fi
fi

dnl Priority 6: Guess using a list of folders.
if test "z$LIBXSLT_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for libxslt library installation in the typical folders)
    if test "z$LIBXSLT_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(LIBXSLT_INCLUDE_PATH, $LIBXSLT_INCLUDE_MARKER, $LIBXSLT_INCLUDE_DIR)
    fi
    if test "z$LIBXSLT_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(LIBXSLT_LIB_PATH, $LIBXSLT_SHARED_LIB_MARKER, $LIBXSLT_LIB_DIR)
    fi
    if test "z$LIBXSLT_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(LIBXSLT_LIB_PATH, $LIBXSLT_STATIC_LIB_MARKER, $LIBXSLT_LIB_DIR)
    fi
    if test "z$LIBXSLT_INCLUDE_PATH" != "z" -a "z$LIBXSLT_LIB_PATH" != "z" ; then
        LIBXSLT_FOUND="yes"
        AC_MSG_RESULT([yes ("-I$LIBXSLT_INCLUDE_PATH -L$LIBXSLT_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi

dnl Priority 7: Just try to compile/link and hope for the best
if test "z$LIBXSLT_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for libxslt library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $LIBXML_CFLAGS $LIBXSLT_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $LIBXML_LIBS $LIBXSLT_LIBS $LIBXSLT_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <libxslt/xslt.h>
        ]],[[
            xsltInit();
        ]])
    ],[
        LIBXSLT_FOUND=yes
        LIBXSLT_LIBS="$LIBXSLT_LIBS $LIBXSLT_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        LIBXSLT_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set CFLAGS/LIBS flags
if test "z$LIBXSLT_FOUND" = "zyes" ; then
    if test "z$LIBXSLT_CONFIG_PATH" != "z" -a "z$ENABLE_CUSTOM_CONFIGS" = "zyes" ; then
        dnl Get the values using config tool (overwrite CFLAGS/LIBS!)
        if test "z$LIBXSLT_CFLAGS" = "z" ; then
            LIBXSLT_CFLAGS="`$LIBXSLT_CONFIG_PATH --cflags`"
        fi
        if test "z$LIBXSLT_LIBS" = "z"; then
            LIBXSLT_LIBS="`$LIBXSLT_CONFIG_PATH --libs`"
        fi
        LIBXSLT_CONFIG=$LIBXSLT_CONFIG_PATH
        LIBXSLT_FOUND="yes"
    else
        dnl Set flags if INCLUDE_PATH or LIB_PATH are set (do NOT overwrite CFLAGS/LIBS!)
        if test "z$LIBXSLT_INCLUDE_PATH" != "z" ; then
            LIBXSLT_CFLAGS="$LIBXSLT_CFLAGS -I$LIBXSLT_INCLUDE_PATH"
        fi
        if test "z$LIBXSLT_LIB_PATH" != "z" ; then
            if test "z$with_gnu_ld" = "zyes" ; then
                LIBXSLT_LIBS="$LIBXSLT_LIBS -Wl,-rpath-link -Wl,$LIBXSLT_LIB_PATH"
            fi
            LIBXSLT_LIBS="$LIBXSLT_LIBS -L$LIBXSLT_LIB_PATH $LIBXSLT_LIBS_LIST"
        fi
    fi
fi

dnl Verify the version
AC_MSG_CHECKING(for libxslt library >= $LIBXSLT_MIN_VERSION)
if test "z$LIBXSLT_FOUND" = "zyes" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $LIBXSLT_CFLAGS"
    minvers=`echo $LIBXSLT_MIN_VERSION | awk -F. '{ printf "%d", ($1 * 100 + $2) * 100 + $3;}'`
    AC_EGREP_CPP(greater-than-minvers, [
        #include <libxslt/xsltconfig.h>
        #if LIBXSLT_VERSION >= $minvers
        greater-than-minvers
        #endif
    ],[
        LIBXSLT_FOUND=yes
    ],[
        LIBXSLT_FOUND=no
    ])
    CPPFLAGS=$OLD_CPPFLAGS
fi
AC_MSG_RESULT([$LIBXSLT_FOUND])

dnl Finally set variables
if test "z$LIBXSLT_FOUND" = "zyes" ; then
    XMLSEC_NO_LIBXSLT="0"
    LIBXSLT_PC_FILE_COND="libxslt >= $LIBXSLT_MIN_VERSION"
else
    XMLSEC_NO_LIBXSLT="1"
    LIBXSLT_PC_FILE_COND=""
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_XSLT=1"
fi
AC_SUBST(XMLSEC_NO_LIBXSLT)
AC_SUBST(LIBXSLT_CFLAGS)
AC_SUBST(LIBXSLT_LIBS)
AC_SUBST(LIBXSLT_CONFIG)
AC_SUBST(LIBXSLT_MIN_VERSION)
AC_SUBST(LIBXSLT_PC_FILE_COND)

dnl ==========================================================================
dnl See if we can find a crypto library
dnl ==========================================================================
XMLSEC_CRYPTO_LIST=""
XMLSEC_CRYPTO_DISABLED_LIST=""

dnl ==========================================================================
dnl OpenSSL
dnl ==========================================================================
OPENSSL_MIN_VERSION="1.1.1"
OPENSSL_INCLUDE_DIR="$COMMON_INCLUDE_DIR /usr/local/ssl/include"
OPENSSL_LIB_DIR="$COMMON_LIB_DIR /usr/local/ssl/lib /usr/local/ssl/lib64"
OPENSSL_CRYPTO_LIB="$XMLSEC_PACKAGE-openssl"
OPENSSL_INCLUDE_MARKER="openssl/opensslv.h"
OPENSSL_LIB_SHARED_MARKER="libcrypto$shrext"
OPENSSL_LIB_STATIC_MARKER="libcrypto.a"
OPENSSL_LIBS_LIST="-lcrypto"

XMLSEC_NO_OPENSSL="1"
OPENSSL_VERSION=""
OPENSSL_INCLUDE_PATH=
OPENSSL_LIB_PATH=
OPENSSL_TEST_CONFIG=
OPENSSL_FOUND=no
AC_ARG_WITH([openssl], [AS_HELP_STRING([--with-openssl@<:@=PFX@:>@],[openssl location])])

dnl Priority 0: Check if library is disabled
if test "z$with_openssl" = "zno" ; then
    OPENSSL_FOUND=disabled
fi

dnl Priority 1: User specifies the path to installation
if test "z$OPENSSL_FOUND" = "zno" -a "z$with_openssl" != "z" -a "z$with_openssl" != "zyes" ; then
    AC_MSG_CHECKING(for openssl library installation in "$with_openssl" folder)
    if test -f "$with_openssl/include/$OPENSSL_INCLUDE_MARKER" -a -f "$with_openssl/lib/$OPENSSL_LIB_SHARED_MARKER" ; then
        OPENSSL_INCLUDE_PATH="$with_openssl/include"
        OPENSSL_LIB_PATH="$with_openssl/lib"
        OPENSSL_FOUND="yes"
        AC_MSG_RESULT([yes])
    elif test -f "$with_openssl/include/$OPENSSL_INCLUDE_MARKER" -a -f "$with_openssl/lib64/$OPENSSL_LIB_SHARED_MARKER" ; then
        OPENSSL_INCLUDE_PATH="$with_openssl/include"
        OPENSSL_LIB_PATH="$with_openssl/lib64"
        OPENSSL_FOUND="yes"
        AC_MSG_RESULT([yes])
    elif test -f "$with_openssl/include/$OPENSSL_INCLUDE_MARKER" -a -f "$with_openssl/lib/$OPENSSL_LIB_STATIC_MARKER" ; then
        OPENSSL_INCLUDE_PATH="$with_openssl/include"
        OPENSSL_LIB_PATH="$with_openssl/lib"
        OPENSSL_FOUND="yes"
        AC_MSG_RESULT([yes])
    elif test -f "$with_openssl/include/$OPENSSL_INCLUDE_MARKER" -a -f "$with_openssl/libi64/$OPENSSL_LIB_STATIC_MARKER" ; then
        OPENSSL_INCLUDE_PATH="$with_openssl/include"
        OPENSSL_LIB_PATH="$with_openssl/lib64"
        OPENSSL_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_openssl/include/$OPENSSL_INCLUDE_MARKER" or "$with_openssl/lib(64)/$OPENSSL_LIB_SHARED_MARKER" or "$with_openssl/lib(64)/$OPENSSL_LIB_STATIC_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 2: User sets both CFLAGS and LIBS flags
if test "z$OPENSSL_FOUND" = "zno" -a  "z$OPENSSL_CFLAGS" != "z" -a "z$OPENSSL_LIBS" != "z" ; then
    OPENSSL_FOUND="yes"
fi

dnl Priority 3: Guess with pkg_config
if test "z$OPENSSL_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" ; then
    PKG_CHECK_MODULES(OPENSSL, openssl >= $OPENSSL_MIN_VERSION,
        [OPENSSL_FOUND=yes],
        [OPENSSL_FOUND=no])
fi

dnl Priority 4: Guess using a list of folders (do not overwrite CFLAGS/LIBS flags).
if test "z$OPENSSL_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for openssl library installation in the typical folders)
    if test "z$OPENSSL_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(OPENSSL_INCLUDE_PATH, $OPENSSL_INCLUDE_MARKER, $OPENSSL_INCLUDE_DIR)
    fi
    if test "z$OPENSSL_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(OPENSSL_LIB_PATH, $OPENSSL_LIB_SHARED_MARKER, $OPENSSL_LIB_DIR)
    fi
    if test "z$OPENSSL_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(OPENSSL_LIB_PATH, $OPENSSL_LIB_STATIC_MARKER, $OPENSSL_LIB_DIR)
    fi
    if test "z$OPENSSL_INCLUDE_PATH" != "z" -a "z$OPENSSL_LIB_PATH" != "z" ; then
        OPENSSL_FOUND="yes"
        AC_MSG_RESULT([yes ("-I$OPENSSL_INCLUDE_PATH -L$OPENSSL_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi

dnl Priority 5: Just try to compile/link and hope for the best
if test "z$OPENSSL_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for openssl library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $OPENSSL_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $OPENSSL_LIBS $OPENSSL_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <openssl/crypto.h>
        ]],[[
            OPENSSL_init_crypto(0, NULL);
        ]])
    ],[
        OPENSSL_FOUND=yes
        OPENSSL_LIBS="$OPENSSL_LIBS $OPENSSL_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        OPENSSL_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set flags if INCLUDE_PATH or LIB_PATH are set
if test "z$OPENSSL_FOUND" = "zyes" -a "z$OPENSSL_INCLUDE_PATH" != "z" ; then
    OPENSSL_CFLAGS="$OPENSSL_CFLAGS -I$OPENSSL_INCLUDE_PATH"
fi
if test "z$OPENSSL_FOUND" = "zyes" -a "z$OPENSSL_LIB_PATH" != "z" ; then
    if test -f "$OPENSSL_LIB_PATH/$OPENSSL_LIB_SHARED_MARKER" ; then
        if test "z$with_gnu_ld" = "zyes" ; then
            OPENSSL_LIBS="$OPENSSL_LIBS -Wl,-rpath-link -Wl,$OPENSSL_LIB_PATH"
        fi
    fi
    OPENSSL_LIBS="$OPENSSL_LIBS -L$OPENSSL_LIB_PATH $OPENSSL_LIBS_LIST $OPENSSL_EXTRA_LIBS"
fi

dnl Check the OpenSSL version; if you change this code then you probably want to
dnl change include/xmlsec/openssl/crypto.h as well.
AC_MSG_CHECKING(for openssl library >= $OPENSSL_MIN_VERSION)
if test "z$OPENSSL_FOUND" = "zyes" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $OPENSSL_CFLAGS"
    if test "z$OPENSSL_VERSION" = "z" ; then
        AC_EGREP_CPP(greater-than-minvers, [
            #include <openssl/opensslv.h>
            #if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x30500000L
            greater-than-minvers
            #endif
        ],[
            OPENSSL_VERSION="LibreSSL >= 3.5"
            OPENSSL_LIBS="-Wl,-Bstatic $OPENSSL_LIBS -Wl,-Bdynamic"
            enable_dh=no
        ],[
            OPENSSL_VERSION=""
        ])
    fi

    if test "z$OPENSSL_VERSION" = "z" ; then
        AC_EGREP_CPP(greater-than-minvers, [
            #include <openssl/opensslv.h>
            #include <openssl/crypto.h>
            #if OPENSSL_VERSION_NUMBER >= 0x10100010L
            #ifdef OPENSSL_IS_BORINGSSL
            greater-than-minvers
            #endif
            #endif
        ],[
            OPENSSL_VERSION="BoringSSL >= 1.1.1"
            OPENSSL_LIBS="-Wl,-Bstatic $OPENSSL_LIBS -Wl,-Bdynamic"
            enable_ripemd160=no
            enable_dsa=no
            enable_dh=no
            enable_sha3=no
        ],[
            OPENSSL_VERSION=""
        ])
    fi

    if test "z$OPENSSL_VERSION" = "z" ; then
        AC_EGREP_CPP(greater-than-minvers, [
            #include <openssl/opensslv.h>
            #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            greater-than-minvers
            #endif
        ],[
            OPENSSL_VERSION="3.0.0"
            OPENSSL_TEST_CONFIG="openssl3.cnf"
        ],[
            OPENSSL_VERSION=""
        ])
    fi

    if test "z$OPENSSL_VERSION" = "z" ; then
        AC_EGREP_CPP(greater-than-minvers, [
            #include <openssl/opensslv.h>
            #if OPENSSL_VERSION_NUMBER >= 0x10100010L
            greater-than-minvers
            #endif
        ],[
            OPENSSL_VERSION="1.1.1"
        ],[
            OPENSSL_VERSION=""
        ])
    fi

    CPPFLAGS=$OLD_CPPFLAGS

    if test "z$OPENSSL_VERSION" != "z" ; then
        OPENSSL_FOUND=yes
    else
        OPENSSL_FOUND=no
    fi
fi
if test "z$OPENSSL_FOUND" = "zyes" ; then
    AC_MSG_RESULT([yes (openssl version '$OPENSSL_VERSION')])
else
    AC_MSG_RESULT([$OPENSSL_FOUND])
fi

dnl Finally set all the flags
if test "z$OPENSSL_FOUND" = "zyes" ; then
    XMLSEC_NO_OPENSSL="0"
    OPENSSL_CFLAGS="$OPENSSL_CFLAGS -DXMLSEC_CRYPTO_OPENSSL=1"
    XMLSEC_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST openssl"
else
    XMLSEC_CRYPTO_DISABLED_LIST="$XMLSEC_CRYPTO_DISABLED_LIST openssl"
fi

AM_CONDITIONAL(XMLSEC_NO_OPENSSL, test "z$XMLSEC_NO_OPENSSL" = "z1")
AC_SUBST(XMLSEC_NO_OPENSSL)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)
AC_SUBST(OPENSSL_CRYPTO_LIB)
AC_SUBST(OPENSSL_TEST_CONFIG)
AC_SUBST(OPENSSL_MIN_VERSION)
AC_SUBST(OPENSSL_VERSION)

dnl See if we should build OpenSSL 3+ with engines support
AC_ARG_ENABLE([openssl3_engines],[AS_HELP_STRING([--enable-openssl3-engines],[enable engines support for OpenSSL 3+ (no)])])
if test "z$OPENSSL_VERSION" = "z3.0.0" ; then
    AC_MSG_CHECKING(for OpenSSL 3+ engines support)
    if test "z$enable_openssl3_engines" = "zyes" ; then
        XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_OPENSSL3_ENGINES=1"
        AC_MSG_RESULT([enabled])
    else
        AC_MSG_RESULT([disabled])
    fi
fi

dnl ==========================================================================
dnl See if we can find NSS and NSPR
dnl Allow the use of:
dnl   1.  Mozilla style distribution where all mozilla components (NSS, NSPR
dnl       are just 2 of over 100 components) are under one directory.
dnl       options: [--with-mozilla-ver=<VERSION>]
dnl
dnl       Using the version number, various directories are searched
dnl       for NSS & NSPR
dnl
dnl                      AND / OR
dnl
dnl   2.  separate NSS & NSPR distributions
dnl       options: [--with-nss=<PFX>] [--with-nspr=<PFX>]
dnl
dnl   2 overrides 1
dnl
dnl ==========================================================================

dnl After upgrading min ver >= 3.59, remove the check in include/nss/crypto.h (search for NSS_VMAJOR)
NSS_MIN_VERSION="3.35"
NSPR_MIN_VERSION="4.18.0"
SEAMONKEY_MIN_VERSION="1.0"
MOZILLA_MIN_VERSION="1.4"
NSS_CRYPTO_LIB="$XMLSEC_PACKAGE-nss"
NSPR_PACKAGE=mozilla-nspr
NSS_PACKAGE=mozilla-nss
NSPR_INCLUDE_MARKER="nspr/nspr.h"
NSPR_LIB_MARKER="libnspr4$shrext"
NSPR_LIBS_LIST="-lnspr4 -lplds4 -lplc4"
NSS_INCLUDE_MARKER="nss/nss.h"
NSS_LIB_MARKER="libnss3$shrext"
NSS_LIBS_LIST="-lnss3 -lsmime3 -lnssutil3"

XMLSEC_NO_NSS="1"
NSPR_INCLUDE_PATH=
NSPR_LIB_PATH=
NSS_INCLUDE_PATH=
NSS_LIB_PATH=
NSS_FOUND="no"
NSPR_FOUND="no"
AC_ARG_WITH([nss], [AS_HELP_STRING([--with-nss@<:@=PFX@:>@],[nss location])])
AC_ARG_WITH([nspr], [AS_HELP_STRING([--with-nspr@<:@=PFX@:>@],[nspr location (needed for NSS)])])
AC_ARG_WITH([seamonkey_ver], [AS_HELP_STRING([--with-seamonkey-ver@<:@=VER@:>@],[mozilla version (alt to --with-nss, --with-nspr)])])
AC_ARG_WITH([mozilla_ver], [AS_HELP_STRING([--with-mozilla-ver@<:@=VER@:>@],[mozilla version (alt to --with-nss, --with-nspr)])])

dnl Priority 0: Check if library is disabled
if test "z$with_nss" = "zno" -o "z$with_nspr" = "zno" ; then
    NSS_FOUND="disabled"
    NSPR_FOUND="disabled"
fi

dnl Priority 1: User specifies the path to installation
if test "z$NSPR_FOUND" = "zno" -a "z$with_nspr" != "z" -a "z$with_nspr" != "zyes" ; then
    AC_MSG_CHECKING(for nspr library installation in "$with_nspr" folder)
    if test -f "$with_nspr/include/$NSPR_INCLUDE_MARKER" -a -f "$with_nspr/lib/$NSPR_LIB_MARKER" ; then
        NSPR_INCLUDE_PATH="$with_nspr/include"
        NSPR_LIB_PATH="$with_nspr/lib"
        NSPR_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_nspr/include/$NSPR_INCLUDE_MARKER" and/or "$with_nspr/lib/$NSPR_LIB_MARKER" files don't exist), typo?])
    fi
fi
if test "z$NSS_FOUND" = "zno" -a "z$with_nss" != "z" -a "z$with_nss" != "zyes" ; then
    AC_MSG_CHECKING(for nss library installation in "$with_nss" folder)
    if test -f "$with_nss/include/$NSS_INCLUDE_MARKER" -a -f "$with_nss/lib/$NSS_LIB_MARKER" ; then
        NSS_INCLUDE_PATH="$with_nss/include"
        NSS_LIB_PATH="$with_nss/lib"
        NSS_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_nss/include/$NSS_INCLUDE_MARKER" and/or "$with_nss/lib/$NSS_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 2: User sets both CFLAGS and LIBS flags
if test "z$NSPR_FOUND" = "zno" -a  "z$NSPR_CFLAGS" != "z" -a "z$NSPR_LIBS" != "z" ; then
    NSPR_FOUND="yes"
fi
if test "z$NSS_FOUND" = "zno" -a  "z$NSS_CFLAGS" != "z" -a "z$NSS_LIBS" != "z" ; then
    NSS_FOUND="yes"
fi

dnl Priority 3: Guess with pkg_config
dnl
dnl Mozilla's NSS/NSPR are distributed under different names in different distribution,
dnl we are going to try all options:
dnl     seamonkey-nspr and seamonkey-nss
dnl     mozilla-nspr and mozilla-nss
dnl     xulrunner-nspr and xulrunner-nss
dnl     nspr and nss
if test "z$NSPR_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" -a "z$with_mozilla_ver" = "z" -a "z$with_seamonkey_ver" ; then
    if test "z$NSPR_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSPR, seamonkey-nspr >= $NSPR_MIN_VERSION,
           [NSPR_FOUND=yes NSPR_PACKAGE=seamonkey-nspr],
           [NSPR_FOUND=no])
    fi
    if test "z$NSPR_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSPR, mozilla-nspr >= $MOZILLA_MIN_VERSION,
           [NSPR_FOUND=yes NSPR_PACKAGE=mozilla-nspr],
           [NSPR_FOUND=no])
    fi
    if test "z$NSPR_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSPR, xulrunner-nspr >= $NSPR_MIN_VERSION,
           [NSPR_FOUND=yes NSPR_PACKAGE=xulrunner-nspr],
           [NSPR_FOUND=no])
    fi
    if test "z$NSPR_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSPR, nspr >= $NSPR_MIN_VERSION,
           [NSPR_FOUND=yes NSPR_PACKAGE=nspr],
           [NSPR_FOUND=no])
    fi
fi
if test "z$NSS_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" -a "z$with_mozilla_ver" = "z" -a "z$with_seamonkey_ver" ; then
    if test "z$NSS_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSS, seamonkey-nss >= $SEAMONKEY_MIN_VERSION,
    	   [NSS_FOUND=yes NSS_PACKAGE=seamonkey-nss],
	       [NSS_FOUND=no])
    fi
    if test "z$NSS_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSS, mozilla-nss >= $MOZILLA_MIN_VERSION,
    	   [NSS_FOUND=yes NSS_PACKAGE=mozilla-nss],
	       [NSS_FOUND=no])
    fi
    if test "z$NSS_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSS, xulrunner-nss >= $NSS_MIN_VERSION,
    	   [NSS_FOUND=yes NSS_PACKAGE=xulrunner-nss],
	       [NSS_FOUND=no])
    fi
    if test "z$NSS_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(NSS, nss >= $NSS_MIN_VERSION,
    	   [NSS_FOUND=yes NSS_PACKAGE=nss],
	       [NSS_FOUND=no])
    fi
fi

dnl Priority 4: Guess using a list of folders using mozilla/seamonkey version hints (if any)
if test "z$with_seamonkey_ver" != "z" ; then
    NSS_MOZILLA_NAME=seamonkey-$with_seamonkey_ver
elif test "z$with_mozilla_ver" != "z" ; then
    NSS_MOZILLA_NAME=mozilla-$with_mozilla_ver
else
    NSS_MOZILLA_NAME=mozilla-$MOZILLA_MIN_VERSION
fi
NSS_INCLUDE_DIR="$COMMON_INCLUDE_DIR /usr/include/mozilla /usr/local/include/mozilla /usr/include/$NSS_MOZILLA_NAME /usr/local/include/$NSS_MOZILLA_NAME"
NSS_LIB_DIR="$COMMON_LIB_DIR /usr/lib/$NSS_MOZILLA_NAME /usr/local/lib/$NSS_MOZILLA_NAME"
if test "z$NSPR_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for nspr library installation in the typical folders)
    if test "z$NSPR_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(NSPR_INCLUDE_PATH, $NSPR_INCLUDE_MARKER, $NSS_INCLUDE_DIR)
    fi
    if test "z$NSPR_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(NSPR_LIB_PATH, $NSPR_LIB_MARKER, $NSS_LIB_DIR)
    fi
    if test "z$NSPR_INCLUDE_PATH" != "z" -a "z$NSPR_LIB_PATH" != "z" ; then
        NSPR_FOUND=yes
        AC_MSG_RESULT([yes ("-I$NSPR_INCLUDE_PATH -L$NSPR_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi
if test "z$NSS_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for nss library installation in the typical folders)
    if test "z$NSS_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(NSS_INCLUDE_PATH, $NSS_INCLUDE_MARKER, $NSS_INCLUDE_DIR)
    fi
    if test "z$NSS_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(NSS_LIB_PATH, $NSS_LIB_MARKER, $NSS_LIB_DIR)
    fi
    if test "z$NSS_INCLUDE_PATH" != "z" -a "z$NSS_LIB_PATH" != "z" ; then
        NSS_FOUND=yes
        AC_MSG_RESULT([yes ("-I$NSS_INCLUDE_PATH -L$NSS_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi

dnl Priority 5 (NSPR): Just try to compile/link and hope for the best
if test "z$NSPR_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for nspr library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $NSPR_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $NSPR_LIBS $NSPR_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <stdio.h>
            #include <nspr/nspr.h>
        ]],[[
            printf("v=%s\n", PR_GetVersion());
        ]])
    ],[
        NSPR_FOUND=yes
        NSPR_LIBS="$NSPR_LIBS $NSPR_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        NSPR_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl NSRP: Set flags if INCLUDE_PATH or LIB_PATH are set (need to do it before we try to find NSS)
if test "z$NSPR_FOUND" = "zyes" -a "z$NSPR_INCLUDE_PATH" != "z" ; then
    NSPR_CFLAGS="$NSPR_CFLAGS -I$NSPR_INCLUDE_PATH -I$NSPR_INCLUDE_PATH/nspr"
fi
if test "z$NSPR_FOUND" = "zyes" -a "z$NSPR_LIB_PATH" != "z" ; then
    if test "z$with_gnu_ld" = "zyes" ; then
        NSPR_LIBS="$NSPR_LIBS -Wl,-rpath-link -Wl,$NSPR_LIB_PATH"
    fi
    NSPR_LIBS="$NSPR_LIBS -L$NSPR_LIB_PATH $NSPR_LIBS_LIST"
fi

dnl Priority 5 (NSS): Just try to compile/link and hope for the best
if test "z$NSS_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for nss library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $NSPR_CFLAGS $NSS_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $NSS_LIBS $NSPR_LIBS $NSS_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <stdio.h>
            #include <nss/nss.h>
        ]],[[
            printf("v=%s\n", NSS_GetVersion());
        ]])
    ],[
        NSS_FOUND=yes
        NSS_LIBS="$NSS_LIBS $NSS_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        NSS_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl NSS: Set flags if INCLUDE_PATH or LIB_PATH are set
if test "z$NSS_FOUND" = "zyes" -a "z$NSS_INCLUDE_PATH" != "z" ; then
    NSS_CFLAGS="$NSS_CFLAGS -I$NSS_INCLUDE_PATH -I$NSS_INCLUDE_PATH/nss"
fi
if test "z$NSS_FOUND" = "zyes" -a "z$NSS_LIB_PATH" != "z" ; then
    if test "z$with_gnu_ld" = "zyes" ; then
        NSS_LIBS="$NSS_LIBS -Wl,-rpath-link -Wl,$NSS_LIB_PATH"
    fi
    NSS_LIBS="$NSS_LIBS -L$NSS_LIB_PATH $NSS_LIBS_LIST"
fi

dnl Check NSS and NSPR versions
AC_MSG_CHECKING(for nspr library >= $NSPR_MIN_VERSION)
if test "z$NSPR_FOUND" = "zyes" ; then
    minvers=`echo $NSPR_MIN_VERSION | awk -F. '{ printf "%d", ($1 * 100 + $2) * 100 + $3;}'`
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $NSPR_CFLAGS"
    AC_EGREP_CPP(greater-than-minvers, [
        #include <prinit.h>
        #if ((PR_VMAJOR * 100 + PR_VMINOR) * 100 + PR_VPATCH) >= $minvers
        greater-than-minvers
        #endif
    ],[
        NSPR_FOUND=yes
    ],[
        NSPR_FOUND=no
    ])
    CPPFLAGS="$OLD_CPPFLAGS"
fi
AC_MSG_RESULT([$NSPR_FOUND])

AC_MSG_CHECKING(for nss library >= $NSS_MIN_VERSION)
if test "z$NSS_FOUND" = "zyes" ; then
    minvers=`echo $NSS_MIN_VERSION | awk -F. '{ printf "%d", ($1 * 100 + $2) * 100 + $3;}'`
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $NSPR_CFLAGS $NSS_CFLAGS"
    AC_EGREP_CPP(greater-than-minvers, [
        #include <nss.h>
        #if ((NSS_VMAJOR * 100 + NSS_VMINOR) * 100 + NSS_VPATCH) >= $minvers
        greater-than-minvers
        #endif
    ],[
        NSS_FOUND=yes
    ],[
        NSS_FOUND=no
    ])
    CPPFLAGS="$OLD_CPPFLAGS"
fi
AC_MSG_RESULT([$NSS_FOUND])

dnl Check that we have found both NSS and NSPR
if test "z$NSPR_FOUND" = "zyes" -a "z$NSS_FOUND" = "zyes" ; then
    NSS_CFLAGS="$NSS_CFLAGS $NSPR_CFLAGS"
    NSS_LIBS="$NSS_LIBS $NSPR_LIBS"
elif test "z$NSPR_FOUND" != "zyes" -a "z$NSS_FOUND" = "zyes" ; then
    NSS_FOUND="no"
    AC_MSG_RESULT([NSPR library is required for NSS, ignoring NSS library we have found])
fi

dnl Finally set all the flags
if test "z$NSS_FOUND" = "zyes" ; then
    XMLSEC_NO_NSS="0"
    NSS_CFLAGS="$NSS_CFLAGS -DXMLSEC_CRYPTO_NSS=1"
    XMLSEC_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST nss"
else
    XMLSEC_CRYPTO_DISABLED_LIST="$XMLSEC_CRYPTO_DISABLED_LIST nss"
fi

AM_CONDITIONAL(XMLSEC_NO_NSS, test "z$XMLSEC_NO_NSS" = "z1")
AC_SUBST(XMLSEC_NO_NSS)
AC_SUBST(NSPR_PACKAGE)
AC_SUBST(NSS_PACKAGE)
AC_SUBST(NSS_CFLAGS)
AC_SUBST(NSS_LIBS)
AC_SUBST(NSS_CRYPTO_LIB)
AC_SUBST(NSS_MIN_VERSION)
AC_SUBST(NSPR_MIN_VERSION)
AC_SUBST(MOZILLA_MIN_VERSION)

dnl ==========================================================================
dnl See if we can find GCrypt
dnl ==========================================================================
GCRYPT_MIN_VERSION="1.4.0"
GCRYPT_INCLUDE_DIR="$COMMON_INCLUDE_DIR /usr/local/gcrypt/include"
GCRYPT_LIB_DIR="$COMMON_LIB_DIR /usr/local/gcrypt/lib"
GCRYPT_CONFIG="libgcrypt-config"
GCRYPT_INCLUDE_MARKER="gcrypt.h"
GCRYPT_LIB_MARKER="libgcrypt$shrext"
GCRYPT_CRYPTO_LIB="$XMLSEC_PACKAGE-gcrypt"
GCRYPT_LIBS_LIST="-lgcrypt"

XMLSEC_NO_GCRYPT="1"
GCRYPT_VERSION=
GCRYPT_INCLUDE_PATH=
GCRYPT_LIB_PATH=
GCRYPT_FOUND="no"
AC_ARG_WITH([gcrypt], [AS_HELP_STRING([--with-gcrypt@<:@=PFX@:>@],[gcrypt location])])

dnl Priority 0: Check if library is not needed
if test "z$with_gcrypt" = "zno" ; then
    GCRYPT_FOUND="disabled"
fi

dnl Priority 1: User specifies the path to installation
if test "z$GCRYPT_FOUND" = "zno" -a "z$with_gcrypt" != "z" -a "z$with_gcrypt" != "zyes" ; then
    AC_MSG_CHECKING(for libgcrypt library installation in "$with_gcrypt" folder)
    if test "z$ENABLE_CUSTOM_CONFIGS" = "zyes" -a -f "$with_gcrypt/bin/$GCRYPT_CONFIG" ; then
        GCRYPT_CONFIG_PATH="$with_gcrypt/bin/$GCRYPT_CONFIG"
        GCRYPT_FOUND="yes"
        AC_MSG_RESULT([yes])
    elif test -f "$with_gcrypt/include/$GCRYPT_INCLUDE_MARKER" -a -f "$with_gcrypt/lib/$GCRYPT_LIB_MARKER" ; then
        GCRYPT_INCLUDE_PATH="$with_gcrypt/include"
        GCRYPT_LIB_PATH="$with_gcrypt/lib"
        GCRYPT_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_gcrypt/bin/$GCRYPT_CONFIG" tool, or "$with_gcrypt/include/$GCRYPT_INCLUDE_MARKER" and/or "$with_gcrypt/lib/$GCRYPT_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 2: User sets both CFLAGS and LIBS flags
if test "z$GCRYPT_FOUND" = "zno" -a  "z$GCRYPT_CFLAGS" != "z" -a "z$GCRYPT_LIBS" != "z" ; then
    GCRYPT_FOUND="yes"
fi

dnl Priority 3: Guess with pkg_config
if test "z$GCRYPT_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" ; then
    if test "z$GCRYPT_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(GCRYPT, gcrypt >= $GCRYPT_MIN_VERSION,
            [GCRYPT_FOUND=yes],
            [GCRYPT_FOUND=no])
    fi
    if test "z$GCRYPT_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(GCRYPT, libgcrypt20 >= $GCRYPT_MIN_VERSION,
            [GCRYPT_FOUND=yes],
            [GCRYPT_FOUND=no])
    fi
    if test "z$GCRYPT_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(GCRYPT, libgcrypt11 >= $GCRYPT_MIN_VERSION,
            [GCRYPT_FOUND=yes],
            [GCRYPT_FOUND=no])
    fi
    if test "z$GCRYPT_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(GCRYPT, libgcrypt >= $GCRYPT_MIN_VERSION,
            [GCRYPT_FOUND=yes],
            [GCRYPT_FOUND=no])
    fi
fi

dnl Priority 4: Guess the config tool location
if test "z$GCRYPT_FOUND" = "zno" -a "z$ENABLE_CUSTOM_CONFIGS" = "zyes" ; then
    AC_PATH_PROG(GCRYPT_CONFIG_PATH, [$GCRYPT_CONFIG], [], [$PATH])
    if test "z$GCRYPT_CONFIG_PATH" != "z" ; then
        GCRYPT_FOUND="yes"
    fi
fi

dnl Priority 5: Guess using a list of folders.
if test "z$GCRYPT_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for libgcrypt library installation in the typical folders)
    if test "z$GCRYPT_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(GCRYPT_INCLUDE_PATH, $GCRYPT_INCLUDE_MARKER, $GCRYPT_INCLUDE_DIR)
    fi
    if test "z$GCRYPT_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(GCRYPT_LIB_PATH, $GCRYPT_LIB_MARKER, $GCRYPT_LIB_DIR)
    fi
    if test "z$GCRYPT_INCLUDE_PATH" != "z" -a "z$GCRYPT_LIB_PATH" != "z" ; then
        GCRYPT_FOUND="yes"
        AC_MSG_RESULT([yes ("-I$GCRYPT_INCLUDE_PATH -L$GCRYPT_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi

dnl Priority 6: Just try to compile/link and hope for the best
if test "z$GCRYPT_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for gcrypt library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $GCRYPT_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $GCRYPT_LIBS $GCRYPT_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <gcrypt.h>
        ]],[[
            printf("v=%s\n", gcry_check_version("0"));
        ]])
    ],[
        GCRYPT_FOUND=yes
        GCRYPT_LIBS="$GCRYPT_LIBS $GCRYPT_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        GCRYPT_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set CFLAGS/LIBS flags
if test "z$GCRYPT_FOUND" = "zyes" ; then
    if test "z$GCRYPT_CONFIG_PATH" != "z" -a "z$ENABLE_CUSTOM_CONFIGS" = "zyes" ; then
        dnl Get the values using config tool (overwrite CFLAGS/LIBS!)
        if test "z$GCRYPT_CFLAGS" = "z" ; then
            GCRYPT_CFLAGS="`$GCRYPT_CONFIG_PATH --cflags`"
        fi
        if test "z$GCRYPT_LIBS" = "z"; then
            GCRYPT_LIBS="`$GCRYPT_CONFIG_PATH --libs`"
        fi
        GCRYPT_CONFIG=$GCRYPT_CONFIG_PATH
        GCRYPT_FOUND="yes"
    else
        dnl Set flags if INCLUDE_PATH or LIB_PATH are set (do NOT overwrite CFLAGS/LIBS!)
        if test "z$GCRYPT_INCLUDE_PATH" != "z" ; then
            GCRYPT_CFLAGS="$GCRYPT_CFLAGS -I$GCRYPT_INCLUDE_PATH"
        fi
        if test "z$GCRYPT_LIB_PATH" != "z" ; then
            if test "z$with_gnu_ld" = "zyes" ; then
                GCRYPT_LIBS="$GCRYPT_LIBS -Wl,-rpath-link -Wl,$GCRYPT_LIB_PATH"
            fi
            GCRYPT_LIBS="$GCRYPT_LIBS -L$GCRYPT_LIB_PATH $GCRYPT_LIBS_LIST"
        fi
    fi
fi

dnl Verify the version
AC_MSG_CHECKING(for libgcrypt library >= $GCRYPT_MIN_VERSION)
if test "z$GCRYPT_FOUND" = "zyes" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $GCRYPT_CFLAGS"
    dnl gcrypt uses hex digits for version number
    minvers=`echo $GCRYPT_MIN_VERSION | awk -F. '{ printf "%d", ($1 * 256 + $2) * 256 + $3;}'`
    AC_EGREP_CPP(greater-than-minvers, [
        #include <gcrypt.h>
        #if GCRYPT_VERSION_NUMBER >= $minvers
        greater-than-minvers
        #endif
    ],[
        GCRYPT_FOUND=yes
    ], [
        GCRYPT_FOUND=no
    ])
    CPPFLAGS=$OLD_CPPFLAGS
fi
AC_MSG_RESULT([$GCRYPT_FOUND])

dnl Finally set variables
if test "z$GCRYPT_FOUND" = "zyes" ; then
    XMLSEC_NO_GCRYPT="0"
    GCRYPT_CFLAGS="$GCRYPT_CFLAGS -DXMLSEC_CRYPTO_GCRYPT=1"
    XMLSEC_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST gcrypt"
else
    XMLSEC_CRYPTO_DISABLED_LIST="$XMLSEC_CRYPTO_DISABLED_LIST gcrypt"
fi

AM_CONDITIONAL(XMLSEC_NO_GCRYPT, test "z$XMLSEC_NO_GCRYPT" = "z1")
AC_SUBST(XMLSEC_NO_GCRYPT)
AC_SUBST(GCRYPT_CFLAGS)
AC_SUBST(GCRYPT_LIBS)
AC_SUBST(GCRYPT_CRYPTO_LIB)
AC_SUBST(GCRYPT_MIN_VERSION)

dnl ==========================================================================
dnl See if we can find GnuTLS
dnl ==========================================================================
GNUTLS_MIN_VERSION="3.6.13"
GNUTLS_INCLUDE_DIR="$COMMON_INCLUDE_DIR /usr/local/gnutls/include"
GNUTLS_LIB_DIR="$COMMON_LIB_DIR /usr/local/gnutls/lib"
GNUTLS_INCLUDE_MARKER="gnutls/gnutls.h"
GNUTLS_LIB_MARKER="libgnutls$shrext"
GNUTLS_CRYPTO_LIB="$XMLSEC_PACKAGE-gnutls"
GNUTLS_LIBS_LIST="-lgnutls"

XMLSEC_NO_GNUTLS="1"
GNUTLS_INCLUDE_PATH=
GNUTLS_LIB_PATH=
GNUTLS_FOUND="no"
AC_ARG_WITH([gnutls], [AS_HELP_STRING([--with-gnutls@<:@=PFX@:>@],[gnutls location])])

dnl Priority 0: Check if library is not needed
if test "z$with_gnutls" = "zno" ; then
    GNUTLS_FOUND="disabled"
fi

dnl Priority 1: User specifies the path to installation
if test "z$GNUTLS_FOUND" = "zno" -a "z$with_gnutls" != "z" -a "z$with_gnutls" != "zyes" ; then
    AC_MSG_CHECKING(for libgnutls library installation in "$with_gnutls" folder)
    if test -f "$with_gnutls/include/$GNUTLS_INCLUDE_MARKER" -a -f "$with_gnutls/lib/$GNUTLS_LIB_MARKER" ; then
        GNUTLS_INCLUDE_PATH="$with_gnutls/include"
        GNUTLS_LIB_PATH="$with_gnutls/lib"
        GNUTLS_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_gnutls/bin/$GNUTLS_CONFIG" tool, or "$with_gnutls/include/$GNUTLS_INCLUDE_MARKER" and/or "$with_gnutls/lib/$GNUTLS_LIB_MARKER" files don't exist), typo?])
    fi
fi

dnl Priority 2: User sets both CFLAGS and LIBS flags
if test "z$GNUTLS_FOUND" = "zno" -a  "z$GNUTLS_CFLAGS" != "z" -a "z$GNUTLS_LIBS" != "z" ; then
    GNUTLS_FOUND="yes"
fi

dnl Priority 3: Guess with pkg_config
if test "z$GNUTLS_FOUND" = "zno" -a "z$PKGCONFIG_FOUND" = "zyes" ; then
    if test "z$GNUTLS_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(GNUTLS, gnutls >= $GNUTLS_MIN_VERSION,
            [GNUTLS_FOUND=yes],
            [GNUTLS_FOUND=no])
    fi
    if test "z$GNUTLS_FOUND" = "zno" ; then
        PKG_CHECK_MODULES(GNUTLS, libgnutls >= $GNUTLS_MIN_VERSION,
            [GNUTLS_FOUND=yes],
            [GNUTLS_FOUND=no])
    fi
fi

dnl Priority 4: Guess using a list of folders.
if test "z$GNUTLS_FOUND" = "zno" -a "z$ENABLE_FOLDERS_SEARCH" = "zyes" ; then
    AC_MSG_CHECKING(for libgnutls library installation in the typical folders)
    if test "z$GNUTLS_INCLUDE_PATH" = "z" ; then
        AX_FIND_FOLDER(GNUTLS_INCLUDE_PATH, $GNUTLS_INCLUDE_MARKER, $GNUTLS_INCLUDE_DIR)
    fi
    if test "z$GNUTLS_LIB_PATH" = "z" ; then
        AX_FIND_FOLDER(GNUTLS_LIB_PATH, $GNUTLS_LIB_MARKER, $GNUTLS_LIB_DIR)
    fi
    if test "z$GNUTLS_INCLUDE_PATH" != "z" -a "z$GNUTLS_LIB_PATH" != "z" ; then
        GNUTLS_FOUND="yes"
        AC_MSG_RESULT([yes ("-I$GNUTLS_INCLUDE_PATH -L$GNUTLS_LIB_PATH")])
    else
        AC_MSG_RESULT([not found])
    fi
fi

dnl Priority 5: Just try to compile/link and hope for the best
if test "z$GNUTLS_FOUND" = "zno" ; then
    AC_MSG_CHECKING(for gnutls library installation)
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $GNUTLS_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $GNUTLS_LIBS $GNUTLS_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <gnutls/gnutls.h>
        ]],[[
            gnutls_global_init();
        ]])
    ],[
        GNUTLS_FOUND=yes
        GNUTLS_LIBS="$GNUTLS_LIBS $GNUTLS_LIBS_LIST"
        AC_MSG_RESULT([yes])
    ],[
        GNUTLS_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set CFLAGS/LIBS flags
if test "z$GNUTLS_FOUND" = "zyes" ; then
    dnl Set flags if INCLUDE_PATH or LIB_PATH are set (do NOT overwrite CFLAGS/LIBS!)
    if test "z$GNUTLS_INCLUDE_PATH" != "z" ; then
        GNUTLS_CFLAGS="$GNUTLS_CFLAGS -I$GNUTLS_INCLUDE_PATH"
    fi
    if test "z$GNUTLS_LIB_PATH" != "z" ; then
        if test "z$with_gnu_ld" = "zyes" ; then
            GNUTLS_LIBS="$GNUTLS_LIBS -Wl,-rpath-link -Wl,$GNUTLS_LIB_PATH"
        fi
        GNUTLS_LIBS="$GNUTLS_LIBS -L$GNUTLS_LIB_PATH $GNUTLS_LIBS_LIST"
    fi
fi

dnl Verify the version
AC_MSG_CHECKING(for libgnutls library >= $GNUTLS_MIN_VERSION)
if test "z$GNUTLS_FOUND" = "zyes" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $GNUTLS_CFLAGS"
    dnl gnutls uses hex digits for version number
    minvers=`echo $GNUTLS_MIN_VERSION | awk -F. '{ printf "%d", ($1 * 256 + $2) * 256 + $3;}'`
    AC_EGREP_CPP(greater-than-minvers, [
        #include <gnutls/gnutls.h>
        #if GNUTLS_VERSION_NUMBER >= $minvers
        greater-than-minvers
        #endif
    ],[
        GNUTLS_FOUND=yes
    ],[
        GNUTLS_FOUND=no
    ])
    CPPFLAGS=$OLD_CPPFLAGS
fi
AC_MSG_RESULT([$GNUTLS_FOUND])

dnl Finally set all the flags
if test "z$GNUTLS_FOUND" = "zyes" ; then
    XMLSEC_NO_GNUTLS="0"
    GNUTLS_CFLAGS="$GNUTLS_CFLAGS -DXMLSEC_CRYPTO_GNUTLS=1"
    XMLSEC_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST gnutls"
else
    XMLSEC_CRYPTO_DISABLED_LIST="$XMLSEC_CRYPTO_DISABLED_LIST gnutls"
fi

AM_CONDITIONAL(XMLSEC_NO_GNUTLS, test "z$XMLSEC_NO_GNUTLS" = "z1")
AC_SUBST(XMLSEC_NO_GNUTLS)
AC_SUBST(GNUTLS_CFLAGS)
AC_SUBST(GNUTLS_LIBS)
AC_SUBST(GNUTLS_CRYPTO_LIB)
AC_SUBST(GNUTLS_MIN_VERSION)


dnl ==========================================================================
dnl See if we can find MSCrypto
dnl ==========================================================================
MSCRYPTO_CRYPTO_LIB="$XMLSEC_PACKAGE-mscrypto"
case $host in
*-w64-mingw*)
    MSCRYPTO_XMLSEC_DEFINES=
    MSCRYPTO_LIBS_LIST="-lcrypt32"
    ;;
*-*-mingw*)
    dnl use own def-file and header as mingw.org crypt32
    dnl is limited (library and header)
    MSCRYPTO_XMLSEC_DEFINES="-DXMLSEC_CUSTOM_CRYPT32=1"
    MSCRYPTO_LIBS_LIST="-Wl,$(srcdir)/mingw-crypt32.def"
    ;;
*)
    MSCRYPTO_XMLSEC_DEFINES=
    MSCRYPTO_LIBS_LIST="-lcrypt32"
    ;;
esac

XMLSEC_NO_MSCRYPTO="1"
MSCRYPTO_FOUND="no"
AC_ARG_ENABLE([mscrypto], [AS_HELP_STRING([--enable-mscrypto],[enable mscrypto (no)])])
AC_MSG_CHECKING(for mscrypto)

dnl Priority 0: Check if library is not needed
if test "z$enable_mscrypto" != "zyes" ; then
    MSCRYPTO_FOUND="disabled"
    AC_MSG_RESULT([disabled])
fi

dnl Priority 1: User sets both CFLAGS and LIBS flags
if test "z$MSCRYPTO_FOUND" = "zno" -a "z$MSCRYPTO_CFLAGS" != "z" -a "z$MSCRYPTO_LIBS" != "z" ; then
    MSCRYPTO_FOUND=yes
    AC_MSG_RESULT([yes])
fi

dnl Priority 2: Just try to compile/link and hope for the best
if test "z$MSCRYPTO_FOUND" = "zno" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $MSCRYPTO_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $MSCRYPTO_LIBS $MSCRYPTO_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <windows.h>
            #include <wincrypt.h>
        ]],[[
            CertOpenStore(0,0,0,0,0);
        ]])
    ],[
        MSCRYPTO_FOUND=yes
        AC_MSG_RESULT([yes])
    ],[
        MSCRYPTO_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set CFLAGS/LIBS flags, do not change CFLAGS/LIBS if both are set
if test "z$MSCRYPTO_FOUND" = "zyes" ; then
    if test "z$MSCRYPTO_CFLAGS" = "z" -o "z$MSCRYPTO_LIBS" = "z" ; then
        XMLSEC_DEFINES="$XMLSEC_DEFINES $MSCRYPTO_XMLSEC_DEFINES"
        MSCRYPTO_LIBS="$MSCRYPTO_LIBS $MSCRYPTO_LIBS_LIST"
    fi
fi

dnl Finally set all the flags
if test "z$MSCRYPTO_FOUND" = "zyes" ; then
    XMLSEC_NO_MSCRYPTO="0"
    MSCRYPTO_CFLAGS="$MSCRYPTO_CFLAGS -DXMLSEC_CRYPTO_MSCRYPTO=1"
    XMLSEC_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST mscrypto"
else
    XMLSEC_CRYPTO_DISABLED_LIST="$XMLSEC_CRYPTO_DISABLED_LIST mscrypto"
fi

AM_CONDITIONAL(XMLSEC_NO_MSCRYPTO, [test "z$XMLSEC_NO_MSCRYPTO" = "z1"])
AC_SUBST(XMLSEC_NO_MSCRYPTO)
AC_SUBST(MSCRYPTO_CFLAGS)
AC_SUBST(MSCRYPTO_LIBS)
AC_SUBST(MSCRYPTO_CRYPTO_LIB)


dnl ==========================================================================
dnl See if we can find MSCng
dnl ==========================================================================
MSCNG_CRYPTO_LIB="$XMLSEC_PACKAGE-mscng"
dnl This is tested on w64-mingw only so far.
MSCNG_XMLSEC_DEFINES=
MSCNG_LIBS_LIST="-lcrypt32 -lbcrypt -lncrypt"

XMLSEC_NO_MSCNG="1"
MSCNG_FOUND="no"
AC_ARG_ENABLE([mscng], [AS_HELP_STRING([--enable-mscng],[enable mscng (no)])])
AC_MSG_CHECKING(for mscng)

dnl Priority 0: Check if library is not needed
if test "z$enable_mscng" != "zyes" ; then
    MSCNG_FOUND="disabled"
    AC_MSG_RESULT([disabled])
fi

dnl Priority 1: User sets both CFLAGS and LIBS flags
if test "z$MSCNG_FOUND" = "zno" -a "z$MSCNG_CFLAGS" != "z" -a "z$MSCNG_LIBS" != "z" ; then
    MSCNG_FOUND=yes
    AC_MSG_RESULT([yes])
fi

dnl Priority 2: Just try to compile/link and hope for the best
if test "z$MSCNG_FOUND" = "zno" ; then
    OLD_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $MSCNG_CFLAGS"
    OLD_LIBS=$LIBS
    LIBS="$LIBS $MSCNG_LIBS $MSCNG_LIBS_LIST"
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([[
            #include <windows.h>
            #include <wincrypt.h>
        ]],[[
            BCRYPT_ALG_HANDLE hAlg;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        ]])
    ],[
        MSCNG_FOUND=yes
        AC_MSG_RESULT([yes])
    ],[
        MSCNG_FOUND=no
        AC_MSG_RESULT([not found])
    ])
    CPPFLAGS=$OLD_CPPFLAGS
    LIBS=$OLD_LIBS
fi

dnl Set CFLAGS/LIBS flags, do not change CFLAGS/LIBS if both are set
if test "z$MSCNG_FOUND" = "zyes" ; then
    if test "z$MSCNG_CFLAGS" = "z" -o "z$MSCNG_LIBS" = "z" ; then
        XMLSEC_DEFINES="$XMLSEC_DEFINES $MSCNG_XMLSEC_DEFINES"
        MSCNG_LIBS="$MSCNG_LIBS $MSCNG_LIBS_LIST"
    fi
fi

dnl Finally set all the flags
if test "z$MSCNG_FOUND" = "zyes" ; then
    XMLSEC_NO_MSCNG="0"
    MSCNG_CFLAGS="$MSCNG_CFLAGS -DXMLSEC_CRYPTO_MSCNG=1"
    XMLSEC_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST mscng"
else
    XMLSEC_CRYPTO_DISABLED_LIST="$XMLSEC_CRYPTO_DISABLED_LIST mscng"
fi

AM_CONDITIONAL(XMLSEC_NO_MSCNG, [test "z$XMLSEC_NO_MSCNG" = "z1"])
AC_SUBST(XMLSEC_NO_MSCNG)
AC_SUBST(MSCNG_CFLAGS)
AC_SUBST(MSCNG_LIBS)
AC_SUBST(MSCNG_CRYPTO_LIB)


dnl ==========================================================================
dnl Figure out the default crypt - the first crypto library wins
dnl ==========================================================================
XMLSEC_DEFAULT_CRYPTO=""
XMLSEC_CRYPTO_LIB=""
XMLSEC_CRYPTO_CFLAGS=""
XMLSEC_CRYPTO_LIBS=""
AC_MSG_CHECKING(for default crypto library)
AC_ARG_WITH([default_crypto], [AS_HELP_STRING([--with-default-crypto=name],[default crypto name])])

# check the argument
case "z$with_default_crypto" in
    'zmscng')
        if test "z$XMLSEC_NO_MSCNG" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="mscng"
        else
            AC_MSG_ERROR('$with_default_crypto' is specified as default crypto library but it is not configured or found)
        fi
        ;;
    'zopenssl')
        if test "z$XMLSEC_NO_OPENSSL" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="openssl"
        else
            AC_MSG_ERROR('$with_default_crypto' is specified as default crypto library but it is not configured or found)
        fi
        ;;
    'znss')
        if test "z$XMLSEC_NO_NSS" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="nss"
        else
            AC_MSG_ERROR('$with_default_crypto' is specified as default crypto library but it is not configured or found)
        fi
        ;;
    'zgnutls')
        if test "z$XMLSEC_NO_GNUTLS" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="gnutls"
        else
            AC_MSG_ERROR('$with_default_crypto' is specified as default crypto library but it is not configured or found)
        fi
        ;;
    'zmscrypto')
        if test "z$XMLSEC_NO_MSCRYPTO" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="mscrypto"
        else
            AC_MSG_ERROR('$with_default_crypto' is specified as default crypto library but it is not configured or found)
        fi
        ;;
    'zgcrypt')
        if test "z$XMLSEC_NO_GCRYPT" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="gcrypt"
        else
            AC_MSG_ERROR('$with_default_crypto' is specified as default crypto library but it is not configured or found)
        fi
        ;;
    'z')
        dnl The first crypto library wins:
        dnl    - if on Windows and MSCng is available -- use it
        dnl    - Then choose one with most supported features: OpenSSL > NSS > GnuTLS
        dnl    - MSCrypto and GCrypt are in maintanance mode and go last
        if test "z$XMLSEC_NO_MSCNG" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="mscng"
        elif test "z$XMLSEC_NO_OPENSSL" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="openssl"
        elif test "z$XMLSEC_NO_NSS" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="nss"
        elif test "z$XMLSEC_NO_GNUTLS" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="gnutls"
        elif test "z$XMLSEC_NO_MSCRYPTO" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="mscrypto"
        elif test "z$XMLSEC_NO_GCRYPT" != "z1" ; then
            XMLSEC_DEFAULT_CRYPTO="gcrypt"
        else
            AC_MSG_ERROR(At least one crypto library should exist for $XMLSEC_PACKAGE)
        fi
        ;;
    *)
        AC_MSG_ERROR(The value '$with_default_crypto' is not a recongnized crypto library name)
        ;;
esac

dnl Set the flags for default crypto lib
case "$XMLSEC_DEFAULT_CRYPTO" in
    'mscrypto')
        XMLSEC_CRYPTO_LIB="$MSCRYPTO_CRYPTO_LIB"
        XMLSEC_CRYPTO_CFLAGS="$MSCRYPTO_CFLAGS"
        XMLSEC_CRYPTO_LIBS="$MSCRYPTO_LIBS"
        ;;
    'mscng')
        XMLSEC_CRYPTO_LIB="$MSCNG_CRYPTO_LIB"
        XMLSEC_CRYPTO_CFLAGS="$MSCNG_CFLAGS"
        XMLSEC_CRYPTO_LIBS="$MSCNG_LIBS"
        ;;
    'openssl')
        XMLSEC_CRYPTO_LIB="$OPENSSL_CRYPTO_LIB"
        XMLSEC_CRYPTO_CFLAGS="$OPENSSL_CFLAGS"
        XMLSEC_CRYPTO_LIBS="$OPENSSL_LIBS"
        ;;
    'nss')
        XMLSEC_CRYPTO_LIB="$NSS_CRYPTO_LIB"
        XMLSEC_CRYPTO_CFLAGS="$NSS_CFLAGS"
        XMLSEC_CRYPTO_LIBS="$NSS_LIBS"
        ;;
    'gnutls')
        XMLSEC_CRYPTO_LIB="$GNUTLS_CRYPTO_LIB"
        XMLSEC_CRYPTO_CFLAGS="$GNUTLS_CFLAGS"
        XMLSEC_CRYPTO_LIBS="$GNUTLS_LIBS"
        ;;
    'gcrypt')
        XMLSEC_CRYPTO_LIB="$GCRYPT_CRYPTO_LIB"
        XMLSEC_CRYPTO_CFLAGS="$GCRYPT_CFLAGS"
        XMLSEC_CRYPTO_LIBS="$GCRYPT_LIBS"
        ;;
    *)
        AC_MSG_ERROR(The value '$XMLSEC_DEFAULT_CRYPTO' is not a recongnized crypto library name)
        ;;
esac
AC_MSG_RESULT([yes ("$XMLSEC_DEFAULT_CRYPTO")])

dnl ==========================================================================
dnl Do we need to use Unicode (Windows build only)
dnl ==========================================================================
if test "z$build_on_windows" = "zyes" ; then
    AC_MSG_CHECKING(for Unicode support)
    AC_ARG_ENABLE([unicode], [AS_HELP_STRING([--enable-unicode],[enable Unicode support on Windows (yes)])])
    if test "z$enable_unicode" = "zyes" -o "z$enable_unicode" = "ztrue" ; then
        XMLSEC_DEFINES="$XMLSEC_DEFINES -DUNICODE=1 -D_UNICODE=1"
        case "${host}" in
         *-*-mingw*)
	        XMLSEC_EXTRA_LDFLAGS="$XMLSEC_EXTRA_LDFLAGS -municode"
	        XMLSEC_CRYPTO_EXTRA_LDFLAGS="$XMLSEC_CRYPTO_EXTRA_LDFLAGS -municode"
	        ;;
        *)
            ;;
        esac
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
    fi
fi

dnl ==========================================================================
dnl See do we need files support
dnl ==========================================================================
AC_MSG_CHECKING(for files support)
AC_ARG_ENABLE([files], [AS_HELP_STRING([--enable-files],[enable files support (yes)])])
if test "z$enable_files" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_FILES=1"
    XMLSEC_NO_FILES="1"
    AC_MSG_RESULT([no (tests will be broken!)])
else
    XMLSEC_NO_FILES="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_FILES, test "z$XMLSEC_NO_FILES" = "z1")
AC_SUBST(XMLSEC_NO_FILES)

dnl ==========================================================================
dnl See do we need FTP support
dnl ==========================================================================
AC_MSG_CHECKING(for FTP support)
AC_ARG_ENABLE([ftp], [AS_HELP_STRING([--enable-ftp],[enable FTP support (no, deprecated)])])
if test "z$enable_ftp" = "zyes" ; then
    XMLSEC_NO_FTP="0"
    AC_MSG_RESULT([yes (deprecated)])
else
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_FTP=1"
    XMLSEC_NO_FTP="1"
    AC_MSG_RESULT([disabled])
fi
AM_CONDITIONAL(XMLSEC_NO_FTP, test "z$XMLSEC_NO_FTP" = "z1")
AC_SUBST(XMLSEC_NO_FTP)

dnl ==========================================================================
dnl See do we need HTTP support
dnl ==========================================================================
AC_MSG_CHECKING(for HTTP support)
AC_ARG_ENABLE([http], [AS_HELP_STRING([--enable-http],[enable HTTP support (yes)])])
if test "z$enable_http" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_HTTP=1"
    XMLSEC_NO_HTTP="1"
    AC_MSG_RESULT([no])
else
    XMLSEC_NO_HTTP="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_HTTP, test "z$XMLSEC_NO_HTTP" = "z1")
AC_SUBST(XMLSEC_NO_HTTP)

dnl ==========================================================================
dnl See do we need MD5 support
dnl ==========================================================================
AC_MSG_CHECKING(for MD5 support)
AC_ARG_ENABLE([md5], [AS_HELP_STRING([--enable-md5],[enable MD5 support (no, deprecated)])])
if test "z$enable_md5" = "zyes" ; then
    XMLSEC_NO_MD5="0"
    AC_MSG_RESULT([yes (deprecated)])
else
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_MD5=1"
    XMLSEC_NO_MD5="1"
    AC_MSG_RESULT([disabled])
fi
AM_CONDITIONAL(XMLSEC_NO_MD5, test "z$XMLSEC_NO_MD5" = "z1")
AC_SUBST(XMLSEC_NO_MD5)

dnl ==========================================================================
dnl See do we need RIPEMD-160 support
dnl ==========================================================================
AC_MSG_CHECKING(for RIPEMD-160 support)
AC_ARG_ENABLE([ripemd160], [AS_HELP_STRING([--enable-ripemd160],[enable RIPEMD-160 support (yes)])])
if test "z$enable_ripemd160" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_RIPEMD160=1"
    XMLSEC_NO_RIPEMD160="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_RIPEMD160="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_RIPEMD160, test "z$XMLSEC_NO_RIPEMD160" = "z1")
AC_SUBST(XMLSEC_NO_RIPEMD160)

dnl ==========================================================================
dnl See do we need SHA1 support
dnl ==========================================================================
AC_MSG_CHECKING(for SHA1 support)
AC_ARG_ENABLE([sha1], [AS_HELP_STRING([--enable-sha1],[enable SHA1 support (yes, use discouraged)])])
if test "z$enable_sha1" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SHA1=1"
    XMLSEC_NO_SHA1="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_SHA1="0"
    AC_MSG_RESULT([yes (use discouraged)])
fi
AM_CONDITIONAL(XMLSEC_NO_SHA1, test "z$XMLSEC_NO_SHA1" = "z1")
AC_SUBST(XMLSEC_NO_SHA1)

dnl ==========================================================================
dnl See do we need SHA224 support
dnl ==========================================================================
AC_MSG_CHECKING(for SHA224 support)
AC_ARG_ENABLE([sha224], [AS_HELP_STRING([--enable-sha224],[enable SHA224 support (yes)])])
if test "z$enable_sha224" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SHA224=1"
    XMLSEC_NO_SHA224="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_SHA224="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_SHA224, test "z$XMLSEC_NO_SHA224" = "z1")
AC_SUBST(XMLSEC_NO_SHA224)

dnl ==========================================================================
dnl See do we need SHA256 support
dnl ==========================================================================
AC_MSG_CHECKING(for SHA256 support)
AC_ARG_ENABLE([sha256], [AS_HELP_STRING([--enable-sha256],[enable SHA256 support (yes)])])
if test "z$enable_sha256" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SHA256=1"
    XMLSEC_NO_SHA256="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_SHA256="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_SHA256, test "z$XMLSEC_NO_SHA256" = "z1")
AC_SUBST(XMLSEC_NO_SHA256)

dnl ==========================================================================
dnl See do we need SHA384 support
dnl ==========================================================================
AC_MSG_CHECKING(for SHA384 support)
AC_ARG_ENABLE([sha384], [AS_HELP_STRING([--enable-sha384],[enable SHA384 support (yes)])])
if test "z$enable_sha384" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SHA384=1"
    XMLSEC_NO_SHA384="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_SHA384="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_SHA384, test "z$XMLSEC_NO_SHA384" = "z1")
AC_SUBST(XMLSEC_NO_SHA384)

dnl ==========================================================================
dnl See do we need SHA512 support
dnl ==========================================================================
AC_MSG_CHECKING(for SHA512 support)
AC_ARG_ENABLE([sha512], [AS_HELP_STRING([--enable-sha512],[enable SHA512 support (yes)])])
if test "z$enable_sha512" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SHA512=1"
    XMLSEC_NO_SHA512="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_SHA512="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_SHA512, test "z$XMLSEC_NO_SHA512" = "z1")
AC_SUBST(XMLSEC_NO_SHA512)

dnl ==========================================================================
dnl See do we need SHA3 support
dnl ==========================================================================
AC_MSG_CHECKING(for SHA3 support)
AC_ARG_ENABLE([sha3], [AS_HELP_STRING([--enable-sha3],[enable SHA3 support (yes)])])
if test "z$enable_sha3" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SHA3=1"
    XMLSEC_NO_SHA3="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_SHA3="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_SHA3, test "z$XMLSEC_NO_SHA3" = "z1")
AC_SUBST(XMLSEC_NO_SHA3)

dnl ==========================================================================
dnl See do we need HMAC support
dnl ==========================================================================
AC_MSG_CHECKING(for HMAC support)
AC_ARG_ENABLE([hmac], [AS_HELP_STRING([--enable-hmac],[enable HMAC support (yes)])])
if test "z$enable_hmac" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_HMAC=1"
    XMLSEC_NO_HMAC="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_HMAC="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_HMAC, test "z$XMLSEC_NO_HMAC" = "z1")
AC_SUBST(XMLSEC_NO_HMAC)

dnl ==========================================================================
dnl See do we need DH support
dnl ==========================================================================
AC_MSG_CHECKING(for DH support)
AC_ARG_ENABLE([dh], [AS_HELP_STRING([--enable-dh],[enable DH support (yes)])])
if test "z$enable_dh" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_DH=1"
    XMLSEC_NO_DH="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_DH="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_DH, test "z$XMLSEC_NO_DH" = "z1")
AC_SUBST(XMLSEC_NO_DH)


dnl ==========================================================================
dnl See do we need DSA support
dnl ==========================================================================
AC_MSG_CHECKING(for DSA support)
AC_ARG_ENABLE([dsa], [AS_HELP_STRING([--enable-dsa],[enable DSA support (yes)])])
if test "z$enable_dsa" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_DSA=1"
    XMLSEC_NO_DSA="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_DSA="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_DSA, test "z$XMLSEC_NO_DSA" = "z1")
AC_SUBST(XMLSEC_NO_DSA)

dnl ==========================================================================
dnl See do we need MD5 support
dnl ==========================================================================
AC_MSG_CHECKING(for MD5 support)
AC_ARG_ENABLE([md5], [AS_HELP_STRING([--enable-md5],[enable MD5 support (no, deprecated)])])
if test "z$enable_md5" = "zyes" ; then
    XMLSEC_NO_MD5="0"
    AC_MSG_RESULT([yes (deprecated)])
else
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_MD5=1"
    XMLSEC_NO_MD5="1"
    AC_MSG_RESULT([disabled])
fi
AM_CONDITIONAL(XMLSEC_NO_MD5, test "z$XMLSEC_NO_MD5" = "z1")
AC_SUBST(XMLSEC_NO_MD5)

dnl ==========================================================================
dnl See do we need RSA support
dnl ==========================================================================
AC_MSG_CHECKING(for RSA support)
AC_ARG_ENABLE([rsa], [AS_HELP_STRING([--enable-rsa],[enable RSA support (yes)])])
if test "z$enable_rsa" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_RSA=1"
    XMLSEC_NO_RSA="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_RSA="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_RSA, test "z$XMLSEC_NO_RSA" = "z1")
AC_SUBST(XMLSEC_NO_RSA)


dnl ==========================================================================
dnl See do we need EC (Eliptic Curve) support
dnl ==========================================================================
AC_MSG_CHECKING(for Eliptic Curve support)
AC_ARG_ENABLE([ec], [AS_HELP_STRING([--enable-ec],[enable EC support (yes)])])
if test "z$enable_ec" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_EC=1"
    XMLSEC_NO_EC="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_EC="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_EC, test "z$XMLSEC_NO_EC" = "z1")
AC_SUBST(XMLSEC_NO_EC)

dnl ==========================================================================
dnl See do we need x509 support
dnl ==========================================================================
AC_MSG_CHECKING(for x509 support)
AC_ARG_ENABLE([x509], [AS_HELP_STRING([--enable-x509],[enable x509 support (yes)])])
if test "z$enable_x509" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_X509=1"
    XMLSEC_NO_X509="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_X509="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_X509, test "z$XMLSEC_NO_X509" = "z1")
AC_SUBST(XMLSEC_NO_X509)

dnl ==========================================================================
dnl See do we need DES support
dnl ==========================================================================
AC_MSG_CHECKING(for DES support)
AC_ARG_ENABLE([des], [AS_HELP_STRING([--enable-des],[enable DES support (yes, deprecated)])])
if test "z$enable_des" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_DES=1"
    XMLSEC_NO_DES="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_DES="0"
    AC_MSG_RESULT([yes (deprecated)])
fi
AM_CONDITIONAL(XMLSEC_NO_DES, test "z$XMLSEC_NO_DES" = "z1")
AC_SUBST(XMLSEC_NO_DES)

dnl ==========================================================================
dnl See do we need AES support
dnl ==========================================================================
AC_MSG_CHECKING(for AES support)
AC_ARG_ENABLE([aes], [AS_HELP_STRING([--enable-aes],[enable AES support])])
if test "z$enable_aes" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_AES=1"
    XMLSEC_NO_AES="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_AES="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_AES, test "z$XMLSEC_NO_AES" = "z1")
AC_SUBST(XMLSEC_NO_AES)

dnl ==========================================================================
dnl See do we need ConcatKDF support
dnl ==========================================================================
AC_MSG_CHECKING(for ConcatKDF support)
AC_ARG_ENABLE([concatkdf], [AS_HELP_STRING([--enable-concatkdf],[enable ConcatKDF support (yes)])])
if test "z$enable_concatkdf" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_CONCATKDF=1"
    XMLSEC_NO_CONCATKDF="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_CONCATKDF="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_CONCATKDF, test "z$XMLSEC_NO_CONCATKDF" = "z1")
AC_SUBST(XMLSEC_NO_CONCATKDF)

dnl ==========================================================================
dnl See do we need PBKDF2 support
dnl ==========================================================================
AC_MSG_CHECKING(for PBKDF2 support)
AC_ARG_ENABLE([pbkdf2], [AS_HELP_STRING([--enable-pbkdf2],[enable PBKDF2 support (yes)])])
if test "z$enable_pbkdf2" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_PBKDF2=1"
    XMLSEC_NO_PBKDF2="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_PBKDF2="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_PBKDF2, test "z$XMLSEC_NO_PBKDF2" = "z1")
AC_SUBST(XMLSEC_NO_PBKDF2)

dnl ==========================================================================
dnl See do we need GOST 2001 support
dnl ==========================================================================
AC_MSG_CHECKING(for GOST 2001 support)
AC_ARG_ENABLE([gost], [AS_HELP_STRING([--enable-gost],[enable GOST-2001 support (no)])])
if test "z$enable_gost" != "zyes" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_GOST=1"
    XMLSEC_NO_GOST="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_GOST="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_GOST, test "z$XMLSEC_NO_GOST" = "z1")
AC_SUBST(XMLSEC_NO_GOST)

dnl ==========================================================================
dnl See do we need GOST 2012 support
dnl ==========================================================================
AC_MSG_CHECKING(for GOST 2012 support)
AC_ARG_ENABLE([gost2012], [AS_HELP_STRING([--enable-gost2012],[enable GOST-2012 support (no)])])
if test "z$enable_gost2012" != "zyes" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_GOST2012=1"
    XMLSEC_NO_GOST2012="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_GOST2012="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_GOST2012, test "z$XMLSEC_NO_GOST2012" = "z1")
AC_SUBST(XMLSEC_NO_GOST2012)


dnl ==========================================================================
dnl See do we need XMLDSig support
dnl ==========================================================================
AC_MSG_CHECKING(for XMLDSig support)
AC_ARG_ENABLE([xmldsig], [AS_HELP_STRING([--enable-xmldsig],[enable XMLDSig support (yes)])])
if test "z$enable_xmldsig" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_XMLDSIG=1"
    XMLSEC_NO_XMLDSIG="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_XMLDSIG="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_XMLDSIG, test "z$XMLSEC_NO_XMLDSIG" = "z1")
AC_SUBST(XMLSEC_NO_XMLDSIG)

dnl ==========================================================================
dnl See do we need XMLEnc support
dnl ==========================================================================
AC_MSG_CHECKING(for XMLEnc support)
AC_ARG_ENABLE([xmlenc], [AS_HELP_STRING([--enable-xmlenc],[enable XMLEnc support (yes)])])
if test "z$enable_xmlenc" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_XMLENC=1"
    XMLSEC_NO_XMLENC="1"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_NO_XMLENC="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_XMLENC, test "z$XMLSEC_NO_XMLENC" = "z1")
AC_SUBST(XMLSEC_NO_XMLENC)

dnl ==========================================================================
dnl See do we need mans
dnl ==========================================================================
AC_MSG_CHECKING(for mans)
AC_ARG_ENABLE([mans], [AS_HELP_STRING([--enable-mans],[enable manual pages (yes)])])
if test "z$enable_mans" = "zno" ; then
    XMLSEC_MANS="0"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_MANS="1"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_MANS, test "z$XMLSEC_MANS" = "z1")
AC_SUBST(XMLSEC_MANS)

dnl ==========================================================================
dnl See do we need docs
dnl ==========================================================================
AC_MSG_CHECKING(for docs)
AC_ARG_ENABLE([docs], [AS_HELP_STRING([--enable-docs],[enable documentation (yes)])])
if test "z$enable_docs" = "zno" ; then
    XMLSEC_DOCS="0"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_DOCS="1"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_DOCS, test "z$XMLSEC_DOCS" = "z1")
AC_SUBST(XMLSEC_DOCS)

dnl ==========================================================================
dnl See if we need apps
dnl ==========================================================================
AC_MSG_CHECKING(for apps)
AC_ARG_ENABLE([apps], [AS_HELP_STRING([--enable-apps],[enable applications (yes)])])
if test "z$enable_apps" = "zno" ; then
    XMLSEC_APPS="0"
    AC_MSG_RESULT([disabled])
else
    XMLSEC_APPS="1"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_APPS, test "z$XMLSEC_APPS" = "z1")
AC_SUBST(XMLSEC_APPS)

dnl ==========================================================================
dnl Static linking (implies enable_crypto_dl="no")
dnl ==========================================================================
XMLSEC_STATIC_BINARIES=""
AC_MSG_CHECKING(for static linking)
AC_ARG_ENABLE([static_linking], [AS_HELP_STRING([--enable-static-linking],[enable static linking (no)])])
if test "z$enable_static_linking" = "zyes" -o "z$enable_static_linking" = "ztrue" ; then
    XMLSEC_STATIC_BINARIES="-static"
    if test "z$build_on_windows" = "zyes" ; then
        XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_STATIC=1"
    fi
    XMLSEC_APP_DEFINES="$XMLSEC_APP_DEFINES -DXMLSEC_STATIC=1"
    enable_crypto_dl="no"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([disabled])
fi
AC_SUBST(XMLSEC_STATIC_BINARIES)

dnl ==========================================================================
dnl check if we need dynamic loading support
dnl ==========================================================================
LIBLTDL_INCLUDE_MARKER="ltdl.h"
LIBLTDL_LIB_MARKER="libltdl$shrext"

LIBLTDL_CFLAGS=""
LIBLTDL_LIBS=""
LIBLTDL_FOUND="no"

AC_ARG_WITH([libltdl], [AS_HELP_STRING([--with-libltdl@<:@=PFX@:>@],[libltdl location])])
AC_ARG_ENABLE([crypto_dl], [AS_HELP_STRING([--enable-crypto-dl],[enable dynamic loading support for xmlsec-crypto libraries (obsolete, use --with-libltdl)])])

dnl Priority 0: Check if library is not needed
if test "z$with_libltdl" = "zno" ||  test "z$enable_crypto_dl" = "zno" ; then
    LIBLTDL_FOUND="disabled"
fi

dnl Priority 1: User specifies the path to installation
if test "z$LIBLTDL_FOUND" = "zno" -a "z$with_libltdl" != "z" -a "z$with_libltdl" != "zyes" ; then
    AC_MSG_CHECKING(for libltdl library installation in "$with_libltdl" folder)
    if test -f "$with_libltdl/include/$LIBLTDL_INCLUDE_MARKER" ; then
        LIBLTDL_CFLAGS="-I$with_libltdl/include"
        LIBLTDL_LIBS="-L$with_libltdl/lib -lltdl"
        LIBLTDL_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
        AC_MSG_ERROR([not found: "$with_libltdl/include/$LIBLTDL_INCLUDE_MARKER" file doesn't exist), typo?])
    fi
fi

dnl Priority 2: User sets both CFLAGS and LIBS flags
if test "z$LIBLTDL_FOUND" = "zno" -a  "z$LIBLTDL_CFLAGS" != "z" -a "z$LIBLTDL_LIBS" != "z" ; then
    LIBLTDL_FOUND="yes"
fi

dnl Priority 3: Just try to compile/link and hope for the best
if test "z$LIBLTDL_FOUND" = "zno" ; then
    AC_CHECK_HEADER([ltdl.h], [
       AC_CHECK_LIB(
    	    [ltdl],
    	    [lt_dlopenext],
    	    [LIBLTDL=-lltdl],
    	    [LIBLTDL=]
        )
    ], [
        LIBLTDL=
    ])

    AC_MSG_CHECKING(for libltdl library installation)
    if test "z$LIBLTDL" != "z" ; then
        LIBLTDL_CFLAGS="$INCLTDL"
        LIBLTDL_LIBS="$LIBLTDL"
        LIBLTDL_FOUND="yes"
        AC_MSG_RESULT([yes])
    else
	   AC_MSG_RESULT([not found])
    fi
fi

dnl Finally set all the flags
AC_MSG_CHECKING(for xmlsec-crypto dynamic loading support)
if test "z$LIBLTDL_FOUND" = "zyes" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_DL_LIBLTDL=1"
    XMLSEC_NO_CRYPTO_DYNAMIC_LOADING="0"
    AC_MSG_RESULT([yes])
else
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1"
    XMLSEC_NO_CRYPTO_DYNAMIC_LOADING="1"
    AC_MSG_RESULT([$LIBLTDL_FOUND])
fi

AM_CONDITIONAL(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING, test "z$XMLSEC_NO_CRYPTO_DYNAMIC_LOADING" = "z1")
AC_SUBST(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING)
AC_SUBST(LIBLTDL_CFLAGS)
AC_SUBST(LIBLTDL_LIBS)

dnl ==========================================================================
dnl check if we need dynamic loading in the xmlsec apps
dnl ==========================================================================
AC_MSG_CHECKING(for xmlsec-crypto dynamic loading support in command line tool)
AC_ARG_ENABLE([apps_crypto_dl], [AS_HELP_STRING([--enable-apps-crypto-dl],[ enable dynamic loading support for xmlsec-crypto libraries in xmlsec command line tool (yes)])])
if test "z$enable_apps_crypto_dl" = "z" ; then
    enable_apps_crypto_dl="$enable_crypto_dl"
fi
if test "z$enable_apps_crypto_dl" = "zno" ; then
    XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING="1"
    AC_MSG_RESULT([disabled])
elif test "z$enable_crypto_dl" = "zno" ; then
    AC_MSG_RESULT([disabled])
    AC_MSG_ERROR(xmlsec-crypto libraries dynamic loading support in xmlsec command line tool is requested but no dynamic loading in xmlsec itself is disabled)
elif test "z$LIBLTDL_FOUND" != "zyes" ; then
    AC_MSG_RESULT([disabled])
    AC_MSG_ERROR(xmlsec-crypto libraries dynamic loading support in xmlsec command line tool is requested but no LibLTDL is found)
else
    XMLSEC_APP_DEFINES="$XMLSEC_APP_DEFINES -DXMLSEC_CRYPTO_DYNAMIC_LOADING=1"
    XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING="0"
    AC_MSG_RESULT([yes])
fi
AM_CONDITIONAL(XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING,
    test "z$XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING" = "z1")
AC_SUBST(XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING)

dnl ==========================================================================
dnl Where do we want to install docs
dnl ==========================================================================
AC_MSG_CHECKING(for docs folder)
AC_ARG_WITH([html-dir], [AS_HELP_STRING([--with-html-dir=PATH],[path to installed docs])])
if test "z$with_html_dir" != "z" ; then
    XMLSEC_DOCDIR="$with_html_dir"
elif test "z$htmldir" != "z" ; then
    XMLSEC_DOCDIR='$(htmldir)'
else
    XMLSEC_DOCDIR='$(datadir)/doc/xmlsec1'
fi

AC_MSG_RESULT([$XMLSEC_DOCDIR])
AC_SUBST(XMLSEC_DOCDIR)

dnl ==========================================================================
dnl See do we need Simple Keys Manager
dnl ==========================================================================
AC_MSG_CHECKING(for Simple Keys Manager testing)
AC_ARG_ENABLE([skm], [AS_HELP_STRING([--enable-skm],[enable Simple Keys Manager testing (yes)])])
if test "z$enable_skm" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_SKM_TEST=1"
    AC_MSG_RESULT([disabled])
else
    AC_MSG_RESULT([yes])
fi

dnl ==========================================================================
dnl See do we need templates tests
dnl ==========================================================================
AC_MSG_CHECKING(for templates testing)
AC_ARG_ENABLE([tmpl_tests], [AS_HELP_STRING([--enable-tmpl-tests],[enable templates testing in xmlsec utility (yes)])])
if test "z$enable_tmpl_tests" = "zno" ; then
    XMLSEC_DEFINES="$XMLSEC_DEFINES -DXMLSEC_NO_TMPL_TEST=1"
    AC_MSG_RESULT([disabled])
else
    AC_MSG_RESULT([yes])
fi

dnl ==========================================================================
dnl Debug
dnl ==========================================================================
AC_MSG_CHECKING(for debugging)
AC_ARG_ENABLE([debugging], [AS_HELP_STRING([--enable-debugging],[enable debugging compilation flags (no)])])
if test "z$enable_debugging" = "zyes" ; then
    CFLAGS="$CFLAGS -g"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([disabled])
fi

dnl ==========================================================================
dnl Warnings as errors
dnl ==========================================================================
AC_MSG_CHECKING(for warnings as errors)
AC_ARG_ENABLE([werror], [AS_HELP_STRING([--enable-werror],[handle warnings as errors (no)])])
if test "z$enable_werror" = "zyes" ; then
    CFLAGS="$CFLAGS -Werror"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([disabled])
fi

dnl ==========================================================================
dnl Profiling
dnl ==========================================================================
AC_MSG_CHECKING(for profiling)
AC_ARG_ENABLE([profiling], [AS_HELP_STRING([--enable-profiling],[enable profiling compilation flags (no)])])
if test "z$enable_profiling" = "zyes" ; then
    CFLAGS="$CFLAGS -pg"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([disabled])
fi

dnl ==========================================================================
dnl Pedantic compilation
dnl ==========================================================================
AC_MSG_CHECKING(for pedantic)
AC_ARG_ENABLE([pedantic], [AS_HELP_STRING([--enable-pedantic],[enable pedantic compilation flags (yes)])])
if test "z$enable_pedantic" = "zno" ; then
    AC_MSG_RESULT([disabled])
else
    CFLAGS="$CFLAGS -O -std=c99 -pedantic -pedantic-errors -W -Wall -Wextra"
    CFLAGS="$CFLAGS -fno-inline -Wnull-dereference -Wdouble-promotion"
    CFLAGS="$CFLAGS -Wformat=2 -Wformat-security -Wformat-nonliteral"
    CFLAGS="$CFLAGS -Wconversion -Wunused -Wshadow -Wpointer-arith -Wcast-align"
    CFLAGS="$CFLAGS -Wwrite-strings -Wmissing-prototypes"
    CFLAGS="$CFLAGS -Wnested-externs -Wredundant-decls"

    if test "z$build_with_gcc" = "zyes" ; then
        CFLAGS="$CFLAGS -Wformat-overflow=2 -Wformat-signedness"
    fi
    AC_MSG_RESULT([yes])
fi

dnl ==========================================================================
dnl Secure memset
dnl ==========================================================================
AC_MSG_CHECKING(for secure memset)
AC_ARG_ENABLE([secure-memset], [AS_HELP_STRING([--enable-secure-memset],[enable secure memset compilation flags (yes)])])
if test "z$enable_secure_memset" != "zno" ; then
    CFLAGS="$CFLAGS -fno-builtin-memset"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([disabled])
fi


dnl ==========================================================================
dnl Final steps: xmlsec config
dnl ==========================================================================

dnl Cannot test all libraries when dynamic loading is disabled
if test "z$XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING" = "z1" ; then
    XMLSEC_CHECK_CRYPTO_LIST="$XMLSEC_DEFAULT_CRYPTO"
else
    XMLSEC_CHECK_CRYPTO_LIST="$XMLSEC_CRYPTO_LIST"
fi

XMLSEC_CORE_CFLAGS="$XMLSEC_DEFINES -I${includedir}/xmlsec1  $LIBLTDL_CFLAGS"
XMLSEC_CORE_LIBS="-lxmlsec1 $LIBLTDL_LIBS "
AC_SUBST(XMLSEC_CORE_CFLAGS)
AC_SUBST(XMLSEC_CORE_LIBS)

dnl used in xmlsecConf.sh*
XMLSEC_LIBDIR="${libdir}"
AC_SUBST(XMLSEC_LIBDIR)

XMLSEC_OPENSSL_CFLAGS="$XMLSEC_CORE_CFLAGS $OPENSSL_CFLAGS"
XMLSEC_OPENSSL_LIBS="-L${libdir} -l$OPENSSL_CRYPTO_LIB $XMLSEC_CORE_LIBS $OPENSSL_LIBS"
AC_SUBST(XMLSEC_OPENSSL_CFLAGS)
AC_SUBST(XMLSEC_OPENSSL_LIBS)

XMLSEC_GCRYPT_CFLAGS="$XMLSEC_CORE_CFLAGS $GCRYPT_CFLAGS"
XMLSEC_GCRYPT_LIBS="-L${libdir} -l$GCRYPT_CRYPTO_LIB $XMLSEC_CORE_LIBS $GCRYPT_LIBS"
AC_SUBST(XMLSEC_GCRYPT_CFLAGS)
AC_SUBST(XMLSEC_GCRYPT_LIBS)

XMLSEC_GNUTLS_CFLAGS="$XMLSEC_CORE_CFLAGS $GNUTLS_CFLAGS"
XMLSEC_GNUTLS_LIBS="-L${libdir} -l$GNUTLS_CRYPTO_LIB $XMLSEC_CORE_LIBS $GNUTLS_LIBS"
AC_SUBST(XMLSEC_GNUTLS_CFLAGS)
AC_SUBST(XMLSEC_GNUTLS_LIBS)

XMLSEC_NSS_CFLAGS="$XMLSEC_CORE_CFLAGS $NSS_CFLAGS"
XMLSEC_NSS_LIBS="-L${libdir} -l$NSS_CRYPTO_LIB $XMLSEC_CORE_LIBS $NSS_LIBS"
AC_SUBST(XMLSEC_NSS_CFLAGS)
AC_SUBST(XMLSEC_NSS_LIBS)

dnl No we will not generate pkg-config file for mscrypto !
dnl XMLSEC_MSCRYPTO_CFLAGS="$XMLSEC_CORE_CFLAGS $MSCRYPTO_CFLAGS"
dnl XMLSEC_MSCRYPTO_LIBS="-L${libdir} -l$MSCRYPTO_CRYPTO_LIB $XMLSEC_CORE_LIBS $MSCRYPTO_LIBS";;
dnl AC_SUBST(XMLSEC_MSCRYPTO_CFLAGS)
dnl AC_SUBST(XMLSEC_MSCRYPTO_LIBS)

dnl No we will not generate pkg-config file for mscng.
dnl XMLSEC_MSCNG_CFLAGS="$XMLSEC_CORE_CFLAGS $MSCNG_CFLAGS"
dnl XMLSEC_MSCNG_LIBS="-L${libdir} -l$MSCNG_CRYPTO_LIB $XMLSEC_CORE_LIBS $MSCNG_LIBS";;
dnl AC_SUBST(XMLSEC_MSCNG_CFLAGS)
dnl AC_SUBST(XMLSEC_MSCNG_LIBS)

XMLSEC_CFLAGS="$XMLSEC_CORE_CFLAGS $LIBXML_CFLAGS $LIBXSLT_CFLAGS $XMLSEC_CRYPTO_CFLAGS"
XMLSEC_LIBS="-L${libdir} -l$XMLSEC_CRYPTO_LIB $XMLSEC_CORE_LIBS $LIBXML_LIBS $LIBXSLT_LIBS $XMLSEC_CRYPTO_LIBS"
AC_SUBST(XMLSEC_CFLAGS)
AC_SUBST(XMLSEC_LIBS)

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(XMLSEC_DEFINES)
AC_SUBST(XMLSEC_APP_DEFINES)
AC_SUBST(XMLSEC_EXTRA_LDFLAGS)
AC_SUBST(XMLSEC_CRYPTO_EXTRA_LDFLAGS)

AC_SUBST(XMLSEC_DEFAULT_CRYPTO)
AC_SUBST(XMLSEC_CRYPTO_LIST)
AC_SUBST(XMLSEC_CHECK_CRYPTO_LIST)
AC_SUBST(XMLSEC_CRYPTO_DISABLED_LIST)
AC_SUBST(XMLSEC_CRYPTO_LIB)
AC_SUBST(XMLSEC_CRYPTO_CFLAGS)
AC_SUBST(XMLSEC_CRYPTO_LIBS)

XMLSEC_CRYPTO_PC_FILES_LIST=""
for i in $XMLSEC_CRYPTO_LIST ; do
    dnl skip pkg-config file for mscrypto/mscng
    test x$i = xmscrypto && continue
    test x$i = xmscng && continue
    XMLSEC_CRYPTO_PC_FILES_LIST="$XMLSEC_CRYPTO_PC_FILES_LIST $XMLSEC_PACKAGE-$i.pc"
done
AC_SUBST(XMLSEC_CRYPTO_PC_FILES_LIST)

dnl ==========================================================================
dnl Writing result files
dnl ==========================================================================
if test "z$XMLSEC_NO_OPENSSL" != "z1" ; then
AC_CONFIG_FILES([include/xmlsec/openssl/Makefile src/openssl/Makefile])
fi

if test "z$XMLSEC_NO_GNUTLS" != "z1" ; then
AC_CONFIG_FILES([include/xmlsec/gnutls/Makefile src/gnutls/Makefile])
fi

if test "z$XMLSEC_NO_GCRYPT" != "z1" ; then
AC_CONFIG_FILES([include/xmlsec/gcrypt/Makefile src/gcrypt/Makefile])
fi

if test "z$XMLSEC_NO_NSS" != "z1" ; then
AC_CONFIG_FILES([include/xmlsec/nss/Makefile src/nss/Makefile])
fi

if test "z$XMLSEC_NO_MSCRYPTO" != "z1" ; then
AC_CONFIG_FILES([include/xmlsec/mscrypto/Makefile src/mscrypto/Makefile])
fi

if test "z$XMLSEC_NO_MSCNG" != "z1" ; then
AC_CONFIG_FILES([include/xmlsec/mscng/Makefile src/mscng/Makefile])
fi

if test "z$XMLSEC_NO_CRYPTO_DYNAMIC_LOADING" = "z1" ; then
(rm -f xmlsec1.pc && $LN_S xmlsec1-$XMLSEC_DEFAULT_CRYPTO.pc xmlsec1.pc)
else
AC_CONFIG_FILES([xmlsec1.pc:xmlsec.pc.in])
fi

AC_CONFIG_FILES([
include/xmlsec/version.h
Makefile
include/Makefile
include/xmlsec/Makefile
src/Makefile
apps/Makefile
docs/Makefile
docs/api/Makefile
man/Makefile
xmlsec1-openssl.pc:xmlsec-openssl.pc.in
xmlsec1-gnutls.pc:xmlsec-gnutls.pc.in
xmlsec1-gcrypt.pc:xmlsec-gcrypt.pc.in
xmlsec1-nss.pc:xmlsec-nss.pc.in
xmlsec1.spec:xmlsec.spec.in
])
AC_CONFIG_FILES([xmlsec1Conf.sh:xmlsecConf.sh.in], [chmod +x xmlsec1Conf.sh])
AC_CONFIG_FILES([xmlsec1-config:xmlsec-config.in], [chmod +x xmlsec1-config])
AC_OUTPUT
