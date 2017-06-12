#!/bin/bash

# Continuous Integration script for xmlsec
# Author: Peter Budai <peterbudai@hotmail.com>

# it is supposed to be run by appveyor-ci

# Enable colors
normal=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
cyan=$(tput setaf 6)

# Basic status function
_status() {
    local type="${1}"
    local status="${package:+${package}: }${2}"
    local items=("${@:3}")
    case "${type}" in
        failure) local -n nameref_color='red';   title='[XMLSEC CI] FAILURE:' ;;
        success) local -n nameref_color='green'; title='[XMLSEC CI] SUCCESS:' ;;
        message) local -n nameref_color='cyan';  title='[XMLSEC CI]'
    esac
    printf "\n${nameref_color}${title}${normal} ${status}\n\n"
}

# Run command with status
execute(){
    local status="${1}"
    local command="${2}"
    local arguments=("${@:3}")
    cd "${package:-.}"
    message "${status}"
    if [[ "${command}" != *:* ]]
        then ${command} ${arguments[@]}
        else ${command%%:*} | ${command#*:} ${arguments[@]}
    fi || failure "${status} failed"
    cd - > /dev/null
}

# Build
build_xmlsec() {
    cd $(cygpath ${APPVEYOR_BUILD_FOLDER})

    autoreconf -fi
    mkdir build && cd build

    ../${_realname}/configure   \
     --prefix="$(cygpath ${APPVEYOR_BUILD_FOLDER})\install"      \
     --build="x86_64-w64-mingw32" \
     --host="x86_64-w64-mingw32" \
     --enable-mscrypto

    make
}

# Test
test_xmlsec() {
    cd $(cygpath ${APPVEYOR_BUILD_FOLDER})

    cd build

    make check
}
# Status functions
failure() { local status="${1}"; local items=("${@:2}"); _status failure "${status}." "${items[@]}"; exit 1; }
success() { local status="${1}"; local items=("${@:2}"); _status success "${status}." "${items[@]}"; exit 0; }
message() { local status="${1}"; local items=("${@:2}"); _status message "${status}"  "${items[@]}"; }

# Install build environment and build
PATH=/c/msys64/mingw64/bin:$PATH
execute 'Installing base-devel and toolchain'  pacman -S --noconfirm mingw-w64-x86_64-toolchain
execute 'Installing dependencies' pacman -S --noconfirm  mingw-w64-x86_64-{libxml2,libxslt,openssl,gnutls,libtool}
execute 'Building xmlsec' build_xmlsec
execute 'Testing xmlsec' test_xmlsec

