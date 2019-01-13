#!/bin/sh

if [ "`uname`" = "Darwin" ]; then
	export PATH="/usr/local/opt/nss/bin:$PATH"
	export PKG_CONFIG_PATH="/usr/local/opt/nss/lib/pkgconfig:$PKG_CONFIG_PATH"
fi
