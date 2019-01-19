#!/bin/sh

if [ "`uname`" = "Darwin" ]; then
	# openssl
	export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"

	# nspr/nss
	export PATH="/usr/local/opt/nss/bin:$PATH"
	export PKG_CONFIG_PATH="/usr/local/opt/nss/lib/pkgconfig:$PKG_CONFIG_PATH"
fi
