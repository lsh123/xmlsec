# XMLSec Library: XMLSEC-GNUTLS

## What version of GnuTLS?
GnuTLS 3.8.3 or newer is required.

## Passwords

The GnuTLS backend has no built-in interactive password prompt
(`xmlSecGnuTLSAppGetDefaultPwdCallback()` returns `NULL`). When loading an
encrypted key (encrypted PEM/PKCS#8 or PKCS#12), an explicit password or a
password callback (compatible with the OpenSSL `pem_password_cb` signature)
must be supplied; otherwise the load fails instead of prompting for the
password.

Also note that passwords are passed to GnuTLS byte-for-byte, with no encoding
conversion: since 3.x, GnuTLS treats passwords as UTF-8 and normalizes them
using the RFC 7613 rules, so a non-ASCII password may behave differently
across the xmlsec backends.
