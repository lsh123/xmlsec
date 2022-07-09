# XMLSec Library: XMLSEC-GNUTLS

## What version of GnuTLS?
GnuTLS 2.8.0 or later is required.

## Dependencies
The `xmlsec-gnutls` uses both libgcrypt and libgnutls because GnuTLS
does not provide direct access to low-level crypto operations (digests,
hmac, aes, des, etc.).
