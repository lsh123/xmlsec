# XMLSec Library: XMLSEC-OPENSSL

## What version of OpenSSL?
OpenSSL 3.0.0 or later is strongly recommended.

Also LibreSSL (>= 3.5.0) and Boring SSL (>= 1.1.0) should work but those libraries
have less stable API/ABI and are not tested as frequently as OpenSSL.

## Keys manager
OpenSSL does not have a keys or certificates storage implementation. The
default xmlsec-openssl key manager uses XMLSEC Simple Keys Store based on
a plain keys list. Trusted/untrusted certificates are stored in `STACK_OF(X509)`
structures.
