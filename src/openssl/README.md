# XMLSec Library: XMLSEC-OPENSSL

## What version of OpenSSL?
OpenSSL 1.1.1 or later is required.

Also LibreSSL (>= 3.5.0) and Boring SSL (>= 1.1.0) should work but those are
less tested than OpenSSL.

## Keys manager
OpenSSL does not have a keys or certificates storage implementation. The
default xmlsec-openssl key manager uses XMLSEC Simple Keys Store based on
a plain keys list. Trusted/untrusted certificates are stored in `STACK_OF(X509)`
structures.
