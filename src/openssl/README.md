# XMLSec Library: XMLSEC-OPENSSL

## What version of OpenSSL?
OpenSSL 1.1.1 is the minimum supported version (deprecated); 3.0.13 or newer
is recommended (3.5.0 or newer is strongly recommended).

Also AWS-LC (>= 1.66.0), LibreSSL (>= 4.0.0) and BoringSSL (later than Oct 2024)
should work but those libraries have less stable API/ABI and are not tested
as frequently as OpenSSL.

## Keys manager
OpenSSL does not have a keys or certificates storage implementation. The
default xmlsec-openssl key manager uses XMLSEC Simple Keys Store based on
a plain keys list. Trusted certificates are stored in the `X509_STORE`
object and untrusted certificates are stored in `STACK_OF(X509)` structures.
