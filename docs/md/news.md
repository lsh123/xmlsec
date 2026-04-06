# XML Security Library: News

- TODO
  The [XML Security Library 1.3.11](download.md) release includes the following changes:
  - TODO

- April 2, 2026
  The [XML Security Library 1.3.10](download.md) release includes the following changes:
  - The minimum supported versions for dependencies are now: LibXML2 >= 2.9.13 (February 19, 2022), LibXSLT >= 1.1.35 (February 16, 2022),
    OpenSSL >= 3.0.13 (January 30, 2024), LibreSSL >= 3.9.0 (March 9, 2024), NSS >= 3.91 (June 26, 2023), NSPR >= 4.34.1 (June 26, 2023),
    GnuTLS >= 3.8.3 (January 1, 2024).
  - (xmlsec-core) Disabled all key value data for all key types by default (use '--enabled-key-data' flag to re-enable if needed).
  - (xmlsec-core) Added '--enable-asn1-signatures-hack' option to allow generation / verification of ASN1 signature values.
  - (xmlsec-core) Added '--verify-crls' option to verify CRLs when loading from command line.
  - (xmlsec-openssl) Added support for EdDSA signature algorithm; XDH (X25519 and X448) key agreement algorithms;
    HKDF key derivation algorithm; Camellia block cipher and key wrap algorithms; ChaCha20 and ChaCha20-Poly1305 encryption algorithms;
    and **experimental** ML-DSA and SLH-DSA-SHA2 signature algorithms.
  - (xmlsec-gnutls) Added support for EdDSA signature algorithms; ECDH and XDH (X25519 and X448) key agreement algorithms;
    ConcatKDF, PBKDF2, and HKDF key derivation algorithms; ChaCha20 and ChaCha20-Poly1305 encryption algorithms;
    SHA2-224 and SHA3-224 digest algorithms; and **experimental** support for ML-DSA signature algorithms.
  - (xmlsec-nss) Added support for EdDSA (Ed25519) signature algorithms; ECDH and XDH (X25519) key agreement algorithms;
    ConcatKDF and HKDF key derivation algorithms; and ChaCha20-Poly1305 encryption algorithm.
    Camellia block cipher and key wrap algorithms.
  - (xmlsec-mscng) Added support for DSA-SHA256 signature algorithm; XDH (X25519) and DH (X9.42 DHX) key agreement algorithms;
    HKDF key derivation algorithm; and SHA3 digest algorithms.
  - (xmlsec-mscng) Added support for loading CRLs from command line.
  - (xmlsec-test) Created scripts to generate keys, regenerated all keys with standard names, and updated tests accordingly.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/xmlsec_1_3_10)).

- November 10, 2025
  The [XML Security Library 1.3.9](download.md) release includes the following changes:
  - (xmlsec-openssl) Added pub/priv key type check for EC and DH keys; improved non-memory EVP keys detection.
  - (xmlsec-openssl) Fixed memory leak in X509 certs verification code.
  - (xmlsec-openssl) Added octet parser in X509 names.
  - (xmlsec-msncg) Added support for non-persistent PKCS12 keys.
  - (xmlsec-windows) Simplified windows build and removed 'with-dl' option for 'configure.js'.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 15, 2025
  The [XML Security Library 1.3.8](download.md) release includes the following changes:
  - (xmlsec-openssl) Deprecated support for OpenSSL 1.1.1 ([reached its End of Life in September, 2023](https://openssl-corporation.org/post/2023-09-11-eol-111/)).
  - (xmlsec-openssl) Added AWS-LC support.
  - (xmlsec-openssl, xmlsec-gnutls, xmlsec-mscng) Added support for longer than expected DSA and ECDSA signatures to support broken Java implementations.
  - (xmlsec command line tool) Added option "--add-id-attr" to add ID attributes by name to all nodes in the document.
  - (xmlsec-core) Added RSA MGF1 and digest template API.
  - (xmlsec-core) Added example of signing / verifying signature by ID attribute.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- June 16, 2025
  The legacy [XML Security Library 1.2.42](download.md) release includes the following changes:
  - (xmlsec-openssl) Ensured that only certificates from XML file are returned after verification.
  - (xmlsec-core) Fixed includes to support latest LibXML2 / LibXSLT.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

- February 11, 2025
  The [XML Security Library 1.3.7](download.md) release includes the following changes:
  - (xmlsec-core) Added XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED flag to the xmlSecTransform to differentiate transforms specified in the input XML file vs transforms automatically added by XMLSec library.
  - (xmlsec-core) Added signature result verification to the examples to demonstrate the need to ensure the correct data is actually signed.
  - (xmlsec-core) Disabled old crypto algorithms (MD5, RIPEMD160) and the old crypto engines (MSCrypto, GCrypt) by default (use "--with-legacy-features" option to reenable everything).
  - (xmlsec-openssl) Fixed excess padding in ECDSA signature generation.
  - (xmlsec-openssl) Fixed build warnings for BoringSSL / AWS-LC.
  - (xmlsec-nss) Fixed certificates search in NSS DB.
  - (xmlsec-openssl, xmlsec-gnutls, xmlsec-mscng) Added an option to skip timestamp checks for certificates and CLRs.
  - (xmlsec-windows) Disabled old crypto algorithms (MD5, RIPEMD160), made "mscng" the default crypto engine on Windows, and added support for "legacy-features" flag for "configure.js".
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 22, 2024
  The [XML Security Library 1.3.6](download.md) release includes the following changes:
  - (xmlsec-openssl) Fixed build if OpenSSL 3.0 doesn't have engines support enabled.
  - (xmlsec-mscng, xmlsec-mscrypto) Added support for multiple trusted certs with the same subject.
  - (windows) Disabled iconv support by default (use 'iconv=yes' option for 'configure.js' to re-enable it).
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- July 19, 2024
  The [XML Security Library 1.3.5 and legacy 1.2.41](download.md) releases include the following changes:
  - (xmlsec-mscng, xmlsec-mscrypto) Improved certificates verification.
  - (xmlsec-gnutls) Added support for self-signed certificates.
  - (xmlsec-core) Fix deprecated functions in LibXML2 2.13.1 including disabling HTTP support
    by default (use '--enable-http' option to re-enable it).
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

- July 11, 2024
  The legacy [XML Security Library 1.2.40](https://www.aleksey.com/xmlsec/download/xmlsec1-1.2.40.tar.gz) release includes the following changes:
  - (xmlsec-core) Fixed functions deprecated in LibXML2 2.13.1 (including disabling HTTP support by default).
  - (xmlsec-nss) Increased keys size in all tests to support NSS 3.101.
  - (windows) Added "ftp" and "http" flags in 'configure.js' (both are disabled by default).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

- April 9, 2024
  The [XML Security Library 1.3.4](download.md) release includes the following changes:
  - (xmlsec-openssl) Support cert dates before unix epoch start.
  - (xmlsec-openssl) Fix build for LibreSSL or BoringSSL.
  - (xmlsec-nss) Ensure NSS algorithms are initialized.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- January 4, 2024
  The [XML Security Library 1.3.3](download.md) release includes the following changes:
  - (xmlsec-core) Disabled KeyValue and DEREncodedKeyValue XML nodes by default. Use the '--enabled-key-data' option
    for the xmlsec command line utility or update the 'keyInfoCtx.enabledKeyData' parameter if you need to re-enable these nodes
    (also see [question 3.5 in the FAQ](faq.md)).
  - (xmlsec-core) Removed '--enable-size-t' ('size_t' for MSVC builds) option and made 'xmlSecSize' to always be the same as 'size_t'.
  - (xmlsec-core) Removed previously deprecated functions, defines, etc.
  - (xmlsec-core) Fixed build for libxml2 v2.12.0.
  - (xmlsec-openssl) Removed support for OpenSSL 1.1.0 ([end of life in Aug 2016](https://endoflife.date/openssl)).
    The minimum OpenSSL supported version is 1.1.1; the version 3.0.0 or greater is recommended.
  - (xmlsec-nss) Added runtime check for the enabled algorithms in NSS.
  - (xmlsec-mscrypto) Removed NT4 support.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- December 12, 2023
  The legacy [XML Security Library 1.2.39](https://www.aleksey.com/xmlsec/download/) release includes the following changes:
  - Added options to enable/disable local files, HTTP, and FTP support. FTP is disabled by default.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

- October 31, 2023
  The [XML Security Library 1.3.2](download.md) release includes the following changes:
  - (xmlsec-openssl) Fixed padding for GOST 2001 and 2012 signatures.
  - (xmlsec-nss) Added support for reading PEM certificates.
  - (xmlsec-nss) Added a check to ensure that the key certificate matches the key.
  - (xmlsec-nss) Added support for xmlsec command line tool '--verify-keys' option.
  - (xmlsec-gnutls) Added support for GOST R 34.11-94, GOST R 34.11-2012 256 bit, and GOST R 34.11-2012 512 bit digest algorithms.
  - (xmlsec-gnutls) Added support for GOST R 34.10-2001, GOST R 34.11-2012 256 bit, and GOST R 34.11-2012 512 bit signature algorithms.
  - (xmlsec-gnutls) Added support for xmlsec command line tool '--verify-keys' option.
  - (xmlsec-gnutls) Added check to ensure that the key certificate matches the key.
  - (xmlsec-mscng) Added support for xmlsec command line tool '--verify-keys' option.
  - (xmlsec-mscng) Replaced windows.h includes with wincrypt.h includes where possible.
  - (xmlsec-mscrypto) Replaced windows.h includes with wincrypt.h includes where possible.
  - (xmlsec command line tool) Added '--base64-line-size' option to control the base64 encoding line size.
  - (MSVC build) Added 'ftp' and 'http' options to control FTP and HTTP support. FTP support is disabled by default.
  - (MinGW build) The xmlsec-mscrypto is moved down in the default crypto library selection list as it is now
    in maintenance mode (use '--with-default-crypto' option to force the selection).
  - (MinGW build) Fixed the static libraries build with "--enable-static-linking" option.
  - Several other small fixes (see [more details](https://github.com/lsh123/xmlsec/commits/master)).

- July 5, 2023
  The legacy [XML Security Library 1.2.38](https://www.aleksey.com/xmlsec/download/) release includes the following changes:
  - Fixed static linking with MinGW.
  - (xmlsec-mscng) Fixed block ciphers key size.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/xmlsec-1_2_x)).

- June 6, 2023
  The [XML Security Library 1.3.1](download.md) release includes the following changes:
  - Added "--with-libltdl" option for ./configure to allow custom libltdl installations and deprecated "--enable-crypto-dl" option.
  - Added support for clang compiler on non-MacOSX platforms.
  - (xmlsec-openssl) Restored support for LibreSSL and bumped minimum required version to 3.5.0.
  - (xmlsec-nss) Restored minimum supported NSS version to 3.35.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- April 12, 2023
  The [XML Security Library 1.3.0](download.md) release includes the following changes:
  - **core xmlsec and all xmlsec-crypto libraries:**
    - (**ABI breaking change**) Added support for the [KeyInfoReference Element](https://www.w3.org/TR/xmldsig-core1/#sec-KeyInfoReference).
    - (**ABI breaking change**) Switched xmlSecSize to use size_t by default. Use "--enable-size-t=no" configure option ("size_t=no" on Windows) to
      restore the old behaviour (note that support for xmlSecSize being different from size_t will be removed in the future).
    - (**API breaking change**) Changed the key search to strict mode: only keys referenced by KeyInfo are used. To restore the old "lax" mode,
      set XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH flag on xmlSecKeyInfoCtx or use '--lax-key-search' option for XMLSec command line utility.
    - (**API breaking change**) The KeyName element content is now trimmed before key search is performed.
    - (**API breaking change**) Disabled FTP support by default. Use "--enable-ftp" configure option to restore it. Also added
      "--enable-http" and "--enable-files" configure options to control support for loading files over HTTP or locally.
    - (**API/ABI breaking change**) Disabled MD5 digest method by default. Use "--enable-md5" configure options ("legacy-crypto" option on Windows) to re-enable MD5.
    - (**ABI breaking change**) Added "failureReason" field to xmlSecDSigCtx and xmlEncCtx to provide more granular operation failure reason.
    - (**ABI breaking change**) Removed deprecated functions.
    - Added support for loading keys through [ossl-store](https://www.openssl.org/docs/man3.0/man7/ossl_store.html) interface (e.g.
      for using keys from an HSM). Also see '--privkey-openssl-store' and '--pubkey-openssl-store' command line options for XMLSec utility.
    - Added ability to control transforms binary chunk size to improve performance (see '--transform-binary-chunk-size' command line option for XMLSec utility).
    - Fixed all potentially unsafe integer conversions and all the other warnings.
    - Added [XML Signature 1.1 interop (2012)](https://www.w3.org/TR/2012/NOTE-xmldsig-core1-interop-20121113/)
      and [XML Encryption 1.1 interop (2012)](https://www.w3.org/TR/2012/NOTE-xmlenc-core1-interop-20121113/) tests.
  - **xmlsec-openssl library:**
    - Added support for [SHA3 digests](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms).
    - Added support for [ECDSA-SHA3 signatures](https://www.ietf.org/rfc/rfc9231.html#name-ecdsa-sha-ecdsa-ripemd160-e).
    - Added support for [RSA PSS signatures (without parameters)](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10).
    - Added support for [ConcatKDF key](https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF) and
      [PBKDF2](https://www.w3.org/TR/xmlenc-core1/#sec-PBKDF2) derivation algorithms.
    - (**ABI breaking change**) Added support for [ECDH-ES Key Agreement algorithm](https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES).
    - (**ABI breaking change**) Added support for [DH-ES Key Agreement algorithm](https://www.w3.org/TR/xmlenc-core1/#sec-DHKeyAgreementExplicitKDF) with explicit KDF.
    - Added support for [MGF1 algorithm to RSA OAEP key transport](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP).
    - Added support for [X509Digest](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data) element and ability to lookup keys using other X509Data elements.
    - Added support for [DEREncodedKeyValue](https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue) element.
    - Automatically set key name from PKCS12 key name.
    - Removed support for OpenSSL 1.0.0 and LibreSSL before 2.7.0.
  - **xmlsec-nss library:**
    - Added support for [RSA PSS signatures (without parameters)](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10).
    - Added support for [RSA OAEP key transport including MGF1 algorithms](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP).
    - Added support for [AES GCM ciphers](https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM).
    - Added support for [PBKDF2](https://www.w3.org/TR/xmlenc-core1/#sec-PBKDF2) derivation algorithm.
    - Added support for [X509Digest](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data) element and ability to lookup keys using other X509Data elements.
    - Added support for [DEREncodedKeyValue](https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue) element.
    - Automatically set key name from PKCS12 key name.
  - **xmlsec-gnutls library:**
    - (**API/ABI breaking change**) Removed dependency on xmlsec-gcrypt and libgcrypt libraries (including API functions) to enable support for different GnuTLS backends.
    - Bumped minimal GnuTLS version to 3.6.13.
    - Added support for [SHA3 digests](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms).
    - Added support for [ECDSA signatures](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA).
    - Added support for [DSA-SHA256 signatures](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP).
    - Added support for [RSA PSS signatures (without parameters)](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10).
    - Added support for [RSA PKCS 1.5 key transport](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-1_5).
    - Added support for [AES GCM ciphers](https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM).
    - Added support for [PBKDF2](https://www.w3.org/TR/xmlenc-core1/#sec-PBKDF2) derivation algorithm.
    - Added support for [X509Digest](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data) element and ability to lookup keys using other X509Data elements.
    - Added support for [DEREncodedKeyValue](https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue) element.
    - Automatically set key name from PKCS12 key name.
  - **xmlsec-mscng library:**
    - Added support for [RSA PSS signatures (without parameters)](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10).
    - Added support for [MGF1 algorithm to RSA OAEP key transport](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP).
    - (**ABI breaking change**) Added support for [ECDH-ES Key Agreement algorithm](https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES).
    - Added support for [ConcatKDF key](https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF) and
      [PBKDF2](https://www.w3.org/TR/xmlenc-core1/#sec-PBKDF2) derivation algorithms.
    - Added support for [X509Digest](https://www.w3.org/TR/xmldsig-core1/#sec-X509Data) element for keys and certificates lookup from the system stores (only SHA1 is supported).
    - Added support for [DEREncodedKeyValue](https://www.w3.org/TR/xmldsig-core1/#sec-DEREncodedKeyValue) element.
    - Automatically set key name from PKCS12 key name.
  - **xmlsec-mscrypto library:**
    - In maintenance mode starting from this release.
    - Disabled by default support for NT4. Use "nt4=yes" configure option on Windows to re-enable it.
  - **xmlsec-gcrypt library:**
    - In maintenance mode starting from this release.
    - Added support for [SHA3 digests](https://www.ietf.org/rfc/rfc9231.html#name-sha-3-algorithms).
    - Added support for [ECDSA signatures](https://www.w3.org/TR/xmldsig-core1/#sec-ECDSA).
    - Added support for [RSA PSS signatures (without parameters)](https://www.ietf.org/rfc/rfc9231.html#section-2.3.10).
    - Added support for [RSA PKCS 1.5 key transport](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-1_5).
    - Added support for [RSA OAEP key transport including MGF1 algorithms](https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP).
  - **xmlsec command line utility:**
    - (**API breaking change**) The XMLSec command line utility is using 'strict' key search mode by default. To restore the old 'lax'
      key search mode, use the new '--lax-key-search' option.
    - (**API breaking change**) The XMLSec command line utility no longer prints detailed errors by default. To restore the detailed
      errors, use the new '--verbose' option.
    - Added '--transform-binary-chunk-size' option to control transforms binary chunk size (increasing the chunk size should improve performance
      at the expense of memory usage).
    - Added support for loading keys through [ossl-store](https://www.openssl.org/docs/man3.0/man7/ossl_store.html) interface (e.g.
      for using keys from an HSM). Also see '--privkey-openssl-store' and '--pubkey-openssl-store' command line options for XMLSec utility.
    - Added '--enabled-key-info-reference-uris' option to control processing of the
      [KeyInfoReference Element](https://www.w3.org/TR/xmldsig-core1/#sec-KeyInfoReference).
    - Added '--pbkdf2-key' option for loading PBKDF2 keys.
    - Added '--concatkdf-key' option for loading ConcatKDF keys.
    - Added '--hmac-min-out-len' option to control the min accepted HMAC Output length.
    - Added '--pubkey-openssl-engine' option to load public keys from OpenSSL engine.
    - Added '--crl-pem' and '--crl-der' options to load CRLs.
    - Added '--verify-keys' option to verify key's certificate before loading into Keys Manager (only supported for OpenSSL currently).
    - Enabled templatized output filenames to facilitate batch operations on multiple input files.

  Detailed information about supported algorithms can be found here:
  [XMLDsig](xmldsig.md) and [XMLEnc](xmlenc.md) interoperability reports.

- November 30, 2022
  The [XML Security Library 1.2.37](download.md) release includes the following changes:
  - Fixed two regressions from 1.2.36 release: [issue #437](https://github.com/lsh123/xmlsec/issues/437)
    and [issue #449](https://github.com/lsh123/xmlsec/issues/449).

- October 31, 2022
  The [XML Security Library 1.2.36](download.md) release includes the following changes:
  - Retired the XMLSec mailing list "xmlsec@aleksey.com" and the XMLSec Online Signature Verifier.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 25, 2022
  The [XML Security Library 1.2.35](download.md) release includes the following changes:
  - Migration to OpenSSL 3.0 API (based on PR by @snargit). Note that OpenSSL engines
    are disabled by default when XMLSec library is compiled against OpenSSL 3.0.
    To re-enable OpenSSL engines, use "--enable-openssl3-engines" configure flag
    (there will be a lot of deprecation warnings).
  - The OpenSSL before 1.1.0 and LibreSSL before 2.7.0 are now deprecated and
    will be removed in the future versions of XMLSec Library.
  - Refactored all the integer casts to ensure cast-safety. Fixed all warnings
    and enabled "-Werror" and "-pedantic" flags on CI builds.
  - Added configure flag to use size_t for xmlSecSize (currently disabled by default
    for backward compatibility).
  - Moved all CI builds to GitHub actions.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- May 3, 2022
  The [XML Security Library 1.2.34](download.md) release includes the following changes:
  - Support for OpenSSL compiled with OPENSSL_NO_ERR.
  - Full support for LibreSSL 3.5.0 and above (@vishwin).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 25, 2021
  The [XML Security Library 1.2.33](download.md) release includes the following changes:
  - Added --privkey-openssl-engine option to enhance openssl engine support (Leonardo Secci).
  - Fixed decrypting session key for two recipients.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- April 21, 2021
  The [XML Security Library 1.2.32](download.md) release includes the following changes:
  - Several small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 29, 2020
  The [XML Security Library 1.2.31](download.md) release includes the following changes:
  - Added configure option to ensure memset() securely erases memory (gcc).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- April 21, 2020
  The [XML Security Library 1.2.30](download.md) release includes the following changes:
  - Enabled XML_PARSE_HUGE for all xml parsers.
  - Added s390x support for travis (nayana-ibm).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 15, 2019
  The [XML Security Library 1.2.29](download.md) release includes the following changes:
  - Various build and tests fixes and improvements.
  - Move remaining private header files away from xmlsec/include/ folder.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- April 16, 2019
  The [XML Security Library 1.2.28](download.md) release includes the following changes:
  - Added BoringSSL support (chenbd).
  - Added gnutls-3.6.x support (alonbl).
  - Added DSA and ECDSA key size getter for MSCNG (vmiklos).
  - Added --enable-mans configuration option (alonbl).
  - Added continuous build integration for MacOSX (vmiklos).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- October 23, 2018
  The [XML Security Library 1.2.27](download.md) release includes the following changes:
  - Added AES-GCM support for OpenSSL and MSCNG (snargit).
  - Added DSA-SHA256 and ECDSA-SHA384 support for NSS (vmiklos).
  - Added RSA-OAEP support for MSCNG (vmiklos).
  - Continuous build integration in Travis and Appveyor.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- June 5, 2018
  The [XML Security Library 1.2.26](download.md) release includes the following changes:
  - Added xmlsec-mscng module based on [Microsoft Cryptography API: Next Generation](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx) (vmiklos).
  - Added support for GOST 2012 and fixed CryptoPro CSP provider for GOST R 34.10-2001 in xmlsec-mscrypto (ipechorin).
  - Added LibreSSL 2.7 support (vishwin).
  - Upgraded documentation build process to support the latest gtk-doc.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- September 12, 2017
  The [XML Security Library 1.2.25](download.md) release includes the following changes:
  - Removed OpenSSL 0.9.8 support and several previously deprecated functions.
  - Added SHA224 support for xmlsec-nss (vmiklos).
  - Added configurable default linefeed for xmltree module (pablogallardo).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- April 20, 2017
  The [XML Security Library 1.2.24](download.md) release includes the following changes:
  - Added ECDSA-SHA1, ECDSA-SHA256, ECDSA-SHA512 support for xmlsec-nss (vmiklos).
  - Fixed XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS handling (vmiklos).
  - Disabled external entities loading by xmlsec utility app by default to prevent XXE attacks (d-hat).
  - Improved OpenSSL version and features detection.
  - Cleaned up, simplified, and standardized internal error reporting.
  - Marked as deprecated all the functions in xmlsec/soap.h file and a couple other functions no longer
    required by xmlsec. These functions will be removed in the future releases.
  - Fixed a few Coverity-discovered bugs ([report](https://scan.coverity.com/projects/xmlsec)).
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

  Please note that OpenSSL 0.9.8 support will be removed in the next release of XMLSec library.

- October 16, 2016
  The [XML Security Library 1.2.23](download.md) release includes the following changes:
  - Full support for OpenSSL 1.1.0.
  - Several other small fixes ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- April 20, 2016
  The [XML Security Library 1.2.22](download.md) release includes the following changes:
  - Restored SOAP parser to support backward compatibility for Lasso project.

- April 12, 2016
  The [XML Security Library 1.2.21](download.md) release includes the following changes:
  - Added OOXML Relationships Transform Algorithm (patch from [Miklos Vajna](https://github.com/vmiklos)).
  - Added experimental GOST2012 support for xmlsec-openssl (patch from Nikolay Shaplov).
  - Migrated XMLSec to [GitHub](https://github.com/lsh123/xmlsec).
  - Added OpenSSL 1.1.0 (pre 2) API support (major re-factoring for all OpenSSL based implementations of the
    block ciphers and the DSA/ECDSA signatures).
  - Removed support for legacy OpenSSL 0.9.6 (last release: March, 2004) and 0.9.7 (last release: February, 2007).
  - Completely revamped manpages/documentation build to completely pass 'make distcheck' tests.
  - Deprecated XMLSEC_CRYPTO define in favor of xmlSecGetDefaultCrypto() function.
  - Implemented several other smaller features; fixed several other minor bugs, code cleanups:
    ([more details](https://github.com/lsh123/xmlsec/commits/master)).

- January 28, 2016
  The XML Security Library was migrated to [GitHub](https://github.com/lsh123/xmlsec). Please use GitHub for
  accessing source code and reporting issues.

- May 27, 2014
  The [XML Security Library 1.2.20](download.md) release fixes a number of miscellaneous bugs and
  updates expired or soon-to-be-expired certificates in the test suite.

- March 24, 2013
  The [XML Security Library 1.2.19](download.md) release adds support for DSA-SHA256, ECDSA-SHA1,
  ECDSA-SHA224, ECDSA-SHA256, ECDSA-SHA384, ECDSA-SHA512 and fixes a number of miscellaneous bugs.

- May 11, 2011
  The [XML Security Library 1.2.18](download.md) release fixes
  a serious crasher. All users are advised to upgrade as soon as possible.

- March 31, 2011
  Changes in [XML Security Library 1.2.17](download.md) release:
  - Fixed security issue with libxslt (CVE-2011-1425, reported by Nicolas Gregoire).
  - Fixed a number of build configuration problems, pkcs12 file loading, and gcrypt init/shutdown.

- May 26, 2010
  Changes in [XML Security Library 1.2.16](download.md) release:
  - New xmlsec-gcrypt library.
  - xmlsec-gcrypt: Added RSA with SHA1/SHA256/SHA384/SHA512/MD5/RIPEMD160,
    DSA with SHA1, AES/DES KW support.
  - xmlsec-gnutls: Added X509 support and converted the library to use
    xmlsec-gcrypt library for all crypto operations.
  - xmlsec-mscrypto: RSA/OAEP and AES/DES KW support.
  - Several minor bug fixes and code cleanups.

- April 29, 2010
  Changes in [XML Security Library 1.2.15](download.md) release:
  - xmlsec-mscrypto: Added HMAC with MD5, SHA1, SHA256/384/512;
    RSA with MD5, SHA256/384/512 support.
  - xmlsec-mscrypto: Converted to Unicode (the non-Unicode builds are still available as compile time option).
  - xmlsec-nss: Added MD5 and SHA256/384/512 support for digest, HMAC
    and RSA (the new minimum required version for NSS library is 3.9).
  - xmlsec-gnutls: Added SHA256/384/512 for digest and HMAC;
    MD5 and RIPEMD160 digests support (the new minimum required version for
    GnuTLS library is 2.8.0).
  - Fixed typo: "Copyrigth" should be "Copyright".
  - Several critical bug fixes and code cleanups.

- December 5, 2009
  Changes in [XML Security Library 1.2.14](download.md) release:
  - XMLSec library is switched from built-in LTDL library to the system
    LTDL library on Linux/Unix and native calls on Windows to fix a
    [security issue](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2009-3736) in LTDL.
  - Fixed minor bugs (see [commits log](https://github.com/lsh123/xmlsec/commits/master) for complete list).

- September 12, 2009
  Changes in [XML Security Library 1.2.13](download.md) release:
  - [LibXML2](http://xmlsoft.org/) version 2.7.4 is now required.
  - Implemented support for [C14N version 1.1](http://www.w3.org/TR/xml-c14n11/).
  - Increase default minimum hmac size to 80 bits.
  - Added support for --with-libxml-src and --with-libxslt-src ./configure options.
  - Fixed XML dump output.

- July 14, 2009
  The new [XML Security Library 1.2.12](download.md) release
  includes the following changes (see ChangeLog for the complete list of changes):
  - Fixed HMAC vulnerability with small values of HMAC length
    ([CERT VU #466161](http://www.kb.cert.org/vuls/id/466161)).
  - Added support for the GOST implemented by Russian Crypto Pro CSP
    (patch from Dennis Prochko).
  - Added an option to return the replaced node (based on the patch from Frank Gross).
  - Added new function xmlSecNodeEncodeAndSetContent for encoding
    special chars in the node content.
  - Added configurable Base64 line length.
  - Bug fixes.

- November 6, 2007
  The new [XML Security Library 1.2.11](download.md) release
  includes the following changes:
  - Mingw port (Roumen Petrov).
  - Better support for non-Microsoft CSPs (Wouter and Ed Shallow).
  - Bug fixes.

- June 12, 2006
  The new [XML Security Library 1.2.10](download.md) release
  includes the following changes:
  - GOST algorithms support (Dmitry Belyavsky).
  - Ability to disable system trusted certs in xmlsec-mscrypto (Dmitry Belyavsky).
  - New functions for adding X509IssuerName and X509SerialNumber
    nodes to the template (Dmitry Belyavsky).
  - Better packaging support for Fedora and Debian (Daniel Veillard, John Belmonte).
  - Cleanups from Coverity tool reports.
  - Bug fixes.

- July 12, 2005
  The new [XML Security Library 1.2.9](download.md) release
  includes few bug fixes and adds support for the recently released
  [OpenSSL 0.9.8](http://www.openssl.org) including several
  new algorithms for [xmlsec-openssl](xmldsig.md):
  - SHA224/SHA256/SHA384/SHA512
  - HMAC-SHA224/SHA256/SHA384/SHA512
  - RSA-MD5/RIPEMD160/SHA224/SHA256/SHA384/SHA512

- March 30, 2005
  The new [XML Security Library 1.2.8](download.md) release
  merges OpenOffice.org changes to xmlsec-mscrypto and xmlsec-nss into
  main xmlsec source tree.

- February 23, 2005
  The new [XML Security Library 1.2.7](download.md) release
  includes several bug fixes and minor enhancements:
  - (core) added xmlSecSimpleKeysStoreGetKeys() function.
  - (core) added functions to create `<X509Data/>` node children in the signature template.
  - (core) fixed xmlSecGenerateID() function.
  - (core) fixed dynamic linking initialization/shutdown when custom memory allocation functions are used.
  - (core) fixed encrypted text parsing and xmlParseInNodeContext() function.
  - (openssl) fixed parsing quoted values in the certificate subject.
  - (mscrypto) negative numbers support in xmlSecBnFromString()/xmlSecBnToString() functions.

- August 25, 2004
  The new [XML Security Library 1.2.6](download.md)
  fixes several minor bugs and adds support for loading keys and
  certificates from memory.

- July 27, 2004
  Created a [list of books](related.md) about
  cryptography and security that covers most of the topics needed
  for using XML Security Library.

- April 15, 2004
  The new [XML Security Library 1.2.5](download.md)
  includes a simple XKMS server implementation and fixes a nasty
  bug with encrypting/decrypting nodes with an empty content.

- January 27, 2004
  The new [XML Security Library 1.2.4](download.md)
  release fixes many configuration and installation problems
  found by John.

- January 6, 2004
  The new [XML Security Library 1.2.3](download.md)
  release upgrades xmlsec-gnutls code to support latest gnutls
  library version (1.0.4) and fixes several configuration and
  installation problems.

- November 11, 2003
  The new [XML Security Library 1.2.2](download.md)
  release includes several improvements in ./configure script
  (Daniel, Roumen) and a bug fix for certificates serial number
  processing in xmlsec-mscrypto.

- October 14, 2003
  The new [XML Security Library 1.2.1](download.md)
  release includes a special "hack" for supporting ID attributes
  with invalid values in Visa 3D; fixed processing of root element
  node siblings (bug #124245); template functions for creating
  `<enc:KeyReference/>` and `<enc:DataReference/>` nodes (Wouter);
  new "XMLSEC_DOCDIR" environment variable for ./configure script;
  updated README files for xmlsec-crypto libraries.

- September 30, 2003
  The major change in the new [XML Security Library 1.2.0](download.md)
  release is the MS Crypto API support implemented by Wouter. Other changes
  include loading public keys from certificates and improved namespaces
  support for start node selection with "--node-xpath" command line option
  for xmlsec command line utility; updated online XML DSig Verifier;
  updated docs and man pages.

- September 17, 2003
  The new [XML Security Library 1.1.2](download.md) release
  introduces dynamical crypto engines loading based on ltdl library (including
  tutorial, API reference and documentation updates); adds an ability to build
  multiple xmlsec-crypto libraries in one build on Windows; fixes minor problems
  in test suite and multiple warnings when building on Sun Solaris.

- August 21, 2003
  The new [XML Security Library 1.1.1](download.md) release
  adds `<X509Data/>` node templates support to xmlsec-nss (Tej);
  includes new functions for reading keys and certificates from memory
  for xmlsec-core and xmlsec-openssl (Joachim); fixes several problems
  in xmlsec configuration files (Roumen) and a bug in URI attribute
  XInclude processing.

- August 5, 2003
  A great patch from Tej that dramatically improves xmlsec-nss functionality
  deserves a minor version number update :). In addition to that, the new
  [XML Security Library 1.1.0](download.md)
  release includes `<X509Data/>` node templates support
  for xmlsec-openssl (Roumen); separate pkg-config files for xmlsec-crypto
  libraries and minor documentation updates (including coding style
  and some useful commands for xmlsec developers in a new "HACKING" file).

- July 15, 2003
  There were several minor patches during last month and it's time to do
  a new [XML Security Library 1.0.4](download.md)
  release to pick up them: x509 certificates names comparison function
  now supports multiple entries with the same object name (Roumen);
  multiple build fixes; documentation mistypes fixes.
  Also I gave an XML Security presentation at
  [OSCON 2003](http://oreillynet.com/oscon2003/) last week.
  You can download slides [here](http://www.aleksey.com/xmlsec/extra/xmlsec_oscon_2003.ppt).

- June 17, 2003
  The [XML Security Library 1.0.3](download.md)
  release adds PKCS#8 support for xmlsec-openssl (Tej) and fixes several
  configuration and portability problems.

- June 03, 2003
  The [XML Security Library 1.0.2](download.md)
  release includes several fixes in xmlsec-nss configuration and
  linking options (Tej), PKCS12 files reading improvements,
  minor documentation and help file fixes. Also this release
  includes some code for XKMS support. This is absolutely not usable
  right now and not configured in by default. Please, don't
  use or even compile it in.

- April 28, 2003
  The [XML Security Library 1.0.1](download.md)
  release is a maintenance release. It fixes several compilation
  problems found in 1.0.0 release on the following platforms:
  OpenBSD/sparc64, Win32 Wacom C, Sun Workshop CC 6.0. Also from
  now on Win32 MSVC port enables the threading support
  by default (this is a part of the Igor's change to
  LibXML2/LibXSLT/XMLSec libraries). If you don't
  use one of these platforms then you'll see no difference.

- April 17, 2003
  The [XML Security Library 1.0.0](download.md)
  release is the major upgrade from 0.0.X version.
  The new version includes multiple crypto engines support
  (with "out of the box" support for OpenSSL, GnuTLS and NSS);
  simplified and cleaned internal structure and API;
  several performance and memory usage improvements;
  new or updated documentation (tutorial, API reference manual and examples).

- April 10, 2003
  The final release candidate [XML Security Library 1.0.0rc1](download.md) is available for download. This release includes
  minor API polishing,
  complete [API Reference Manual](api/index.md),
  new chapters in the [tutorial](tutorial/index.md) and
  several new [examples](examples/index.md).
  Another big change is using major version number in library files
  to prevent collisions between different library versions.
  If no major problems will be found then the 1.0.0 release should
  happen in a week from now.

- April 8, 2003
  The new [XML Security Library 0.0.15](download.md)
  release is a preparation for the upcoming 1.0.0 release and
  provides an ability to have both versions installed together
  on the same box.
  Also this release includes updated expired certificates for
  the regression test suite and a fix for minor bug in reading binary
  keys on Windows.

- March 26, 2003
  [XML Security Library 0.1.1](download.md)
  release is the first release candidate for the new stable
  version of XML Security Library. A lot of internal changes
  including enhanced processing controls, performance improvements
  for XML transforms, [new documentation](api/index.md),
  updated [examples](examples/index.md)
  and many many other small things.
  Please try this release and report bugs. Again, it's the first
  release candidate and it's very important for me to get your
  feedback about it. Also if you are missing some features
  in the library it's the best time to ask!

- March 19, 2003
  [XML Security Library 0.0.14](download.md) release
  includes several minor bugfixes in references URI
  processing, binary transforms processing and xmlsec
  command line utility.

- March 5, 2003
  The [XML Security Library 0.1.0](download.md) release
  creates a framework for integrating XML Security Library
  with almost any crypto engine and even combining multiple crypto
  engines in one application. As an example, basic support for GnuTLS and NSS
  libraries is provided (digests, hmac and block ciphers).
  This is a pre-alpha release **not recommended** for production
  (please use the [stable 0.0.X](download.md) releases
  instead). The new 0.1.X API and ABI will definitely change.
  However, if you plan to use XML Security Library with a new crypto
  engine and plan to write some code then you can start now.
  The "backend" API is pretty stable and I do not expect major changes.

- February 21, 2003
  [XML Security Library 0.0.13](download.md) release
  fixes incorrect processing of signatures with more than 3 binary
  transforms in a row, improved pkcs12 files support and minor
  documentation update.

- January 26, 2003
  Two major fixes in [HMAC](http://www.aleksey.com/pipermail/xmlsec/2003/000507.html) and
  [DES/AES](http://www.aleksey.com/pipermail/xmlsec/2003/000516.html)
  algorithms are the reason for the new [XML Security Library 0.0.12](download.md) release.
  Also there are few other minor features and bug fixes (see Changelog in the
  distribution for more details).

- December 3, 2002
  New [XML Security Library 0.0.11](download.md) release
  fixes a [major problem](http://www.aleksey.com/pipermail/xmlsec/2002/000368.html)
  in Reference URI attribute processing. This release
  also includes several Win32 build process fixes from Igor.

- October 20, 2002
  Almost two months from previous release and a lot of minor
  enhancements are good reasons for the new
  [XML Security Library 0.0.10](download.md) release:
  - Added a way to specify "current time" to verify certificates expiration against it.
  - Implemented XML results output format for the xmlsec command line utility.
  - Fixed XMLDSig examples and added a new one (thanks to Devin Heitmueller).
  - Resolved static link issue and a bunch of other improvements
    for Win32 platform builds (Igor Zlatkovic).
  - Added dynamic linking option for xmlsec command line utility
    to help Debian port (John Belmonte).
  - Minor bug fixes.

- August 26, 2002
  I've completely screwed up. The release 0.0.8 was totally broken
  (I've simply packaged files from the wrong CVS branch)
  and I am doing a new [0.0.9 release](download.md)
  to fix all the problems. Please upgrade to the new version
  if you use any of previous XML Security Library releases.
  I am really sorry for my stupid mistakes and I promise to never
  do releases on Friday :(
  And special thanks to Ferrell Moultrie for pointing this out.

- August 23, 2002
  [XML Security Library 0.0.8](download.md) is released:
  - New errors reporting system is created and all the code is updated.
  - Added XPointer transform support.
  - Major enveloped and XPath transforms performance improvements.
  - Updated XPath 2 Filter implementation to reflect latest W3C specifications.
  - [Man page](xmlsec-man.md) for xmlsec utility is written.
  - Automatically generated [API Reference](documentation.md) Manual (more than 370 symbols) is created.
  - Minor Win32 bug fixes from Igor.
  - Debian port from John Belmonte.

- July 11, 2002
  XML Security Library [documentation](documentation.md) created.

- July 10, 2002
  A new [XML Security Library 0.0.7](download.md) release
  includes all small bug fixes for last month and a new LibXML2 library
  with improved canonicalization.

- May 28, 2002
  New LibXML 2.4.22 is [released](http://xmlsoft.org/news.md)
  and new [XML Security Library 0.0.6](download.md) is released:
  - Win32 port is added: the idea and most of the configuration scripts
    code was taken from LibXML2 (written by Igor Zlatkovic). I modified
    original files so all errors are mine, not Igor's.
  - Many different performance optimizations (especially for RSA/DSA
    algorithms and enveloped signatures).
  - [XPath Filter 2](http://www.w3.org/TR/xmldsig-filter2/)
    and [Alternative XPath Filter](http://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002AprJun/0001.html)
    (not compiled by default, use --enable-altxpath configuration
    switch if you need this transform) support is added.
  - Custom network protocol handler support is added. It is similar
    to custom protocol handlers in LibXML2 but applied to binary files.
  - Separated XML Security Library RPM into xmlsec and xmlsec-devel
    (suggested by Devin Heitmueller).

- May 14, 2002
  I've checked in new code for plugging in custom input handlers
  (similar to ones that exist in LibXML2). The downside is that
  you have to use a [daily LibXML2 snapshot](ftp://xmlsoft.org/cvs-snapshot.tar.gz)
  to compile a daily XML Security Library snapshot.

- April 28, 2002
  [XMLSec 0.0.5](download.md) released:
  - Big external and internal cleanup. Now the API looks much more consistent
    and I hope simple. I hope to declare API frozen in the next couple weeks.
    Meantime, all comments and suggestions are welcome!
  - Added [symmetric key wrap](http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap)
    (aes, des) support.
  - Added RIPEMD-160 support.

- April 19, 2002
  Minor release [XMLSec 0.0.4](download.md) with main
  goal to fix broken RPM:
  - The RPM is recompiled using OpenSSL 0.9.6. The previous
    version was compiled with OpenSSL 0.9.7 but I got few complaints
    that there are no RPMs for 0.9.7 yet. The downsides of using 0.9.6 are
    some functionality limitations for XML Encryption (no AES support,
    incorrect padding mode for DES, etc.). If you want to use
    XML Encryption it is better to compile the library from sources
    and use OpenSSL 0.9.7.
  - The testDSig, testEnc and testKeys scripts merged into standalone
    "xmlsec" application.
  - A couple minor bugs fixed.

- April 17, 2002
  Installed [xmlsec mailing list](http://www.aleksey.com/pipermail/xmlsec).

- April 16, 2002
  A lot of changes and time for new release [XMLSec 0.0.3](download.md):
  - The first release that includes [XML Encryption support](xmlenc.md)!
    The bad news is that most of new features require [OpenSSL 0.9.7](download.md) which is
    not officially released yet.
  - Options to enable/disable support for particular algorithms were
    added to the `./configure` script.
  - All transforms header files were consolidated in "transforms.h".

- April 6, 2002
  The [RPM packages](download.md) are now available.

- April 5, 2002
  Test suite updates and new minor release [XML Security Library 0.0.2a](download.md).
  New [interoperability tests](http://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002AprJun/0017.html)
  were provided by Merlin Hughes. XML Security Library successfully passed
  **all tests** after small test program tweaking and adding workaround
  for an [OpenSSL CRL problem](http://groups.google.com/groups?hl=en&threadm=96uofi%2417gh%241%40FreeBSD.csie.NCTU.edu.tw&rnum=2&prev=/groups%3Fq%3DX509_STORE_add_crl%26hl%3Den%26selm%3D96uofi%252417gh%25241%2540FreeBSD.csie.NCTU.edu.tw%26rnum%3D2).
  These new tests are included into the distribution and previous Merlin's
  test suites are removed. Because of these changes I decided to generate
  a new package that also will include the Online XML Digital Signature Verifier code.

- April 3, 2002
  The Online XML Digital Signature Verifier is available! You can use this tool to
  verify your XML Digital Signatures from online Web form or using a simple
  Perl script. The idea was stolen from [Manoj K. Srivastava](http://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002AprJun/0006.html).

- March 31, 2002
  Some major changes and a time for new release: [XML Security Library 0.0.2](download.md). Now XML Security Library supports **all** MUST/SHOULD/MAY
  [features](xmldsig.md) from XMLDSig standard!
  - Added X509 certificates and certificate chains support.
  - The detailed signature generation/verification results are made available to the application.
  - [RetrievalMethod, Manifests and additional algorithms](https://www.rfc-editor.org/rfc/rfc9231.html) are added.
  - The Transforms and KeyInfo code was significantly re-written with a goal
    to separate it from XMLDSig logic for better re-usability (in XML Encryption, etc.).

- March 18, 2002
  - Fixed wrong way shift of the DSA digest result bug found by Philipp Gühring. This bug is critical and I have to do a [new build](download.md).
  - Added "--with-pedantic" configuration option and fixed all but "unused variable" warnings (bug reported by Daniel Veillard).

- March 17, 2002
  The [XML Security Library 0.0.1](download.md) is released
  and available for download! Please try it out and send
  me your comments/suggestions.
