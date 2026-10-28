XML Digital Signature 1.1 Core Interoperability Test Vectors 2012 (Modernized)
==============================================================================

The files in this folder are the same documents as in
tests/xmldsig11-interop-2012/
(https://www.w3.org/TR/2012/NOTE-xmldsig-core1-interop-20121113/), but
re-signed with modern algorithms and with keys from tests/keys/ (instead
of the original, weak 1024-bit RSA and the "testkey" HMAC key from the
original keys/ subfolder):

	- HMAC-SHA1 signatures were replaced with HMAC-SHA256 signatures
	  (the two "truncated" tests keep their original 40 and 160 bit
	  HMACOutputLength values),
	- SHA-1 DigestMethod was replaced with SHA-256 (HMAC and RSA tests),
	- the ecdsa-sha1 tests were dropped: modernized they are identical
	  to the already present ecdsa-sha256 tests,
	- the 1024-bit RSA signing key was replaced with the 2048-bit and
	  4096-bit RSA keys from tests/keys/rsa/,
	- the ECDSA keys from tests/keys/ec/ are used,
	- the HMAC key is the one from tests/keys/hmackey.bin (the ASCII
	  encoding of the word "secret", not "testkey" as in the original
	  suite),
	- the original 12 "disabled" test vectors that use the RFC 4050
	  PublicKey X/Y KeyInfo format (*_4050.xml) are not included here:
	  that format is not part of the XML Digital Signature 1.1 specification
	  and xmlsec1 can only consume (not produce) such KeyInfo elements.

Every test has an unsigned template <name>.tmpl (with empty
<DigestValue/>, <SignatureValue/> and, where applicable, empty
<KeyValue/> elements that xmlsec1 fills in when signing) and a matching
pre-signed <name>.xml file (the original suite only had .xml files for
the HMAC and the basic RSA tests).



Keys and certificates (all in tests/keys/)
------------------------------------------

	ec/ec-prime256v1-key{,-win}.p12
	------------------------------
	The EC (P-256) private key with the full certificate chain
	(ec-prime256v1-cert, ca2cert, cacert) in PKCS#12 format.  Password
	is "secret123".  Used by the "p256" ECDSA tests (signing key name
	"TestKeyName-ec-prime256v1").

	ec/ec-prime384v1-key{,-win}.p12
	------------------------------
	The EC (P-384) private key with the full certificate chain
	(ec-prime384v1-cert, ca2cert, cacert) in PKCS#12 format.  Password
	is "secret123".  Used by the "p384" ECDSA tests (signing key name
	"TestKeyName-ec-prime384v1").

	ec/ec-prime521v1-key{,-win}.p12
	------------------------------
	The EC (P-521) private key with the full certificate chain
	(ec-prime521v1-cert, ca2cert, cacert) in PKCS#12 format.  Password
	is "secret123".  Used by the "p521" ECDSA tests (signing key name
	"TestKeyName-ec-prime521v1").

	rsa/rsa-2048-key{,-win}.p12
	--------------------------
	The RSA 2048-bit private key with the full certificate chain
	(rsa-2048-cert, ca2cert, cacert) in PKCS#12 format.  Password is
	"secret123".  Used by the basic RSA tests (signing key name
	"TestKeyName-rsa-2048").

	rsa/rsa-4096-key{,-win}.p12
	--------------------------
	The RSA 4096-bit private key with the full certificate chain
	(rsa-4096-cert, ca2cert, cacert) in PKCS#12 format.  Password is
	"secret123".  Used by the KeyInfoReference, DEREncodedKeyValue and
	X509Digest tests (signing key name "TestKeyName-rsa-4096").

	hmackey.bin
	-----------
	The HMAC key (the ASCII encoding of the word "secret") used by the
	HMAC tests.

Contents of xmldsig11-interop-2012.modern
=========================================

	HMAC tests (no KeyInfo, keyed with tests/keys/hmackey.bin):

	signature-enveloping-hmac-sha256-truncated40.{xml,tmpl}
	-------------------------------------------------------
	Contains an enveloping HMAC-SHA256 signature with the digest
	truncated to 40 bits (HMACOutputLength).  Verification requires
	--hmac-min-out-len 40.


	signature-enveloping-hmac-sha256-truncated160.{xml,tmpl}
	--------------------------------------------------------
	Contains an enveloping HMAC-SHA256 signature with the digest
	truncated to 160 bits (HMACOutputLength).


	signature-enveloping-hmac-sha224.{xml,tmpl}
	-------------------------------------------
	Contains an enveloping HMAC-SHA224 signature.


	signature-enveloping-hmac-sha256.{xml,tmpl}
	-------------------------------------------
	Contains an enveloping HMAC-SHA256 signature.


	signature-enveloping-hmac-sha384.{xml,tmpl}
	-------------------------------------------
	Contains an enveloping HMAC-SHA384 signature.


	signature-enveloping-hmac-sha512.{xml,tmpl}
	-------------------------------------------
	Contains an enveloping HMAC-SHA512 signature.


	ECDSA tests (KeyInfo with KeyName and KeyValue):

	signature-enveloping-p{256,384,521}_sha{224,256,384,512}.{xml,tmpl}
	--------------------------------------------------------------------
	Contain enveloping ECDSA signatures over P-256, P-384 and P-521
	curves with SHA-224, SHA-256, SHA-384 and SHA-512 signature
	algorithm variants (12 tests).


	RSA tests (KeyInfo with KeyName and KeyValue):

	signature-enveloping-rsa-sha{224,256}.{xml,tmpl}
	------------------------------------------------
	signature-enveloping-rsa_sha{384,512}.{xml,tmpl}
	------------------------------------------------
	Contain enveloping RSA signatures using the RSA-SHA224/256/384/512
	signature algorithms.  The SHA-1 digest from the original suite
	was replaced with SHA-256.


	signature-enveloping-sha{224,256,384,512}-rsa_sha256.{xml,tmpl}
	--------------------------------------------------------------
	signature-enveloping-sha256-rsa-sha256.{xml,tmpl}
	-------------------------------------------------
	Contain enveloping RSA signatures using the RSA-SHA256 signature
	algorithm with SHA-224, SHA-256, SHA-384 and SHA-512 reference
	digests (unchanged from the original suite).


	KeyInfo specials:

	signature-enveloping-keyinforeference-rsa.{xml,tmpl}
	---------------------------------------------------
	Contains an enveloping RSA-SHA256 signature whose KeyInfo
	contains a <dsig11:KeyInfoReference/> element pointing to a
	second Object with the real KeyInfo element (KeyName and
	KeyValue).


	signature-enveloping-derencoded-rsa.{xml,tmpl}
	----------------------------------------------
	Contains an enveloping RSA-SHA256 signature whose KeyInfo
	contains a <dsig11:DEREncodedKeyValue/> element with the DER
	encoded public key of the signing key.


	signature-enveloping-derencoded-ec.{xml,tmpl}
	---------------------------------------------
	Contains an enveloping ECDSA-SHA256 signature whose KeyInfo
	contains a <dsig11:DEREncodedKeyValue/> element with the DER
	encoded public key of the signing key.


	signature-enveloping-x509digest-rsa.{xml,tmpl}
	----------------------------------------------
	Contains an enveloping RSA-SHA256 signature whose KeyInfo
	contains an X509Data element with a <dsig11:X509Digest/> element
	(the SHA-256 digest of the signing certificate stored in
	tests/keys/rsa/rsa-4096-cert.der).  Key lookup by X509 data
	requires a backend that supports it (OpenSSL, NSS or GnuTLS).


	README.txt
	----------
	This file.
