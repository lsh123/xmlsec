Sample XML Signatures Produced By Merlin Hughes (Modernized)
===========================================================

The files in this folder are the same documents as in
tests/merlin-xmldsig-twenty-three/, but re-signed with modern
algorithms and with keys and certificates from tests/keys/ (instead
of the original DSA/RSA keys and the merlin certs/ subfolder):

	- DSA signatures were replaced with ECDSA (P-256) signatures:
	  dsa-sha1 -> ecdsa-sha256,
	- RSA signatures were upgraded from SHA-1 to SHA-256
	  (using the RSA 2048 key from tests/keys/):
	  rsa-sha1 -> rsa-sha256,
	- SHA-1 digests were replaced with SHA-256,
	- HMAC-SHA1 signatures were replaced with HMAC-SHA256.

Each signed example has a <name>.xml file and a matching unsigned
template <name>.tmpl.  The templates contain empty <DigestValue/>,
<SignatureValue/> and (where applicable) empty <KeyValue/> or
<X509Data/> elements that xmlsec1 fills in when signing.

Keys and certificates (all in tests/keys/)
------------------------------------------

	ec/ec-prime256v1-key.p12
	----------------------
	The EC (P-256) private key with the full certificate chain
	(ec-prime256v1-cert, ca2cert, cacert) in PKCS#12 format.
	Password is "secret123".  Used by the ECDSA signature examples
	(signing key name "TestKeyName-ec-prime256v1").

	ec/ec-prime256v1-cert.{pem,der}
	------------------------------
	The EC end entity certificate issued by ca2cert.

	ec/ec-prime256v1-pubkey.{crt,der}
	--------------------------------
	The EC end entity certificate (crt) / public key (der), used
	by the signature-keyname example.

	rsa/rsa-2048-key.p12
	--------------------
	The RSA 2048-bit private key with the full certificate chain
	(rsa-2048-cert, ca2cert, cacert) in PKCS#12 format.  Password
	is "secret123".  Used by the RSA signature examples (signing
	key name "TestKeyName-rsa-2048").

	ca2cert.{pem,der}
	-----------------
	The intermediate CA certificate.

	cacert.{pem,der}
	----------------
	The self-signed root CA certificate.

	rsa/rsa-2048-cert-revoked-crl.{pem,der}
	--------------------------------------
	A CRL that revokes rsa-2048-cert.  Used by the "CRL present"
	negative test for the signature-x509-crt-crl example.

	hmackey.bin
	-----------
	The HMAC key (the ASCII encoding of the word "secret") used by
	the HMAC signature examples.

Contents of merlin-xmldsig-twenty-three.modern
==============================================

	signature-enveloped-ecdsa.{xml,tmpl}
	-----------------------------------
	Contains an ECDSA enveloped signature.  KeyInfo contains the
	ECKeyValue of the signing key.


	signature-enveloping-ecdsa.{xml,tmpl}
	------------------------------------
	Contains an ECDSA enveloping signature.  KeyInfo contains the
	ECKeyValue of the signing key.


	signature-enveloping-b64-ecdsa.{xml,tmpl}
	---------------------------------------
	Contains an ECDSA enveloping signature with a Base64 decode
	transform.  KeyInfo contains the ECKeyValue of the signing key.


	signature-enveloping-hmac-sha256.{xml,tmpl}
	------------------------------------------
	Contains an enveloping SHA-256 HMAC signature.  The HMAC key
	name in KeyInfo is "TeskKeyName-Hmac" (the original template
	typo is preserved on purpose).


	signature-enveloping-hmac-sha256-40.{xml,tmpl}
	---------------------------------------------
	Contains an enveloping 80-bit SHA-256 HMAC signature (the
	output is truncated to 80 bits by the HMACOutputLength
	element).


	signature-enveloping-rsa.{xml,tmpl}
	----------------------------------
	Contains an RSA enveloping signature.  KeyInfo contains the
	RSAKeyValue of the signing key.


	signature-external-b64-ecdsa.{xml,tmpl}
	--------------------------------------
	Contains a detached ECDSA signature with a Base64 decode
	transform that references the external file
	tests/external-data/xml-stylesheet-2005.b64.  KeyInfo contains
	the ECKeyValue of the signing key.


	signature-external-ecdsa.{xml,tmpl}
	----------------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005.  KeyInfo
	contains the ECKeyValue of the signing key.


	signature-keyname.{xml,tmpl}
	---------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005.  KeyInfo
	contains only the KeyName "TestKeyName-ec-prime256v1"; the
	corresponding public key must be provided at verification time.


	signature-retrievalmethod-rawx509crt.{xml,tmpl}
	----------------------------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005 and a
	KeyInfo element that refers to the X.509 certificate in
	tests/keys/ec/ec-prime256v1-cert.der via a RetrievalMethod
	element.  The RetrievalMethod URI is relative to this folder
	(../keys/ec/ec-prime256v1-cert.der) because the test script
	runs the tests from inside the test folder.


	signature-x509-crt.{xml,tmpl}
	----------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005.  The
	X509Data element in KeyInfo is filled with the full certificate
	chain of the signing key.


	signature-x509-crt-crl.{xml,tmpl}
	-------------------------------
	Contains a detached RSA signature that references the external
	file tests/external-data/xml-stylesheet-2005.  The X509Data
	element in KeyInfo is filled with the full certificate chain of
	the signing key.  Verification fails when the CRL contained in
	tests/keys/rsa/rsa-2048-cert-revoked-crl is loaded, because the
	signing certificate is revoked.


	signature-x509-sn.{xml,tmpl}
	---------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005.  The
	X509Data element contains an X509SubjectName element that
	references the subject name of the certificate stored in
	tests/keys/ec/ec-prime256v1-cert; the signing key is looked up
	by X509 data, which requires a backend that supports it
	(OpenSSL, NSS or GnuTLS).


	signature-x509-is.{xml,tmpl}
	---------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005.  The
	X509Data element contains an X509IssuerSerial element that
	references the issuer and serial number of the certificate
	stored in tests/keys/ec/ec-prime256v1-cert; the signing key is
	looked up by X509 data, which requires a backend that supports
	it (OpenSSL, NSS or GnuTLS).


	signature-x509-ski.{xml,tmpl}
	----------------------------
	Contains a detached ECDSA signature that references the
	external file tests/external-data/xml-stylesheet-2005.  The
	X509Data element contains an X509SKI element that references
	the Subject Key Identifier of the certificate stored in
	tests/keys/ec/ec-prime256v1-cert; the signing key is looked up
	by X509 data, which requires a backend that supports it
	(OpenSSL, NSS or GnuTLS).


	signature.{xml,tmpl}
	-------------------
	Contains a larger detached ECDSA signature that contains a
	manifest and many references that test various transformation
	algorithms, URI reference syntax formats, etc.  The KeyInfo
	contains a RetrievalMethod element that refers to the X509Data
	object (object-4) that contains the signing certificate.


	README.txt
	----------
	This file.


Original sample set
===================

The original sample documents and certificates were produced by
Merlin Hughes (Baltimore Technologies, Ltd.) in April 2002 and are
distributed in the tests/merlin-xmldsig-twenty-three/ folder.
