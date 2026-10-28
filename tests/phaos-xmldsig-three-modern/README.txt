Sample XML Signatures Produced Using the Phaos XML Toolkit (Modernized)
=======================================================================

The files in this folder are the same documents as in
tests/phaos-xmldsig-three/, but re-signed with modern algorithms and
with keys and certificates from tests/keys/ (instead of the original
phaos certs/ subfolder):

	- DSA signatures were replaced with ECDSA (P-256) signatures:
	  dsa-sha1 -> ecdsa-sha256,
	- RSA signatures were upgraded from RSA 1024 / SHA-1 to
	  RSA 2048 / SHA-256:
	  rsa-sha1 -> rsa-sha256,
	- MD5/SHA-1 digests were replaced with SHA-256,
	- HMAC-MD5/HMAC-SHA1 signatures were replaced with HMAC-SHA256.

Each signed example has a <name>.xml file and a matching unsigned
template <name>.tmpl.  The templates contain empty <DigestValue/>,
<SignatureValue/> and (where applicable) empty <X509Data/> elements
that xmlsec1 fills in when signing.

Keys and certificates (all in tests/keys/)
------------------------------------------

	rsa/rsa-2048-key{,-win}.p12
	--------------------------
	The RSA 2048-bit private key with the full certificate chain
	(rsa-2048-cert, ca2cert, cacert) in PKCS#12 format.  Password is
	"secret123".  Used by the RSA signature examples (signing key
	name "TestKeyName-rsa-2048-phaos").

	rsa/rsa-2048-cert.{pem,der}
	---------------------------
	The RSA end entity certificate issued by ca2cert.

	ec/ec-prime256v1-key{,-win}.p12
	------------------------------
	The EC (P-256) private key with the full certificate chain
	(ec-prime256v1-cert, ca2cert, cacert) in PKCS#12 format.
	Password is "secret123".  Used by the ECDSA signature examples
	(signing key name "TestKeyName-ec-prime256v1-phaos").

	ca2cert.{pem,der}
	-----------------
	The intermediate CA certificate.

	cacert.{pem,der}
	----------------
	The self-signed root CA certificate.

	rsa/rsa-4096-cert.{pem,der}
	--------------------------
	A different RSA certificate, referenced by the
	"bad retrieval method" negative test.

	rsa/rsa-2048-cert-revoked-crl.{pem,der}
	--------------------------------------
	A CRL that revokes rsa-2048-cert.  Used by the "CRL present"
	negative test.

	hmackey.bin
	-----------
	The HMAC key (the ASCII encoding of the word "secret") used by the
	HMAC signature examples.

Contents of phaos-xmldsig-three-modern
======================================

	signature-rsa-enveloped.{xml,tmpl}
	-----------------------------------
	Contains an RSA enveloped signature.  The X509Data element in
	KeyInfo is filled with the full certificate chain of the signing
	key.


	signature-rsa-enveloping.{xml,tmpl}
	-----------------------------------
	Contains an RSA enveloping signature.  The X509Data element in
	KeyInfo is filled with the full certificate chain of the signing
	key.


	signature-rsa-detached.{xml,tmpl}
	---------------------------------
	Contains an RSA detached signature.  The X509Data element in
	KeyInfo is filled with the full certificate chain of the signing
	key.


	signature-ecdsa-enveloped.{xml,tmpl}
	-----------------------------------
	Contains an ECDSA enveloped signature.  The X509Data element in
	KeyInfo is filled with the full certificate chain of the signing
	key.


	signature-ecdsa-enveloping.{xml,tmpl}
	------------------------------------
	Contains an ECDSA enveloping signature.  The X509Data element in
	KeyInfo is filled with the full certificate chain of the signing
	key.


	signature-ecdsa-detached.{xml,tmpl}
	----------------------------------
	Contains an ECDSA detached signature.  The X509Data element in
	KeyInfo is filled with the full certificate chain of the signing
	key.


	signature-hmac-sha256-c14n-enveloping.{xml,tmpl}
	-----------------------------------------------
	Contains an enveloping SHA-256 HMAC signature and uses XML
	Canonicalization as the canonicalization method.


	signature-hmac-sha256-exclusive-c14n-enveloped.{xml,tmpl}
	---------------------------------------------------------
	Contains an enveloped SHA-256 HMAC signature and uses the
	Exclusive XML Canonicalization canonicalization method.


	signature-hmac-sha256-exclusive-c14n-comments-detached.{xml,tmpl}
	-----------------------------------------------------------------
	Contains a detached SHA-256 HMAC signature and uses the Exclusive
	XML Canonicalization With Comments canonicalization method.


	signature-hmac-sha256-40-c14n-comments-detached.{xml,tmpl}
	----------------------------------------------------------
	Contains a detached 40-byte SHA-256 HMAC signature (the digest is
	truncated to 40 bytes by the HMACOutputLength element) and uses
	the XML Canonicalization With Comments canonicalization method.


	signature-hmac-sha256-40-exclusive-c14n-comments-detached.{xml,tmpl}
	--------------------------------------------------------------------
	Contains a detached 40-byte SHA-256 HMAC signature (the digest is
	truncated to 40 bytes by the HMACOutputLength element) and uses
	the Exclusive XML Canonicalization With Comments canonicalization
	method.


	signature-ecdsa-manifest.{xml,tmpl}
	----------------------------------
	Contains a detached ECDSA signature with a manifest.  KeyInfo
	contains the ECKeyValue of the signing key.


	signature-rsa-manifest.{xml,tmpl}
	--------------------------------
	Contains a detached RSA signature with a manifest.  KeyInfo
	contains the RSAKeyValue of the signing key.


	signature-rsa-detached-b64-transform.{xml,tmpl}
	----------------------------------------------
	Contains a detached RSA signature with a Base64 decode transform.
	KeyInfo contains the RSAKeyValue of the signing key.


	signature-rsa-detached-xpath-transform.{xml,tmpl}
	------------------------------------------------
	Contains a detached RSA signature with an XPath transform.
	KeyInfo contains the RSAKeyValue of the signing key.


	signature-rsa-xpath-transform-enveloped.{xml,tmpl}
	-------------------------------------------------
	Contains an RSA signature with an XPath transform that produces
	the same result as the enveloped signature algorithm.  The X509Data
	element in KeyInfo is filled with the full certificate chain of the
	signing key.


	signature-rsa-detached-xslt-transform.{xml,tmpl}
	------------------------------------------------
	Contains a detached RSA signature with an XSLT transformation.
	KeyInfo contains the RSAKeyValue of the signing key.


	signature-rsa-manifest-x509-data-cert.{xml,tmpl}
	-----------------------------------------------
	Contains a detached RSA signature with a manifest and an
	X509Certificate element that contains only the signing certificate.


	signature-rsa-manifest-x509-data-cert-chain.{xml,tmpl}
	------------------------------------------------------
	Contains a detached RSA signature with a manifest and two
	X509Certificate elements that contain the signing certificate and
	the intermediate CA certificate.


	signature-rsa-manifest-x509-data-crl.{xml,tmpl}
	----------------------------------------------
	Contains a detached RSA signature with a manifest and two
	X509Certificate elements (the signing certificate and the
	intermediate CA certificate).  Verification fails when the CRL
	contained in tests/keys/rsa/rsa-2048-cert-revoked-crl is loaded,
	because the signing certificate is revoked.


	signature-rsa-manifest-x509-data-subject-name.{xml,tmpl}
	--------------------------------------------------------
	Contains a detached RSA signature with a manifest and an
	X509SubjectName element that references the subject name of the
	certificate stored in tests/keys/rsa/rsa-2048-cert.  KeyInfo
	contains no KeyName element.


	signature-rsa-manifest-x509-data-issuer-serial.{xml,tmpl}
	---------------------------------------------------------
	Contains a detached RSA signature with a manifest and an
	X509IssuerSerial element that references the issuer and serial
	number of the certificate stored in
	tests/keys/rsa/rsa-2048-cert.  KeyInfo contains no KeyName element.


	signature-rsa-manifest-x509-data-ski.{xml,tmpl}
	----------------------------------------------
	Contains a detached RSA signature with a manifest and an X509SKI
	element that references the Subject Key Identifier of the
	certificate stored in tests/keys/rsa/rsa-2048-cert.  KeyInfo
	contains no KeyName element.


	signature-rsa-detached-xslt-transform-retrieval-method.{xml,tmpl}
	----------------------------------------------------------------
	Contains a detached RSA signature with an XSLT transform and a
	KeyInfo element that refers to the external X.509 certificate
	located in tests/keys/rsa/rsa-2048-cert.der via a RetrievalMethod
	element.


	signature-big.{xml,tmpl}
	------------------------
	Contains a larger detached RSA signature that contains a manifest
	and many references that test various transformation algorithms,
	URI reference syntax formats, etc.  The KeyInfo contains a KeyName
	whose value is the subject name of the certificate stored in
	tests/keys/rsa/rsa-2048-cert.


	signature-rsa-detached-xslt-transform-bad-retrieval-method.xml
	-------------------------------------------------------------
	Contains an enveloped RSA signature whose KeyInfo element refers
	to an INCORRECT external X.509 certificate (the certificate stored
	in tests/keys/rsa/rsa-4096-cert.der instead of
	tests/keys/rsa/rsa-2048-cert.der).  Verification should FAIL.


	signature-rsa-enveloped-bad-digest-val.xml
	-----------------------------------------
	Contains an enveloped RSA signature that contains a reference with
	an INCORRECT digest value.  Verification should FAIL.


	signature-rsa-enveloped-bad-sig.xml
	----------------------------------
	Contains an enveloped RSA signature that contains a reference that
	was added after the signature value was computed.  Verification
	should FAIL.


	document.xml
	------------
	An XML document that is referenced by some of the signature examples.


	document-stylesheet.xml
	-----------------------
	The same as document.xml with the addition of an xsl-stylesheet
	processing instruction.


	document.xsl
	------------
	An XSL stylesheet referenced by several of the signature examples
	and document-stylesheet.xml.


	document.b64
	------------
	A Base64 encoded XML document.


	README.txt
	----------
	This file.


Original sample set
===================

The original sample documents and certificates were produced by Joe
Morgan (Software Engineer, Phaos Technology) in November 2002 and are
distributed in the tests/phaos-xmldsig-three/ folder.
