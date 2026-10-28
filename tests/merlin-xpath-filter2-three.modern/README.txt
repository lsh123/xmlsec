Sample XML Signatures using the Revised XPath Filter 2.0 (Modernized)
=====================================================================

The documents in this folder are the same documents as in
tests/merlin-xpath-filter2-three/, but re-signed with modern
algorithms and with keys from tests/keys/ (instead of the original
DSA key and certificates):

	- the DSA signatures were replaced with ECDSA (P-256)
	  signatures: dsa-sha1 -> ecdsa-sha256,
	- the HMAC-SHA1 signature was replaced with an HMAC-SHA-256
	  signature: hmac-sha1 -> hmac-sha256,
	- the SHA-1 digests were replaced with SHA-256 digests.

The document content, the references (with the same XPath Filter 2.0
expressions) and the canonicalization methods are unchanged: the
C14N 1.0 canonicalization method, the enveloped-signature transform
and the XPath Filter 2.0 transform are not deprecated.

Each signed example has a <name>.xml file and a matching unsigned
template <name>.tmpl.  The templates contain empty <DigestValue> and
<SignatureValue> elements that xmlsec1 fills in when signing.  Like
the original sample, the sign-xfdl example pair intentionally uses
different signature methods: the .xml file is signed with ECDSA,
while the .tmpl file is to be signed with HMAC.

Keys and certificates (in tests/keys/)
--------------------------------------

	ec/ec-prime256v1-key{,-win}.p12
	------------------------------
	The EC (P-256) private key with the full certificate chain
	(ec-prime256v1-cert, ca2cert, cacert) in PKCS#12 format.
	Password is "secret123".  Used to sign the sign-spec example
	and the sign-xfdl .xml file (signing key name
	"TestKeyName-ec-prime256v1").

	hmackey.bin
	-----------
	The binary HMAC key used to sign the sign-xfdl template
	(--hmackey).

Contents of merlin-xpath-filter2-three.modern
=============================================

	sign-spec.{xml,tmpl}
	--------------------
	The last example from the spec along with an example of an
	empty input node set: an enveloping signature over the
	document with two references using the XPath Filter 2.0
	transform (intersect/subtract/union and union of the document
	root).  The .xml file is signed with ECDSA (P-256) and its
	KeyInfo contains the KeyName and the ECKeyValue of the signing
	key.  The X509Data element from the original KeyInfo (with the
	original Baltimore certificates) was removed.


	sign-xfdl.{xml,tmpl}
	--------------------
	John Boyer's example (for performance testing): an enveloped
	signature over the XFDL document with a reference using the
	XPath Filter 2.0 transform (subtract).  The .xml file is
	signed with ECDSA (P-256); its KeyInfo contains the KeyName
	and the ECKeyValue of the signing key (the X509Data element
	from the original KeyInfo was removed).  The .tmpl file is
	to be signed with HMAC-SHA-256 and, unlike the original
	template, has no <KeyInfo> element: the HMAC key is not
	embedded in the document but is provided to xmlsec1 with the
	--hmackey option.


	sign-spec-c14n-0.txt, sign-spec-c14n-1.txt
	------------------------------------------
	The intermediate canonicalized output of the two references
	of the sign-spec example (reference 2 produces an empty
	node set, so its canonicalized output is an empty file).


	sign-xfdl-c14n-0.txt
	---------------------
	The intermediate canonicalized output of the reference of
	the sign-xfdl example.


	sign-spec-c14n-2.txt
	---------------------
	The canonical form of the <SignedInfo> element of the
	sign-spec example (the data that is signed).


	README.txt
	----------
	This file.


Original sample
===============

The original sample documents and certificates were produced by
Merlin Hughes (Baltimore Technologies, Ltd.) in June 2002 and are
distributed in the tests/merlin-xpath-filter2-three/ folder.
