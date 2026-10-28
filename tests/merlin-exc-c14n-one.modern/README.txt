Exclusive Canonical XML Signature Examples (Modernized)
=======================================================

The document in this folder is the same document as in
tests/merlin-exc-c14n-one/, but re-signed with modern algorithms and
with a key from tests/keys/ (instead of the original DSA-1024 key):

	- the DSA signature was replaced with an ECDSA (P-256) signature:
	  dsa-sha1 -> ecdsa-sha256,
	- the SHA-1 digests were replaced with SHA-256 digests.

The document content and the four references (with the same exclusive
canonicalization transform variants, including the InclusiveNamespaces
prefix list and the WithComments variants) are unchanged: the exclusive
canonical XML transforms are not deprecated.  The only changes are the
algorithms in the <SignedInfo> element (SignatureMethod and the four
DigestMethod elements) and the KeyInfo (the DSAKeyValue was replaced
with the ECKeyValue of the new signing key).

Each signed example has a <name>.xml file and a matching unsigned
template <name>.tmpl.  The template contains empty <DigestValue> and
<SignatureValue> elements and an empty <KeyValue> element that xmlsec1
fills in when signing.

Keys and certificates (in tests/keys/)
--------------------------------------

	ec/ec-prime256v1-key{,-win}.p12
	------------------------------
	The EC (P-256) private key with the full certificate chain
	(ec-prime256v1-cert, ca2cert, cacert) in PKCS#12 format.
	Password is "secret123".  Used to sign the example (signing key
	name "TestKeyName-ec-prime256v1").

Contents of merlin-exc-c14n-one.modern
======================================

	exc-signature.{xml,tmpl}
	------------------------
	An enveloping signature with four references to the same object,
	which demonstrate the exclusive canonicalization transform in
	four combinations: with or without comments and with or without
	an inclusive namespace prefix list ("bar #default").  KeyInfo
	contains the KeyName and the ECKeyValue of the signing key.


	README.txt
	----------
	This file.


Original sample
===============

The original sample document was produced by Merlin Hughes
(Baltimore Technologies, Ltd.) in January 2002 and is distributed in
the tests/merlin-exc-c14n-one/ folder.
