Signature Using Canonical XML and Exclusive Canonical XML (Modernized)
======================================================================

The document in this folder is the same document as in
tests/merlin-c14n-three/, but re-signed with a modern algorithm and
with the key from tests/keys/ (instead of the original DSA key and
certificates):

	- the DSA signature was replaced with an ECDSA (P-256) signature:
	  dsa-sha1 -> ecdsa-sha256,
	- the SHA-1 digests were replaced with SHA-256 digests.

The document content, the 27 references (with the same XPath
expressions and the same canonicalization methods) and the c14n
reference outputs for the references (c14n-0.txt through
c14n-26.txt) are unchanged: the C14N 1.0 canonicalization methods
are not deprecated.  c14n-27.txt contains the canonical form of the
updated <SignedInfo> element.

Like the original document, the signature demonstrates
canonicalization behaviour when parts of the namespace axis are
excluded or included.  The same examples are repeated for canonical
XML, exclusive canonical XML and exclusive canonical XML with an
inclusive namespace prefix list.  Some examples repeat the same
behaviour with different XPath expressions.

Each signed example has a <name>.xml file and a matching unsigned
template <name>.tmpl.  The template contains empty <DigestValue> and
<SignatureValue> elements and an empty <KeyValue> element that
xmlsec1 fills in when signing.

Keys and certificates (in tests/keys/)
--------------------------------------

	ec/ec-prime256v1-key{,-win}.p12
	------------------------------
	The EC (P-256) private key with the full certificate chain
	(ec-prime256v1-cert, ca2cert, cacert) in PKCS#12 format.
	Password is "secret123".  Used to sign the example (signing key
	name "TestKeyName-ec-prime256v1").

Contents of merlin-c14n-three.modern
====================================

	signature.{xml,tmpl}
	--------------------
	An enveloping signature over the document with 27 references
	using the XPath transform in combination with canonical XML,
	exclusive canonical XML and exclusive canonical XML with an
	inclusive namespace prefix list.  KeyInfo contains the KeyName
	and the ECKeyValue of the signing key.  The X509Data element
	from the original KeyInfo (with the original Baltimore
	certificates) was removed.


	c14n-0.txt ... c14n-26.txt
	--------------------------
	The intermediate canonicalized output of the 27 references
	(c14n-N.txt is the canonicalized output of the Nth
	reference).  Note that some references produce identical
	canonicalized output (and some produce empty output), so the
	corresponding files contain identical (or empty) content,
	exactly as in the original sample set.


	c14n-27.txt
	-----------
	The canonical form of the <SignedInfo> element (the data that
	is signed).


	README.txt
	----------
	This file.


Original sample
===============

The original sample document and certificates were produced by
Merlin Hughes (Baltimore Technologies, Ltd.) in May 2002 and are
distributed in the tests/merlin-c14n-three/ folder.
