XML Encryption + Signature Interop Test Vectors "merlin" (2002, Modernized)
==========================================================================

The files in this folder are the modernized versions of the documents in
tests/merlin-xmlenc-five/
(https://www.w3.org/2002/03/merlin-xmlenc/), the 5th round of the W3C
XML Encryption interoperability tests ("Merlin").  The original suite uses
several DEPRECATED and/or DISCOURAGED algorithms (3DES, RIPEMD-160,
RSA PKCS#1 v1.5 key transport, SHA-1 with RSA-OAEP) together with weak,
expired 1024-bit keys.  The original suite and its keys are unchanged in
tests/merlin-xmlenc-five/.

The conversions are:

	- 3DES (tripledes-cbc and kw-tripledes) was replaced with AES
	  (aes128/192/256-cbc and kw-aes128/192/256).  Each test uses
	  the AES key sizes that its algorithms require: the data key
	  matches the *-cbc algorithm and the key wrap key matches the
	  kw-aes* algorithm;
	- RSA PKCS#1 v1.5 key transport was replaced with RSAES-OAEP
	  (MGF1-SHA256 and SHA-256 DigestMethod);
	- the SHA-1 DigestMethod used with RSAES-OAEP in the original
	  "encrypt-data-tripledes-cbc-rsa-oaep-mgf1p" test was replaced with
	  SHA-256 (the MGF1 hash is kept as SHA-1 there, since the original
	  file used the default MGF1 and only the digest was changed);
	- the RIPEMD-160 digest and HMAC/RIPEMD-160 signature algorithm
	  of the original "encsig-ripemd160-hmac-ripemd160-kw-tripledes"
	  test were replaced with SHA-256 and HMAC/SHA-256;
	- the original secret keys (bob/3DES, job/AES-128, jeb/AES-192,
	  jed/AES-256) and the 1024-bit RSA key are replaced with the keys
	  from tests/keys/: the AES keys test-aes128, test-aes192 and
	  test-aes256 from tests/keys/keys.xml and the 4096-bit RSA key
	  "TestKeyName-rsa-4096" from tests/keys/rsa/;
	- the two original RSA "encsig" tests
	  (encsig-hmac-sha256-rsa-1_5.xml and
	  encsig-hmac-sha256-rsa-oaep-mgf1p.xml) were merged into a single
	  modern test that uses RSAES-OAEP (MGF1-SHA256 and SHA-256
	  DigestMethod);
	- the encsig tests that already used modern algorithms
	  (SHA-256/SHA-384/SHA-512 digests, HMAC/SHA-2/3/512 signatures and
	  AES key wrap) were kept as-is; only the keys were replaced;
	- the four key-agreement tests that used the legacy Diffie-Hellman
	  KDF (the 2002 draft http://www.w3.org/2001/04/xmlenc#dh KDF with
	  SHA-512 / RIPEMD-160 digests and 1024-bit DH keys) were converted to
	  the current XML Encryption key-agreement specification:
	  http://www.w3.org/2009/xmlenc11#dh-es (explicit DH, "DH-ES") with
	  the ConcatKDF (http://www.w3.org/2009/xmlenc11#ConcatKDF) key
	  derivation function and a SHA-256 DigestMethod, using the 2048-bit
	  RFC 5114 group 3 DH keys from tests/keys/dhx/.  The legacy kw-tripledes
	  key wrap in one of the tests was replaced with kw-aes256.

The tests are split into two groups, following the original suite:

	- 14 XML Encryption tests, run by tests/testEnc.sh (execEncTest);
	- 7 "encsig" tests (XML Signature over encrypted content, per
	  https://www.w3.org/TR/xmlenc-sig), run by tests/testDSig.sh.

Every test has an unsigned template <name>.tmpl with a matching
pre-encrypted <name>.xml file.  Where the harness compares the
decrypted document against a reference file, the reference is stored
in <name>.data (the encsig tests have no .data files: they are
verified by checking the signature).


Keys (all in tests/keys/)
-------------------------

	keys.xml
	--------
	The AES keys test-aes128, test-aes192 and test-aes256 (in
	xmlsec "KeyName" form) used by the tests that carry the
	decryption key in a KeyName element.

	rsa/rsa-4096-key{,-win}.p12 and rsa/rsa-4096-pubkey.crt
	---------------------------------------------------------
	The RSA 4096-bit private key (password "secret123") and its
	certificate in DER format, used by all the RSAES-OAEP tests
	(key name "TestKeyName-rsa-4096").  The certificate is currently
	valid, so no --verification-gmt-time is needed.

	dhx/dhx-rfc5114-3-{first,second}-key.pem and
	dhx/dhx-rfc5114-3-{first,second}-pubkey.pem
	---------------------------------------------
	The 2048-bit RFC 5114 group 3 Diffie-Hellman key pairs
	("dhx-rfc5114-3-first" and "dhx-rfc5114-3-second") used by the
	DH-ES key-agreement tests.  The "first" key is the originator
	(the signing / encrypting side) and the "second" key is the
	recipient (the verifying / decrypting side).

	Note on the encsig session keys: like in the original suite
	(the original Readme says the signatures are "WITHOUT
	cryptographic merit; for example, key transport of an HMAC key
	is meaningless. These are provided solely for testing
	purposes"), the HMAC session key of the encsig tests is
	generated randomly by xmlsec1 at signing time (the key length
	equals the HMAC output length, e.g. 256 bits for
	HMAC/SHA-256).  The two DH-ES encsig tests are the exception:
	"encsig-hmac-sha256-kw-aes256-dh" still uses a random session
	key (wrapped by kw-aes256), but "encsig-hmac-sha256-dh" has no
	EncryptedKey, so the HMAC key is derived directly by the KAM
	from the shared secret (see the test description below).


Contents of merlin-xmlenc-five.modern
=====================================

XML Encryption tests (run by tests/testEnc.sh):

	encrypt-data-aes128-cbc.{xml,tmpl,data}
	--------------------------------------
	(original: encrypt-data-tripledes-cbc)
	An EncryptedData element with Type="#Data" (the encrypted
	document is stored in a separate file).  AES-128-CBC, key in
	KeyName (the original used the 3DES key "bob"; now the
	test-aes128 key).


	encrypt-content-aes256-cbc.{xml,tmpl,data}
	-----------------------------------------
	(original: encrypt-content-tripledes-cbc)
	The PaymentInfo content of a PurchaseOrder document, encrypted
	in-place.  AES-256-CBC (the original used the 3DES key "bob";
	now the test-aes256 key).


	encrypt-content-aes256-cbc-prop.{xml,tmpl,data}
	----------------------------------------------
	(original: encrypt-content-aes256-cbc-prop)
	Same as encrypt-content-aes256-cbc but with an
	EncryptionProperties element ("Contains a useless
	EncryptionProperty" in the original Readme).  Algorithms
	unchanged (AES-256-CBC, key "jeb" -> test-aes256).


	encrypt-element-aes192-cbc-ref.{xml,data}
	----------------------------------------
	(original: encrypt-element-aes192-cbc-ref)
	An EncryptedData element with Type="#Element" whose CipherData
	is a CipherReference: the ciphertext is not inline but stored
	in a CipherValue element elsewhere in the same document
	(reachable by an XPath Transform, in the same way as a
	Reference URI).  AES-192-CBC (key "jeb" -> test-aes192).
	No template file, since the ciphertext location depends on the
	document layout.


	encrypt-element-aes128-cbc-rsa-oaep-sha256.{xml,tmpl,data}
	---------------------------------------------------------
	(original: encrypt-element-aes128-cbc-rsa-1_5)
	An EncryptedData element with Type="#Element" (the Purchase
	element).  The session key is transported with RSAES-OAEP
	(MGF1-SHA256 and SHA-256 DigestMethod); the original used
	RSA PKCS#1 v1.5 (key "job" -> test-aes128, 1024-bit RSA key
	-> TestKeyName-rsa-4096).


	encrypt-data-aes256-cbc-rsa-oaep-sha256.{xml,tmpl,data}
	------------------------------------------------------
	(original: encrypt-data-tripledes-cbc-rsa-oaep-mgf1p)
	An EncryptedData element with Type="#Data".  AES-256-CBC,
	session key transported with RSAES-OAEP with the default
	MGF1 (SHA-1) and a SHA-256 DigestMethod (the original used
	tripledes-cbc and the SHA-1 DigestMethod; the MGF1-SHA1 part
	is kept to exercise the default-MGF1 code path).


	encrypt-data-aes256-cbc-rsa-oaep-mgf1p-sha256.{xml,tmpl,data}
	-----------------------------------------------------------
	(original: encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256)
	An EncryptedData element with Type="#Data".  AES-256-CBC,
	session key transported with RSAES-OAEP (MGF1-SHA256 and
	SHA-256 DigestMethod, plus OAEPparams); the original used
	tripledes-cbc.


	encrypt-data-aes256-cbc-kw-aes256.{xml,tmpl,data}
	------------------------------------------------
	(original: encrypt-data-aes256-cbc-kw-tripledes)
	An EncryptedData element with Type="#Data".  AES-256-CBC, the
	session key is wrapped with AES-256 (kw-aes256); the original
	wrapped it with 3DES (kw-tripledes, key "job" ->
	test-aes256).


	encrypt-content-aes128-cbc-kw-aes192.{xml,tmpl,data}
	---------------------------------------------------
	(original: encrypt-content-aes128-cbc-kw-aes192)
	The PaymentInfo content, AES-128-CBC, the session key wrapped
	with AES-192.  Algorithms unchanged (key "bob" ->
	test-aes192).


	encrypt-data-aes192-cbc-kw-aes256.{xml,tmpl,data}
	------------------------------------------------
	(original: encrypt-data-aes192-cbc-kw-aes256)
	An EncryptedData element with Type="#Data".  AES-192-CBC, the
	session key wrapped with AES-256.  Algorithms unchanged (key
	"job" -> test-aes256).


	encrypt-element-aes256-cbc-kw-aes128.{xml,tmpl,data}
	---------------------------------------------------
	(original: encrypt-element-tripledes-cbc-kw-aes128)
	An EncryptedData element with Type="#Element".  AES-256-CBC,
	the session key wrapped with AES-128 (the original used
	tripledes-cbc for the content, key "jeb" -> test-aes128).


	encrypt-element-aes256-cbc-retrieved-kw-aes256.{xml,data}
	--------------------------------------------------------
	(original: encrypt-element-aes256-cbc-retrieved-kw-aes256)
	An EncryptedData element with Type="#Element" that refers to
	an external EncryptedKey element (identified by a
	RetrievalMethod); the session key is wrapped with AES-256.
	Algorithms unchanged (key "jeb" -> test-aes256).  No template
	file, since the EncryptedKey is part of the document.


	encrypt-content-aes192-cbc-dh-sha256.{xml,tmpl,data}
	---------------------------------------------------
	(original: encrypt-content-aes192-cbc-dh-sha512)
	The PaymentInfo content, encrypted in-place with AES-192-CBC.
	The data key is derived from a DH-ES AgreementMethod
	(http://www.w3.org/2009/xmlenc11#dh-es) using ConcatKDF with a
	SHA-256 DigestMethod and the RFC 5114 group 3 keys
	(dhx-rfc5114-3-first / dhx-rfc5114-3-second); the original used
	the legacy 2002-draft DH KDF (dh-sha512) with 1024-bit DH keys.
	Only the backends that implement DH-ES (OpenSSL and MSCng) can
	decrypt this test; the harness skips it elsewhere.


	encrypt-element-aes256-cbc-kw-aes256-dh-sha256.{xml,tmpl,data}
	------------------------------------------------------------
	(original: encrypt-element-aes256-cbc-kw-aes256-dh-ripemd160)
	The Purchase element, encrypted in-place with AES-256-CBC.  The
	session key is wrapped with AES-256 (kw-aes256); the wrap key is
	derived from a DH-ES AgreementMethod using ConcatKDF with a
	SHA-256 DigestMethod and the RFC 5114 group 3 keys.  The
	original used kw-tripledes and the legacy 2002-draft DH KDF
	(dh-ripemd160) with 1024-bit DH keys.  As above, only run on
	backends that implement DH-ES.


"encsig" tests (XML Signature over encrypted content, run by
tests/testDSig.sh; the encrypted PaymentInfo content carries an
enveloping signature):

	encsig-sha256-hmac-sha256-kw-aes256.{xml,tmpl}
	---------------------------------------------
	(original: encsig-ripemd160-hmac-ripemd160-kw-tripledes)
	SHA-256 digest and HMAC/SHA-256 signature (the original used
	RIPEMD-160 for both), the HMAC key wrapped with AES-256 (the
	original wrapped it with 3DES, key "bob" -> test-aes256).


	encsig-sha256-hmac-sha256-kw-aes128.{xml,tmpl}
	---------------------------------------------
	(original: encsig-sha256-hmac-sha256-kw-aes128)
	Unchanged algorithms (SHA-256, HMAC/SHA-256, AES-128 wrap);
	only the keys were replaced (key "job" -> test-aes128).


	encsig-sha384-hmac-sha384-kw-aes192.{xml,tmpl}
	---------------------------------------------
	(original: encsig-sha384-hmac-sha384-kw-aes192)
	Unchanged algorithms (SHA-384, HMAC/SHA-384, AES-192 wrap);
	only the keys were replaced (key "jeb" -> test-aes192).
	Note: the SHA-384 digest uses the xmldsig-more#sha384 URI
	(xmlsec registers the SHA-384 digest under the
	http://www.w3.org/2001/04/xmldsig-more# namespace).


	encsig-sha512-hmac-sha512-kw-aes256.{xml,tmpl}
	---------------------------------------------
	(original: encsig-sha512-hmac-sha512-kw-aes256)
	Unchanged algorithms (SHA-512, HMAC/SHA-512, AES-256 wrap);
	only the keys were replaced (key "jed" -> test-aes256).


	encsig-hmac-sha256-rsa-oaep-sha256.{xml,tmpl}
	--------------------------------------------
	(original: encsig-hmac-sha256-rsa-1_5 and
	encsig-hmac-sha256-rsa-oaep-mgf1p, merged)
	SHA-256 digest and HMAC/SHA-256 signature; the HMAC key is
	transported with RSAES-OAEP (MGF1-SHA256 and SHA-256
	DigestMethod).  The original suite had two versions of this
	test (one with RSA PKCS#1 v1.5 and one with RSAES-OAEP
	MGF1/SHA-1); they were merged into a single test using
	RSAES-OAEP with the modern digest/MGF1 combination.


	encsig-hmac-sha256-dh.{xml,tmpl}
	------------------------------
	(original: encsig-hmac-sha256-dh)
	SHA-256 digest and HMAC/SHA-256 signature; the HMAC key is
	derived directly from a DH-ES AgreementMethod (no EncryptedKey)
	using ConcatKDF with a SHA-256 DigestMethod and the RFC 5114
	group 3 keys.  Because the HMAC signing method does not specify
	a key size, the derived key length defaults to the KDF digest
	output length (32 bytes for SHA-256).  The original used the
	legacy 2002-draft DH KDF with 1024-bit DH keys.  Only run on
	backends that implement DH-ES.


	encsig-hmac-sha256-kw-aes256-dh.{xml,tmpl}
	-----------------------------------------
	(original: encsig-hmac-sha256-kw-tripledes-dh)
	SHA-256 digest and HMAC/SHA-256 signature; the HMAC key is
	wrapped with AES-256 (kw-aes256) and the wrap key is derived
	from a DH-ES AgreementMethod using ConcatKDF with a SHA-256
	DigestMethod and the RFC 5114 group 3 keys.  The original used
	kw-tripledes and the legacy 2002-draft DH KDF with 1024-bit DH
	keys.  Only run on backends that implement DH-ES.


Files from the original suite that were NOT converted
-----------------------------------------------------

	decryption-transform.xml
	decryption-transform-except.xml
	The "xmlenc-decrypt" transform (RFC draft
	http://www.w3.org/TR/xmlenc-decrypt) is not implemented in
	xmlsec, so these tests cannot be run (they were already
	disabled in the original testEnc.sh).

	encrypt-element-aes256-cbc-carried-kw-aes256.xml
	This test is not decryptable: it relies on a CarriedKeyName in
	an external EncryptedKey, and decryption fails with
	KEY-NOT-FOUND even with the original keys.  It was already
	disabled in the original testEnc.sh.

The remaining files in the original folder (bad-encrypt-content-
aes128-cbc-kw-aes192.xml, plaintext.xml, and the key material:
keys.xml, ids.p12, rsa.p8, rsapriv.*, rsapub.pem, dsa.p8, dh0.p8,
dh1.p8) are not included here.  The first two were not referenced
by any test; the key material is used only by the original tests
in tests/merlin-xmlenc-five/ and is replaced by the keys from
tests/keys/ described above in the modernized tests.

The modernized RSAES-OAEP tests are only run when the crypto
backend supports the corresponding OAEP mode (see
tests/testrun.sh): the "encrypt-element-aes128-cbc-rsa-oaep-sha256",
"encrypt-data-aes256-cbc-rsa-oaep-mgf1p-sha256" and
"encsig-hmac-sha256-rsa-oaep-sha256" tests require the
xmlsec_feature_rsa_oaep_sha256 feature (digest and MGF1 both
SHA-256), while the "encrypt-data-aes256-cbc-rsa-oaep-sha256" test
(SHA-256 digest with the default MGF1-SHA1) additionally requires
the xmlsec_feature_rsa_oaep_sha1 and
xmlsec_feature_rsa_oaep_different_digest_and_mgf1 features.

The DH-ES key-agreement tests (the two "*-dh-sha256" encryption
tests and the two "encsig-hmac-sha256-*-dh" signature tests) are
only run when the crypto backend implements the DH-ES key
agreement method (currently OpenSSL and MSCng).  On the other
backends the required "dh" key data is not registered, so the
harness skips these tests rather than failing them.


README.txt
----------
This file.
