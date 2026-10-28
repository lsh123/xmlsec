XML Encryption 1.1 Core Interoperability Test Vectors 2012 (Modernized)
======================================================================

The files in this folder are the modernized versions of the vectors in
tests/xmlenc11-interop-2012/
(https://www.w3.org/TR/2012/NOTE-xmlenc-core1-interop-20121113/).  The
original suite (and its keys) is unchanged.  The original suite's
algorithms are already modern (AES-GCM, KW-AES, ECDH-ES/DH-ES with
ConcatKDF, DerivedKey with ConcatKDF/PBKDF2 and RSAES-OAEP); only the
deprecated/disallowed key material and one deprecated digest needed to
be replaced:

	- the deprecated SHA-1 DigestMethod of the RSA-2048
	  "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p" vector was
	  replaced with SHA-256.  The MGF1 hash of all four RSA-OAEP
	  vectors stays SHA-1 (the default MGF1, which the vectors use to
	  exercise the "digest != MGF1 hash" code path; MGF1-SHA1 is not
	  deprecated),
	- the 1024-bit MODP (RFC 2631 group 1) Diffie-Hellman keys of the
	  "cipherText__DH-1024__..." vector were replaced with the 2048-bit
	  MODP (RFC 5114 group 3) keys from tests/keys/dhx/, so the test
	  was renamed "cipherText__DH-2048__aes128-gcm__kw-aes128__dh-es__ConcatKDF",
	- all the original interop keys and certificates (RSA-2048/3072/4096,
	  EC P-256/P-384/P-521, DH-1024, the symmetric GCM key and the
	  KDF master keys) were replaced with the keys and certificates
	  from tests/keys/.

Every test has an unsigned template <name>.tmpl (with empty
<CipherValue/> elements that xmlsec1 fills in when encrypting) and a
matching pre-encrypted <name>.xml file (generated with xmlsec1 and
verified by an encrypt/decrypt round-trip against <name>.data).
The .data files are identical to the ones of the original suite.


Keys and certificates (all in tests/keys/)
------------------------------------------

	keys.xml
	--------
	The symmetric AES key "test-aes128" (in xmlsec "KeyName" form)
	used by the xenc11-example-AES128-GCM test (the original used the
	suite-local key "TestKeyName_GCM").

	rsa/rsa-2048-key{,-win}.p12 and rsa/rsa-2048-pubkey.crt
	--------------------------------------------------------
	The RSA 2048-bit private key (password "secret123") and its
	certificate in DER format.  Used by the
	"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p__Sha256" (the
	original "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p",
	replacing the original 2048-bit RSA key "TestRsa2048Key") and the
	"cipherText__RSA-2048__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1"
	(replacing the original 3072-bit key "TestRsa3072Key") tests.
	Key name is "TestKeyName-rsa-2048".

	rsa/rsa-4096-key{,-win}.p12 and rsa/rsa-4096-pubkey.crt
	--------------------------------------------------------
	The RSA 4096-bit private key (password "secret123") and its
	certificate in DER format.  Used by the
	"cipherText__RSA-4096__aes192-gcm__rsa-oaep-mgf1p__Sha256" (the
	original "cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256",
	replacing the original 3072-bit key) and the
	"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource"
	(replacing the original 4096-bit key "TestRsa4096Key", which keeps
	the original OAEPparams PSource value "dumm123",
	base64 "ZHVtbXkxMjM=") tests.  Key name is "TestKeyName-rsa-4096".

	ec/ec-prime256v1-key{,-win}.p12, ec/ec-prime256v1-pubkey.crt,
	ec/ec-prime256v1-second-key{,-win}.p12 and
	ec/ec-prime256v1-second-pubkey.crt
	---------------------------------------------------------------
	The EC (P-256) private keys (password "secret123") and their
	certificates in DER format, used by the P-256 ECDH-ES test
	(originator "TestKeyName-ec-prime256v1", recipient
	"TestKeyName-ec-prime256v1-second"; the original originator was the
	suite-local P-256 key "EC-P256").  The same pair
	pattern (ec-prime384v1 and ec-prime521v1, with the "-second"
	variant) is used by the P-384 and P-521 ECDH-ES tests.

	dhx/dhx-rfc5114-3-first-key{.pem,.der} and
	dhx/dhx-rfc5114-3-first-pubkey{.pem,.der}
	---------------------------------------------------------------
	The 2048-bit MODP (RFC 5114 group 3) Diffie-Hellman key pair
	"dhx-rfc5114-3-first".

	dhx/dhx-rfc5114-3-second-key{.pem,.der} and
	dhx/dhx-rfc5114-3-second-pubkey{.pem,.der}
	---------------------------------------------------------------
	The 2048-bit MODP (RFC 5114 group 3) Diffie-Hellman key pair
	"dhx-rfc5114-3-second".  Together with the "-first" pair they
	replace the original 1024-bit "DH-1024" key (the tests/keys dhx
	keys were already used as the recipient/second party in the
	original DH-ES test; here both parties come from tests/keys).

	hmackey.bin
	----------
	The raw binary key (the ASCII encoding of the word "secret") used
	as the DerivedKey master key (the <MasterKeyName> values
	"dkey", "dkey-pbkdf2", "dkey3" and "dkey3-pbkdf2") of the four
	dkey/dkey3 tests, passed with the --concatkdf-key: /
	--pbkdf2-key: xmlsec1 options.  The original suite used four
	suite-local master key files (dkey-concatkdf.bin,
	dkey3-concatkdf.bin, dkey-pbkdf2.bin, dkey3-pbkdf2.bin).


Contents of xmlenc11-interop-2012.modern
========================================

	xenc11-example-AES128-GCM.{xml,tmpl,data}
	----------------------------------------
	An EncryptedData element with Type="#Data" (16-byte binary
	plaintext).  AES-128-GCM, the key is in a KeyName element
	(TestKeyName_GCM -> test-aes128).  Unchanged algorithms.

	cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p__Sha256.{xml,tmpl,data}
	-----------------------------------------------------------------------
	(original: cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p)
	An EncryptedData element with Type="#Element" (the Purchase
	element of a PurchaseOrder document).  AES-128-GCM, the session
	key is transported with RSAES-OAEP with the default MGF1
	(SHA-1) and a SHA-256 DigestMethod (the original used the
	deprecated SHA-1 DigestMethod, replaced with SHA-256).  The
	RSA-2048 "TestRsa2048Key" key was replaced with
	TestKeyName-rsa-2048.

	cipherText__RSA-4096__aes192-gcm__rsa-oaep-mgf1p__Sha256.{xml,tmpl,data}
	-----------------------------------------------------------------------
	(original: cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256)
	Same as above but with a 4096-bit RSA key (TestKeyName-rsa-4096,
	replacing "TestRsa3072Key"), AES-192-GCM and a SHA-256
	DigestMethod (unchanged).

	cipherText__RSA-2048__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.{xml,tmpl,data}
	--------------------------------------------------------------------------
	(original: cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1)
	AES-256-GCM, RSAES-OAEP with a SHA-384 DigestMethod and MGF1
	SHA-1 (unchanged); the 3072-bit RSA key was replaced with
	TestKeyName-rsa-2048.

	cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.{xml,tmpl,data}
	---------------------------------------------------------------------------------
	(original: cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource)
	AES-256-GCM, RSAES-OAEP with a SHA-512 DigestMethod, MGF1 SHA-1
	and the original OAEPparams PSource value (unchanged); the
	4096-bit RSA key was replaced with TestKeyName-rsa-4096.

	cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.{xml,tmpl,data}
	----------------------------------------------------------------------------
	An EncryptedData element with Type="#Element".  AES-128-GCM, the
	session key is wrapped with AES-128 (kw-aes128); the wrap key is
	derived from an ECDH-ES key agreement (P-256) with a ConcatKDF
	(SHA-256, the original PartyUInfo/PartyVInfo values are kept).
	Algorithms unchanged; the originator key "EC-P256" (a
	suite-local key) was replaced with TestKeyName-ec-prime256v1
	(the recipient key is TestKeyName-ec-prime256v1-second).

	cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF.{xml,tmpl,data}
	----------------------------------------------------------------------------
	Same as above but with a P-384 ECDH-ES agreement, KW-AES-192 and
	AES-192-GCM (originator "EC-P384" -> TestKeyName-ec-prime384v1).

	cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF.{xml,tmpl,data}
	----------------------------------------------------------------------------
	Same as above but with a P-521 ECDH-ES agreement, KW-AES-256 and
	AES-256-GCM (originator "EC-P521" -> TestKeyName-ec-prime521v1).

	cipherText__DH-2048__aes128-gcm__kw-aes128__dh-es__ConcatKDF.{xml,tmpl,data}
	---------------------------------------------------------------------------
	(original: cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF)
	An EncryptedData element with Type="#Element".  AES-128-GCM, the
	session key is wrapped with AES-128 (kw-aes128); the wrap key is
	derived from a DH-ES key agreement with a ConcatKDF (SHA-256,
	the original PartyUInfo value is kept).  The 1024-bit MODP
	DH-1024 keys were replaced with the 2048-bit RFC 5114 group 3
	keys dhx-rfc5114-3-first / dhx-rfc5114-3-second.

	dkey-example-ConcatKDF-crypto.{xml,tmpl,data}
	--------------------------------------------
	An EncryptedData element with Type="#Data" (312-byte binary
	plaintext).  AES-256-CBC, the encryption key is a DerivedKey
	derived from the master key "dkey" with a ConcatKDF (SHA-256,
	the original AlgorithmID/PartyUInfo/PartyVInfo values are kept).
	Algorithms unchanged; the master key is now
	tests/keys/hmackey.bin.

	dkey3-example-ConcatKDF-crypto.{xml,tmpl,data}
	---------------------------------------------
	Same as dkey-example-ConcatKDF-crypto (master key "dkey3").

	dkey-example-PBKDF2-crypto.{xml,tmpl,data}
	-----------------------------------------
	Same as dkey-example-ConcatKDF-crypto, but the key is derived
	with PBKDF2 (HMAC-SHA-256 PRF, the original Salt,
	IterationCount and KeyLength values are kept; master key
	"dkey-pbkdf2").

	dkey3-example-PBKDF2-crypto.{xml,tmpl,data}
	------------------------------------------
	Same as dkey-example-PBKDF2-crypto (master key "dkey3-pbkdf2").


Notes
-----

	The four dkey/dkey3 test vectors of the original suite do not
	implement the AES CBC padding required by the specification
	(see tests/xmlenc11-interop-2012/README.md and the *-orig.data
	files there): their ciphertexts decrypt to 312 bytes, while the
	published 320-byte expected outputs are 8 bytes longer.  The
	modernized .xml files are generated by xmlsec1 itself (proper
	PKCS#7 padding), so the 312-byte .data files of this suite (which
	are identical to the "correct" .data files of the original
	suite) round-trip exactly.

	The pre-encrypted .xml files were generated with xmlsec1 1.3.x
	(OpenSSL backend).  The RSA-OAEP tests embed the tests/keys/
	certificates (X509Data) in the EncryptedKey KeyInfo, while the
	ECDH-ES/DH-ES tests identify the keys by KeyName only.
	Decryption only needs the private key, so the embedded
	certificates do not expire the tests (they are currently valid
	until 2126).

	The RSA-OAEP tests are only run when the crypto backend
	supports the corresponding OAEP mode (see tests/testrun.sh):
	"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p__Sha256" and
	"cipherText__RSA-4096__aes192-gcm__rsa-oaep-mgf1p__Sha256"
	(SHA-256 digest with the default MGF1-SHA1) require the
	xmlsec_feature_rsa_oaep_sha1 and
	xmlsec_feature_rsa_oaep_different_digest_and_mgf1 features,
	"cipherText__RSA-2048__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1"
	additionally requires xmlsec_feature_rsa_oaep_sha384 and
	"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource"
	requires xmlsec_feature_rsa_oaep_sha512.


README.txt
----------
This file.
