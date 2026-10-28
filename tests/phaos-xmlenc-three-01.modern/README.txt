Phaos XML Encryption Test Suite "phaos-xmlenc-three-01" (Modernized)
=====================================================================

The files in this folder are the modernized versions of the documents in
tests/phaos-xmlenc-three-01/.  The original suite (produced with the Phaos
XML toolkit) uses several DEPRECATED and/or DISCOURAGED algorithms
(3DES, RSA PKCS#1 v1.5 key transport, SHA-1 with RSA-OAEP, default
MGF1-SHA1) together with a weak, expired 1024-bit RSA key and short-lived
local symmetric keys.  The original suite and its keys are unchanged in
tests/phaos-xmlenc-three-01/.

The conversions are:

	- 3DES (tripledes-cbc and kw-tripledes) was replaced with AES
	  (aes128/192/256-cbc and kw-aes128/192/256);
	- RSA PKCS#1 v1.5 key transport was replaced with RSAES-OAEP
	  (MGF1-SHA2/3 and SHA-2/3 DigestMethod);
	- the SHA-1 DigestMethod and the implicit MGF1-SHA1 used with
	  RSAES-OAEP in the original suite were replaced with SHA-2/3
	  digests and explicit MGF1-SHA2/3 parameters;
	- the original 1024-bit RSA key ("my-rsa-key") and the local
	  symmetric keys ("my-aes128/192/256-key", "my-tripledes-key")
	  are replaced with the keys from tests/keys/: the AES keys
	  test-aes128, test-aes192 and test-aes256 from
	  tests/keys/keys.xml and the 4096-bit RSA key
	  "TestKeyName-rsa-4096" from tests/keys/rsa/;
	- the tests that already used modern algorithms (AES-CBC data
	  encryption with AES key wrap) were kept as-is; only the keys
	  were replaced.

The per-test correspondence between the original and the modernized
files is:

	original                                  modernized
	enc-element-3des-kt-rsa1_5                enc-element-aes256-kt-rsa_oaep_sha256_mgf1_sha256
	enc-element-3des-kt-rsa_oaep_sha1         enc-element-aes256-kt-rsa_oaep_sha384_mgf1_sha384
	enc-element-3des-kt-rsa_oaep_sha256       enc-element-aes256-kt-rsa_oaep_sha256_mgf1_sha512
	enc-element-3des-kt-rsa_oaep_sha512       enc-element-aes256-kt-rsa_oaep_sha512_mgf1_sha384
	enc-element-aes128-kt-rsa1_5              enc-element-aes128-kt-rsa_oaep_sha256_mgf1_sha256
	enc-element-aes128-kt-rsa_oaep_sha1       enc-element-aes128-kt-rsa_oaep_sha384_mgf1_sha384
	enc-element-aes192-kt-rsa_oaep_sha1       enc-element-aes192-kt-rsa_oaep_sha256_mgf1_sha256
	enc-text-aes192-kt-rsa1_5                 enc-text-aes192-kt-rsa_oaep_sha256_mgf1_sha256
	enc-content-aes256-kt-rsa1_5              enc-content-aes256-kt-rsa_oaep_sha256_mgf1_sha256
	enc-text-aes256-kt-rsa_oaep_sha1          enc-text-aes256-kt-rsa_oaep_sha256_mgf1_sha256
	enc-element-3des-kw-3des                  enc-element-aes256-kw-aes192
	enc-content-aes128-kw-3des                enc-content-aes128-kw-aes192
	enc-content-3des-kw-aes192                enc-content-aes256-kw-aes192
	enc-text-3des-kw-aes256                   enc-text-aes256-kw-aes256
	enc-element-aes128-kw-aes128              enc-element-aes128-kw-aes128 (unchanged)
	enc-element-aes128-kw-aes256              enc-element-aes128-kw-aes256 (unchanged)
	enc-element-aes192-kw-aes192              enc-element-aes192-kw-aes192 (unchanged)
	enc-element-aes256-kw-aes256              enc-element-aes256-kw-aes256 (unchanged)
	enc-content-aes192-kw-aes256              enc-content-aes192-kw-aes256 (unchanged)
	enc-text-aes128-kw-aes192                 enc-text-aes128-kw-aes192 (unchanged)
	bad-alg-enc-element-aes128-kw-3des       bad-alg-enc-element-aes128-kw-aes256

The "element", "content" and "text" prefixes keep the original meaning:
"element" encrypts the <CreditCard> element itself, "content" encrypts
the content of the <CreditCard> element and "text" encrypts the content
of the <Number> element.

The two negative tests are kept from the original suite:

	- bad-alg-enc-element-aes128-kw-aes256.xml
	  a valid AES-256 key wrap of a 32-byte key combined with the
	  aes128-cbc data encryption algorithm; decryption must fail with
	  a key size mismatch;
	- the "missing key" negative test re-uses
	  enc-content-aes256-kt-rsa_oaep_sha256_mgf1_sha256.xml and
	  expects decryption to fail because the RSA private key is not
	  provided.

Every test has an unsigned template <name>.tmpl with a matching
pre-encrypted <name>.xml file.  Where the harness compares the
decryption result, the expected plaintext is stored in <name>.data
(all .data files contain the same payment document).

The four legacy key-agreement files from the original suite
(enc-element-{3des,aes128,aes192,aes256}-ka-dh.xml) use the unsupported
legacy DH key agreement with X.509 certificates and a 1024-bit key.
They were never registered as tests (they have no .tmpl/.data files and
are only mentioned in comments in tests/testEnc.sh), so they are not
converted or copied into this folder.
