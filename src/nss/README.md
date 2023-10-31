# XMLSec Library: XMLSEC-NSS

## What version of NSS?
NSS 3.35 or greater and NSPR 4.18 or greater are required.

## Keys manager

`xmlsec-nss` key manager uses a custom Keys Store, and a custom X509 Store.
The custom Keys Store and the X509 Store use the NSS database as the underlying
store for public/private keys, Certs and CRLs.

The NSS Keys store uses the XMLSEC Simple Keys Store on top of the NSS repository.
The reason for this is that XMLSEC's generic adoptkey/getKey functions use a
XMLSEC key object that contains more attributes than the raw NSS key object,
and the getkey function may use a combination of one or more of these attributes
(name, type, usage, Id) to find a key. There is no straightforward 1-1 mapping
between XMLSEC's adoptkey/getkey and NSS's APIs.

For example, the store may be asked to adopt a symmetric key, and later asked
to find it just by name. Or the store may be asked to adopt a private key
just by its type, and later asked to find it just by type. The key returned
by getKey is expected to contain all the attributes that were present at the
time of adoptkey - NSS store does not provide a way to store app-specific
attributes.

When a key is adopted by the NSS Keys Store, it is simply saved in the
XMLSEC Simple Keys Store. It is not saved into the NSS database. The only
way to load keys into the NSS database is with a load operation through
the XMLSEC API or via an administrator operation.

When a getKey is done on the NSS Keys Store, it first checks the Simple
Keys Store. If the key is found there, it is returned. If not, the key
is searched in the NSS database. If found, the key is stored in the
Simple Keys Store before it is returned.


Thus, the various sources for keys/certs/crls for an XMLSEC-NSS application
are:
- elements in XML documents
- PKCS12 and DER files
- NSS Database


## Known issues / limitations

1) NSS needs to provide a way to convert a DER integer string to an ASCII
decimal string. Once NSS is fixed, the function xmlSecNssASN1IntegerWrite
in src/nss/x509.c needs to be implemented. Also see:
    - [NSS bug](http://bugzilla.mozilla.org/show_bug.cgi?id=212864)
    - [xmlsec bug](http://bugzilla.gnome.org/show_bug.cgi?id=118633)

2) `CERT_FindCertByNameString` does not work in all cases. Also see:
    - [NSS bug](http://bugzilla.mozilla.org/show_bug.cgi?id=210709)
    - [xmlsec bug](https://github.com/lsh123/xmlsec/issues/3)

3) `CERT_FindCertBySubjectKeyID` does not work in all cases. Also see:
    - [NSS bug](http://bugzilla.mozilla.org/show_bug.cgi?id=211051)
    - [xmlsec bug](https://github.com/lsh123/xmlsec/issues/4)

4) Finding a cert by Issuer & Serial Number needs the ability to
convert an ASCII decimal string to a DER integer string. Filed
an RFE against NSS. Once fixed, `xmlSecNssNumToItem` in `nss/x509vfy.c`
needs to be changed to use the new function(s) provided. Also see:
    - [NSS bug](http://bugzilla.mozilla.org/show_bug.cgi?id=212864)
    - [xmlsec bug](http://bugzilla.gnome.org/show_bug.cgi?id=118633)

5) RIPEMD160 Digest and RIPEMD160 HMAC is not supported by NSS. These
algorithms are obsolete and there are no plans to support those in xmlsec.
Also see:
    - [xmlsec bug](https://github.com/lsh123/xmlsec/issues/5)

6) AES Key wrap algorithm is implemented in NSS but not exposed due to
some bug src/nss/kw_aes.c uses a workaround which should be removed
when the bug is fixed. Also see:
    - [NSS bug](http://bugzilla.mozilla.org/show_bug.cgi?id=213795)
    - [xmlsec bug](https://github.com/lsh123/xmlsec/issues/6)

7) Not all file formats are supported
    - `xmlSecNssAppKeyLoadEx()`: This function loads a PKI key from a file.
        - `xmlSecKeyDataFormatDer`: supported (note that `xmlsec-nss` expects
        private key in DER file to be in PrivateKeyInfo format and private keys
        in the xmlsec test suite aren't in that format);
        - `xmlsecKeyDataFormatPkcs12`: supported;
        - `xmlSecKeyDataFormatPkcs8Pem`: NOT supported
        - `xmlSecKeyDataFormatPkcs8Der`: NOT supported

    - `xmlSecNssAppCertLoad()`: This function loads an X509 cert from a file.
        - `xmlSecKeyDataFormatDer`: supported
        - `xmlSecKeyDataFormatPem`: NOT supported

9) The distinction between "trusted" and "untrusted" certificates in
xmlsec-openssl is maintained because the OPENSSL application (and
not the OPENSSL library) has to maintain a cert store and verify
certificates. With NSS, no such distinction is necessary in the
application. (Note from Aleksey: Not sure that I understand this point but thats
what Tej wrote).

10) NSS doesn't support `emailAddress` in the cert subject. There is a hack
that needs to be removed in `xmlSecNssX509FindCert` function (`nss/x509vfy.c`).
 Also see:
    - [NSS bug](https://bugzilla.mozilla.org/show_bug.cgi?id=561689)

11) CRLs from xml document support is not working at all.
