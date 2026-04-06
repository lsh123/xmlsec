# XML Security Library: Frequently Asked Questions

## 0. Where can I read more about XML Signature and XML Encryption?

First of all, read the original specifications: [XML Digital Signature](http://www.w3.org/Signature/) and
[XML Encryption](http://www.w3.org/Encryption/). Also there are [several books](related.md)
available that can help you to get started.

## 1. License(s).

### 1.1. Licensing Terms for XMLSec library. {#section_1_1}

XML Security Library is released under the [MIT License](http://www.opensource.org/licenses/mit-license.html),
see the file Copyright in the distribution for the precise wording.

### 1.2. Can I use xmlsec with proprietary application or library? Can I use xmlsec with a GNU GPL application or library? {#section_1_2}

Probably, you will need to ask a lawyer. But IANAL answer can be found in the following table:

| XML Security Library module | Dependencies | Dependencies Licenses | Using with proprietary code | Using with MIT/BSD code | Using with GPL code |
|---|---|---|---|---|---|
| xmlsec-core | [LibXML2](http://xmlsoft.org), [LibXSLT](http://xmlsoft.org/XSLT) | MIT License | Yes | Yes | Yes |
| xmlsec-openssl | [OpenSSL](http://www.openssl.org) | [OpenSSL licenses](https://www.openssl.org/source/license.html) | Yes | Yes | It's complicated, see [OpenSSL FAQ](https://www.openssl.org/docs/faq.md) for more details |
| xmlsec-nss | [NSS](http://www.mozilla.org/projects/security/pki/nss/) | MPLv2 | Yes | Yes | Yes |
| xmlsec-gnutls | [GnuTLS](http://www.gnu.org/software/gnutls/) | LGPLv2.1+ | It's complicated, talk to a lawyer | Yes | Yes |
| xmlsec-mscrypto and xmlsec-mscng | Windows OS | Microsoft licensing, part of Windows OS. | It's complicated, talk to a lawyer | It's complicated, talk to a lawyer | It's complicated, talk to a lawyer |
| xmlsec-gcrypt | [LibGCrypt](https://gnupg.org/software/libgcrypt/) | LGPLv2.1+ | It's complicated, talk to a lawyer | Yes | Yes |

If you have questions about XML Security Library licensing then feel free to send these questions
to the [XMLSec GitHub Discussions](https://github.com/lsh123/xmlsec/discussions).

## 2. Building XMLSec.

### 2.1. Where can I get xmlsec? {#section_2_1}

See XML Security Library [download page](http://www.aleksey.com/xmlsec/).

### 2.2. How to compile xmlsec? {#section_2_2}

On Unix just follow the "standard":

```
gunzip -c xmlsec-<version>.tar.gz | tar xvf -
cd xmlsec-<version>
mkdir build
cd build
../configure --help
../configure [configure options]
make
make check
make install
```

On Windows the process is more complicated. Please check readme file in
the `xmlsec-<version>/win32` folder.

### 2.3. What other libraries are needed to compile/install xmlsec? {#section_2_3}

See [Download page](download.md) for detailed list.

### 2.4. Why does make check fail for some tests? {#section_2_4}

The most likely reason is that some features might require additional configuration (e.g. installing
and configuring GOST plugins for OpenSSL and MSCrypto). Otherwise, please submit
a [bug report](http://www.aleksey.com/xmlsec/bugs.html) and I'll try to fix it.

### 2.5. I got the xmlsec source code from GitHub and there is no `configure` script. Where can I get it? {#section_2_5}

The `configure` (and several other files) are generated. Use the `autogen.sh` script to regenerate these files:

```
mkdir build
cd build
../autogen.sh [configure options]
make
...
```

### 2.6. I do not need all these features supported by xmlsec. Can I disable some of them? {#section_2_6}

Yes, you can. Please run `configure --help` for the list of possible configuration options.

### 2.7. I am compiling XMLSec library on Windows and it does not compile or crashes right after the launch. Can you help me? {#section_2_7}

There are several possible reasons why you might have problems on Windows:

- **Incorrect MS C runtime libraries.**
  Windows basically has multiple C runtimes. First, there is one called `libc.lib` and it can
  only be linked to statically. The other is called `msvcrt.dll` and can only be linked
  to dynamically. The first one occurs in its single-threaded and multithreaded variants.
  Then for each of the libraries above, there are both debug and release version (we are at **six**
  runtimes!). Next, different versions of Microsoft Visual C/C++ have different runtimes
  which aren't compatible with each other (e.g. MSVC 6.0 runtime is not compatible with .NET 2003 runtime).
  The rule is simple: exactly the same runtime must be used throughout the application and **all**
  the libraries used by the application (e.g. XMLSec, LibXML2, LibXSLT, ...).

- **Mismatched compilation parameters.**
  The XMLSec library and the application should use the **same** defines. For example, when linking
  statically, the `#define XMLSEC_STATIC` or `/DXMLSEC_STATIC=1` should be used
  (and same applies to `LIBXML_STATIC` and `LIBXSLT_STATIC` defines). These defines
  are critical on Windows (e.g. to ensure `__declspec(dllimport)` is done correctly) but have
  no effect on Unix.

## 3. Using XMLSec.

### 3.1. xmlSecDSigCtxValidate() function returned 0. Does this mean that the signature is valid? {#section_3_1}

**No!** The `xmlSecDSigCtxValidate()` function returns 0 when there are no *processing*
errors during signature validation (i.e. the document has correct syntax, all keys were found, etc.).
The signature is valid if and only if the `xmlSecDSigCtxValidate()` function returns 0 **and**
the `status` member of the `xmlSecDSigCtx` structure is equal to `xmlSecDSigStatusSucceeded`.

### 3.2. I am trying to sign a part of XML document using an "Id" attribute but it does not work. Do you support "Id" attributes at all? {#section_3_2}

Yes, the `Id` attributes are supported by both XMLSec and LibXML2 libraries. However, you have to
tell LibXML2/XMLSec what is the name of the ID attribute. XML specification does not require ID attribute to
have name "ID", "Id" or "id". It can be anything you want! There are several ways to declare an ID attribute:

- **Use DTD.** For example, the following DTD declares `Id` attribute in `Data` node to be
  an XML ID attribute:

  ```
  <!DOCTYPE test [
  <!ATTLIST Data Id ID #IMPLIED>
  ]>
  ```

  The DTD might be directly included in the XML file or located in a standalone file. In the second case, you might
  load the DTD in [xmlsec command line utility](xmlsec-man.md) with the `--dtd-file` option.

- **Use xml:id.** The [xml:id](http://www.w3.org/TR/xml-id/) spec allows to declare
  an ID attribute in the schema or DTD.

- **Use --id-attr for [xmlsec command line utility](xmlsec-man.md).** The `--id-attr` command
  line option allows to quickly declare an ID attribute for [xmlsec command line utility](xmlsec-man.md).

- **Use xmlAddID function.** If you are writing an application, you can declare an ID attribute using
  the `xmlAddID` LibXML2 function.

### 3.3. I am trying to sign an XML document and I have a warning about "empty nodes set". Should I worry about this? {#section_3_3}

Most likely **yes**. When it's not an error from specification point of view, I can hardly imagine
a real world case that requires signing an empty nodes set (i.e. signing an empty string). Most likely,
you have this error because you are trying to use an ID attribute and you did not declare the ID attribute
(see [section 3.2](#section_3_2) about ID attributes).

### 3.4. I am trying to sign/validate a document but xmlXPtrEval function can't evaluate "xpointer(id('XXXXXXX'))" expression. What's wrong? {#section_3_4}

First of all, read [section 3.2](#section_3_2) about ID attributes. If you have tried to declare
the required ID attribute and you still have problems then it is likely working with the Visa 3D protocol.
This protocol tries to reference to an "id" attribute defined as CDATA instead of ID in the DTD (it is
impossible in XML as described in [section 3.2](#section_3_2)). Even worse, the value of the
Visa 3D "id" attribute may start from number or contain "+" or "/" and this breaks the
[XML specification](http://www.w3.org/TR/REC-xml#sec-attribute-types) again. The right solution
for this problem is to change Visa 3D protocol. As a practical solution, try (on your own risk) the "Visa 3D hack"
in xmlsec:

- First, register ID attributes manually (using either `xmlAddID` function or
  `--id-attr` option for [xmlsec command line utility](xmlsec-man.md)).

- Second, enable the "Visa 3D hack" in XML DSig context (using either `dsigCtx->flags |= XMLSEC_DSIG_FLAGS_USE_VISA3D_HACK`
  or `--enable-visa3d-hack` option for [xmlsec command line utility](xmlsec-man.md)).

**This is a hack. You are warned!**

**UPDATE:** It appears that a newer version (November, 2005) of the Visa3D DTD has this problem fixed and
now "id" attribute is declared as ID correctly.

### 3.5. The XMLSec library or XMLSec command line tool fails because the key cannot be found. What's wrong? {#section_3_5}

There might be multiple reasons for the "key cannot be found error":

- **KeyValue or DEREncodedKeyValue nodes are disabled by default.** The `KeyValue` and `DEREncodedKeyValue`
  nodes allow definition of the key value directly in an XML file. This creates a security risk because there is no mechanism
  to verify the key origin (and for example, this enables to create "fake" signatures). Thus, the `KeyValue` and
  `DEREncodedKeyValue` nodes are disabled by default. Yet, in some use cases the use of these nodes in XML file
  can be appropriate. If you verify that these nodes do not present security concerns for your application, then you can
  re-enable `KeyValue` and `DEREncodedKeyValue` nodes using the `--enabled-key-data` option
  for the [xmlsec command line utility](xmlsec-man.md), or by setting the `keyInfoCtx->enabledKeyData`
  parameter in your application.
  For example, `--enabled-key-data rsa,key-value,x509` will populate an `<RSAKeyValue>` element (and keep
  `<X509Data>` enabled) when the template contains matching `<KeyValue/>` and `<X509Data/>` placeholders.
  **THIS IS NOT SECURE AND NOT RECOMMENDED.**

- **Key is not referenced in KeyInfo node (or this node is not included).** If a key is not referenced in the XML file then it
  creates a potential security risk because the key is no longer coupled with signature (the `KeyInfo` node is signed
  during the XML signature process and its integrity is validated during XML signature verification). Yet, in some use cases not
  using the `KeyInfo` node to specify the key can be appropriate. If you verify that this does not present a security
  concern for your application, then you can enable "lax" key search mode by using `--lax-key-search` option for the
  [xmlsec command line utility](xmlsec-man.md), or by setting `keyInfoCtx->flags |= XMLSEC_KEYINFO_FLAGS_LAX_KEY_SEARCH;`
  flag in your application.
  **THIS IS NOT SECURE AND NOT RECOMMENDED.**

- **Certificate cannot be verified.** See the next [question 3.6](#section_3_6) in this FAQ.

### 3.6. The XMLSec library or XMLSec command line tool fails because the certificate cannot be verified. What's wrong? {#section_3_6}

There might be several reasons why XMLSec library cannot verify a certificate:

- First, check that both trusted (root) and untrusted certificates from the certificate chain are provided to
  the XMLSec library or command line tool (e.g. in the XML file, or loaded into the keys manager,
  or available in the crypto library certificates store, or provided in the command line, or ...).

- Check if any of the certificates in the certificate verification chain expired.
  The [XML Digital Signature](http://www.w3.org/Signature) specification does not have a standard way
  to include the signature timestamp. If you decide to add timestamp to your signature, then consider
  signing the timestamp along with other data. If you verify that changing signature verification time from "now"
  to some other value does not present a security concern for your application, then you can use
  `--verification-time <time>` option (where `<time>` is the local system time in the
  `YYYY-MM-DD HH:MM:SS` format), or by setting `keyInfoCtx->certsVerificationTime`
  parameter in your application.

- Older certificates that use MD5 or SHA1 hashes might be rejected by newer cryptographic libraries because these
  algorithms are no longer considered secure. If you verify that this does not present a security concern for your
  application, then you can re-enable these algorithms (and also skip some other strict certificate verification
  checks) by using the `--X509-skip-strict-checks` option for the [xmlsec command line utility](xmlsec-man.md),
  or by setting `keyInfoCtx->flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS;` flag in your application.
  **THIS IS NOT SECURE AND NOT RECOMMENDED.**

- Lastly, you can use the `--insecure` option for the [xmlsec command line utility](xmlsec-man.md),
  or set `keyInfoCtx->flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;` flag in your application to
  completely disable the certificates verification. Disabling certificate verification creates a security risk because
  there is no mechanism to verify the key origin (and for example, this enables to create "fake" signatures).
  **THIS IS NOT SECURE AND NOT RECOMMENDED.**

### 3.7. I really like the XMLSec library but it is based on OpenSSL and I have to use another crypto library in my application. Can you write code to support my crypto library? {#section_3_7}

The XMLSec library has a very modular structure and there should be no problem with using another crypto library.
For example, XMLSec already supports NSS, GnuTLS, GCrypt and multiple Microsoft Crypto APIs. If your favorite
cryptographic library is not supported by XMLSec then you can either write integration yourself or contact me
to discuss possible options.

### 3.8. I really like the XMLSec library but it does not have cipher or transform that I need. Can you write code for me? {#section_3_8}

The XMLSec library has a very modular structure and it is easy to add any cipher or other transform. You can
either write integration yourself or contact me to discuss possible options.

### 3.9. I am trying to validate a signature created by another software but validation fails. What's wrong? {#section_3_9}

There might be many reasons for the failures and most likely cause is the incorrect implementation of the
XMLDSig specification by the other software package. XMLSec library tries to handle as many issues as possible
automatically (e.g. missing or added leading zeros in the signature value in many Java implementations).
Another known problem is using ASN1 encoding for ECDSA signatures and you can try
`--enable-asn1-signatures-hack` option for [xmlsec command line utility](xmlsec-man.md) or set
`dsigCtx->flags |= XMLSEC_DSIG_FLAGS_USE_ASN1_SIGNATURE_VALUES;` flag on the XML DSig context (this is a hack
and can cause interoperability problems). If nothing works, then you will need to reach out to the authors of
another software packet and ask them to help you debug the issue. Use `--store-references` and
`--store-signatures` options for the [xmlsec command line utility](xmlsec-man.md) to get pre-digest and
pre-signatures buffers from XMLSec and compare those against the similar buffers from the another software as
a first step in debugging process.

### 3.10. I am trying to validate a signature created by XMLSec with another software but validation fails. What's wrong? {#section_3_10}

[Same advice](#section_3_9) as above applies.

