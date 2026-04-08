# XML Security Library Tutorial

This tutorial explains how to use XML Security Library to perform
XML Digital Signature and XML Encryption operations. For the complete
API reference, see the [XML Security Library API Reference](../api/index.md).
For code examples, see the [XML Security Library Examples](../examples/index.md).


## Table of Contents

* [Building the library](install.md) — Building and installing
the XML Security Library
* [Compiling your application](compiling-and-linking.md) — Compiling
and linking your application with XML Security Library
* [Initialization and shutdown](init-and-shutdown.md) — Initializing and
shutting down the XML Security library and its dependencies
* [Signing and encrypting documents](sign-and-encrypt.md) — Signing XML
documents and encrypting data using templates
* [Creating dynamic templates](creating-templates.md) — Programmatically
constructing signature and encryption templates
* [Verifying and decrypting documents](verify-and-decrypt.md) — Verifying
signatures and decrypting encrypted documents
* [Keys](using-keys.md) — Key structure and key data objects
* [Keys manager](using-keysmngr.md) — Managing keys with the built-in store,
using keys manager for operations, and implementing custom stores
* [Using X509 certificates](using-x509-certs.md) — Signing and verifying with
X509 certificates
* [Using context objects](using-contexts.md) — Controlling operations and
restricting allowed transforms via context objects
* [Transforms and transform chains](using-transforms.md) — Transform model and
processing pipeline
* [Appendix](appendix.md) — Signature and Encryption class diagrams

## Overview

The XML Security Library supports XML Digital Signature and
XML Encryption. It is based on LibXML/LibXSLT and can use almost any
cryptographic library (currently, there is out-of-the-box support for
OpenSSL, Microsoft Crypto API, Microsoft Cryptography API: Next
Generation (CNG), GnuTLS, GCrypt, and NSS).

## XML Security Library Structure

To support different crypto engines, the XML Security Library is split
into two parts: the core library (xmlsec) and the crypto library
(xmlsec-openssl, xmlsec-mscrypt, xmlsec-mscng,
xmlsec-gnutls, xmlsec-gcrypt, xmlsec-nss, ...).

### Figure: The library structure and dependencies
![The library structure and dependencies](images/structure.png)

The core library has no dependencies on any crypto library and
implements all engines as well as all non-crypto transforms (XML
parser, C14N transforms, XPath and XSLT transforms, ...). The XML
Security Crypto library implements crypto transforms, crypto key data,
and key data stores. An application links against a particular XML
Security Crypto library (or even multiple libraries), but the
application code itself can still be general enough that switching the
crypto engine requires changing only a few #include directives.
