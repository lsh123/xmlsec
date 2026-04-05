# XML Security Library Tutorial

This tutorial describes how to use XMLSec Library to perform XML Digital Signatures and XML Encryption
operations. For the complete API reference, see the [XML Security Library API Reference](../api/index.md). For code examples, see the [XML Security Library Examples](../examples/index.md).

## Overview

XML Security Library provides support for XML Digital Signature and XML Encryption. It is based on LibXML/LibXSLT and can use practicaly any crypto library (currently there is "out of the box" support for OpenSSL, Microsoft Crypto API, Microsoft Cryptography API: Next Generation (CNG), GnuTLS, GCrypt and NSS).

## XML Security Library Structure

In order to provide the an ability to use different crypto engines, the XML Security Library is splitted in two parts: core library (xmlsec) and crypto library (xmlsec-openssl, xmlsec-mscrypt, xmlsec-mscng, xmlsec-gnutls, xmlsec-gcrypt, xmlsec-nss, ...).
> **Figure: The library structure and dependencies**
> ![The library structure and dependencies](images/structure.png)

The core library has no dependency on any crypto library and provides implementation of all the engines as well as support for all the non crypto transforms (xml parser, c14n transforms, xpath and xslt transforms,...). The XML Security Crypto library provides implementations for crypto transforms, crypto keys data and key data stores. Application is linked with particular XML Security Crypto library (or even libraries), but the actual application code might be general enough so switching crypto engine would be a matter of changing several #include directives.

## Table of Contents

1. [Building the Application](compiling-and-linking.md) — Compiling and linking with XML Security Library on Unix, Windows, and other platforms
2. [Initialization and Shutdown](init-and-shutdown.md) — Initializing and shutting down the library and its dependencies
3. [Signing and Encrypting Documents](sign-and-encrypt.md) — Signing XML documents and encrypting data using templates
4. [Creating Dynamic Templates](creating-templates.md) — Programmatically constructing signature and encryption templates
5. [Verifying and Decrypting Documents](verify-and-decrypt.md) — Verifying signatures and decrypting encrypted documents
6. [Keys](using-keys.md) — Key structure and key data objects
7. [Keys Manager](using-keysmngr.md) — Managing keys with the built-in store, using keys manager for operations, and implementing custom stores
8. [Using X509 Certificates](using-x509-certs.md) — Signing and verifying with X509 certificates
9. [Transforms and Transforms Chain](using-transforms.md) — Transform model and processing pipeline
10. [Using Context Objects](using-contexts.md) — Controlling operations and restricting allowed transforms via context objects
11. [Appendix](appendix.md) — Signature and Encryption class diagrams
