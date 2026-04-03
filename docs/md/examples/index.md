# XML Security Library Examples

This section contains several examples of using XML Security Library
to sign, verify, encrypt or decrypt XML documents.
For the XML Security Library tutorial and API reference, see the
[XML Security Library Tutorial](../tutorial/index.md).

## Signing a template file

Signs an XML document using a pre-created signature template file and a PEM private key.

[Read more →](sign1.md)

## Signing a dynamically created template

Signs an XML document using a dynamically created signature template.

[Read more →](sign2.md)

## Signing enveloped signature with X509 certificate

Creates an enveloped XML Digital Signature using an X509 certificate.

[Read more →](sign3.md)

## Signing a node by ID with X509 certificate

Signs a specific XML node referenced by ID attribute using an X509 certificate.

[Read more →](sign4.md)

## Verifying a signature with a single key

Verifies an XML Digital Signature using a single public key loaded from a PEM file.

[Read more →](verify1.md)

## Verifying a signature with keys manager

Verifies an XML Digital Signature using a keys manager loaded with multiple keys.

[Read more →](verify2.md)

## Verifying an enveloped signature with X509 certificates

Verifies an enveloped XML Digital Signature using X509 certificate chain verification.

[Read more →](verify3.md)

## Verifying a signature of a node with X509 certificates

Verifies a node signature with X509 certificates.

[Read more →](verify4.md)

## Verifying a signature with additional restrictions

Verifies an XML Digital Signature with additional restrictions (SAML-style).

[Read more →](verify-saml.md)

## Encrypting data with a template file

Encrypts binary data using a pre-created encryption template file.

[Read more →](encrypt1.md)

## Encrypting data with a dynamically created template

Encrypts an XML document using a dynamically created encryption template.

[Read more →](encrypt2.md)

## Encrypting data with a session key

Encrypts an XML document using a session key wrapped with an RSA key from the keys manager.

[Read more →](encrypt3.md)

## Decrypting data with a single key

Decrypts encrypted XML data using a single DES key loaded from a binary file.

[Read more →](decrypt1.md)

## Decrypting data with keys manager

Decrypts encrypted XML data using a keys manager loaded with DES keys.

[Read more →](decrypt2.md)

## Writing a custom keys manager

Demonstrates implementing a custom file-based keys store for decryption.

[Read more →](decrypt3.md)

