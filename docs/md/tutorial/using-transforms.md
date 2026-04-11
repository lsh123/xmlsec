# Transforms and transform chains

The [XML Digital Signature](http://www.w3.org/TR/xmldsig-core/) and
the [XML Encryption](http://www.w3.org/TR/xmlenc-core/) standards are
very flexible and provide many different ways to sign or encrypt any
part, or even multiple parts, of an XML document. The key to this
flexibility is the "transform" model. A transform is defined as a
method for pre-processing binary or XML data before calculating a
digest or signature. The XML Security Library extends this definition
to include any operation performed on the data as a "transform":
reading data from a URI, XML parsing, XML transformation, digest
calculation, encryption, decryption, and so on.

The XML Security Library constructs a transform chain according to the
signature/encryption template or the signed/encrypted document. If
necessary, the XML Security Library inserts additional transforms
(e.g. an XML parser or default canonicalization) to ensure that the
output data type (binary or XML) of the previous transform matches the
input of the next transform.

The data flows through the transform chain one transform at a time:

## Figure: Transform chain created for [dsig:Reference](http://www.w3.org/TR/xmldsig-core/#sec-Reference) element processing

![Transform chain created for dsig:Reference element processing](images/transforms-chain.png)

