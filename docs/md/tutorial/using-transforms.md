# Transforms and transforms chain

XML Digital Signature and XML Encryption standards are very flexible and provide an XML developer many different ways to sign or encrypt any part (or even parts) of an XML document. The key for such great flexibility is the "transforms" model. Transform is defined as a method of pre-processing binary or XML data before calculating digest or signature. XML Security Library extends this definition and names "transform" any operation performed on the data: reading data from an URI, xml parsing, xml transformation, calculation digest, encrypting or decrypting. Each XML Security Library transform provides at least one of the following callbacks:
- [push binary data](#xmlsectransformpushbinmethod) ;
- [push xml data](#xmlsectransformpushxmlmethod) ;
- [pop binary data](#xmlsectransformpopbinmethod) ;
- [pop xml data](#xmlsectransformpopxmlmethod) .

One additional [execute](#xmlsectransformexecutemethod) callback was added to simplify the development and reduce code size. This callback is used by default implementations of the four external callbacks from the list above. For example, most of the crypto transforms could be implemented by just implementing one "execute" callback and using default push/pop binary data callbacks. However, in some cases using push/pop callbacks directly is more efficient.

> **Figure: The XML Security Library transform**
> ![The XML Security Library transform](images/transform.png)

XML Security Library constructs transforms chain according to the signature/encryption template or signed/encrypted document. If necessary, XML Security Library inserts XML parser or defaul canonicalization to ensure that the output data type (binary or XML) of previous transform matches the input of the next transform.

The data are processed by pushing through or poping from the chain depending on the transforms in the chain. For example, then binary data chunk is pushed through a binary-to-binary transform, it processes this chunk and pushes the result to the next transform in the chain.

> **Figure: Transforms chain created for <dsig:Reference/> element processing**
> ![Transforms chain created for <dsig:Reference/> element processing](images/transforms-chain.png)

