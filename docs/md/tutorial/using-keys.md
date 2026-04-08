# Keys

A key in the XML Security Library is a representation of the
[dsig:KeyInfo](http://www.w3.org/TR/xmldsig-core/#sec-KeyInfo)
element and consists of several key data objects. The "value" key data
usually contains a pointer to the actual key, while other key data
objects may contain additional information about the key (e.g. X509
certificates). All key data objects within the same key are associated
with that key.


### Figure: The key structure
![The key structure](images/key.png)

The XML Security Library has several "invisible" key data classes.
These classes never appear in a key's list of key data, but are used
for processing
[dsig:KeyInfo](http://www.w3.org/TR/xmldsig-core/#sec-KeyInfo)
([dsig:KeyName](http://www.w3.org/TR/xmldsig-core/#sec-KeyName),
[enc:EncryptedKey](http://www.w3.org/TR/xmlenc-core/#sec-EncryptedKey),
...). As with transforms, an application can add custom key data
objects or replace the default ones.

