# XML Encryption 1.1 interop tests (2012)

See https://www.w3.org/TR/2012/NOTE-xmlenc-core1-interop-20121113/


# Aleksey:

- The ConcatKDF interop tests (dkey-example-ConcatKDF-crypto and 
dkey3-example-ConcatKDF-crypto) are incorrect because test vectors 
do not implement padding for AES CBC as it is required by the spec
(see https://www.w3.org/TR/xmlenc-core1/#sec-Padding). As the result,
XMLSec Library produces the output 8 bytes shorter than test vectors
(last decrypted byte in the decrypted data is 07). The original test
expected outputs are saved in the corresponding *-orig.data files.


