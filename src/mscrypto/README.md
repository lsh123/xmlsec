# XMLSec Library: XMLSEC-MSCRYPTO

## What version of MS Windows?

The MS Crypto API has been evolving a lot with the new releases of MS Windows.
Full functionality will only be achieved on MS Windows XP or greater (e.g. AES is
not supported on pre Windows XP versions of Windows).

## Keys Manager with MS Certificate store support.
The default xmlsec-mscrypto keys manager is based upon the XMLSEC Simple Keys
Store,. If keys are not found in the XMLSEC Simple Keys Store, than MS Certificate store is
used to lookup keys. The certificate store is only used on a READONLY base, so it is
not possible to store keys via the keys store into the MS certificate store.

When the xmlsec application is started, with the config parameter the name of
the (system) keystore can be given. That keystore will be used for certificates
and keys lookup. With the keyname now two types of values can be given:
- simple name (called friendly name with MS);
- full subject name (recommended) of the key's certificate.


## Known issues / limitations

1) Default keys manager don't use trusted certs in MS Crypto Store (also see
[xmlsec bug](https://github.com/lsh123/xmlsec/issues/7)).

2) The only supported file formats are PKCS#12 and DER certificates (also see
[xmlsec bug](https://github.com/lsh123/xmlsec/issues/9)).


