# XMLSec Library: XMLSEC-MSCNG

## What version of MS Windows?
The Microsoft CNG API is a set of BCrypt* and NCrypt* functions. Taking
`BCryptOpenAlgorithmProvider()` as a representative example, the minimum
supported client is Windows Vista and the minimum supported server is Windows
Server 2008.

## Keys manager with MS Certificate store support.
Similarly to the xmlsec-nss and xmlsec-mscrypto backends, the xmlsec-mscng
keys manager is based on the XMLSEC Simple Keys Store. If keys are not found
in the XMLSEC Simple Keys Store, then the MS Certificate store (the `MY` store
by default, visible as `Personal -> Certificates` in `certmgr.msc`) is used
to look up keys. The certificate store from the OS is a read-only store.
