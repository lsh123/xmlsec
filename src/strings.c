/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:strings
 * @Short_description: The strings constants.
 * @Stability: Stable
 *
 */
#include "globals.h"

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

/*************************************************************************
 *
 * Global Namespaces
 *
 ************************************************************************/
const xmlChar xmlSecNs[]                        = "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[]                    = "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecDSig11Ns[]                  = "http://www.w3.org/2009/xmldsig11#";
const xmlChar xmlSecEncNs[]                     = "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecEnc11Ns[]                   = "http://www.w3.org/2009/xmlenc11#";
const xmlChar xmlSecXPathNs[]                   = "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[]                  = "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]                = "http://www.w3.org/2001/04/xmldsig-more/xptr";

/*************************************************************************
 *
 * DSig Nodes
 *
 ************************************************************************/
const xmlChar xmlSecNodeSignature[]             = "Signature";
const xmlChar xmlSecNodeSignedInfo[]            = "SignedInfo";
const xmlChar xmlSecNodeCanonicalizationMethod[]= "CanonicalizationMethod";
const xmlChar xmlSecNodeSignatureMethod[]       = "SignatureMethod";
const xmlChar xmlSecNodeSignatureValue[]        = "SignatureValue";
const xmlChar xmlSecNodeDigestMethod[]          = "DigestMethod";
const xmlChar xmlSecNodeDigestValue[]           = "DigestValue";
const xmlChar xmlSecNodeObject[]                = "Object";
const xmlChar xmlSecNodeManifest[]              = "Manifest";
const xmlChar xmlSecNodeSignatureProperties[]   = "SignatureProperties";

/*************************************************************************
 *
 * Encryption Nodes
 *
 ************************************************************************/
const xmlChar xmlSecNodeEncryptedData[]         = "EncryptedData";
const xmlChar xmlSecNodeEncryptionMethod[]      = "EncryptionMethod";
const xmlChar xmlSecNodeEncryptionProperties[]  = "EncryptionProperties";
const xmlChar xmlSecNodeEncryptionProperty[]    = "EncryptionProperty";
const xmlChar xmlSecNodeCipherData[]            = "CipherData";
const xmlChar xmlSecNodeCipherValue[]           = "CipherValue";
const xmlChar xmlSecNodeCipherReference[]       = "CipherReference";
const xmlChar xmlSecNodeReferenceList[]         = "ReferenceList";
const xmlChar xmlSecNodeDataReference[]         = "DataReference";
const xmlChar xmlSecNodeKeyReference[]          = "KeyReference";

const xmlChar xmlSecNodeCarriedKeyName[]        = "CarriedKeyName";

const xmlChar xmlSecTypeEncContent[]            = "http://www.w3.org/2001/04/xmlenc#Content";
const xmlChar xmlSecTypeEncElement[]            = "http://www.w3.org/2001/04/xmlenc#Element";

/*************************************************************************
 *
 * KeyInfo Nodes
 *
 ************************************************************************/
const xmlChar xmlSecNodeKeyInfo[]               = "KeyInfo";
const xmlChar xmlSecNodeReference[]             = "Reference";
const xmlChar xmlSecNodeTransforms[]            = "Transforms";
const xmlChar xmlSecNodeTransform[]             = "Transform";

/*************************************************************************
 *
 * Attributes
 *
 ************************************************************************/
const xmlChar xmlSecAttrId[]                    = "Id";
const xmlChar xmlSecAttrURI[]                   = "URI";
const xmlChar xmlSecAttrType[]                  = "Type";
const xmlChar xmlSecAttrMimeType[]              = "MimeType";
const xmlChar xmlSecAttrEncoding[]              = "Encoding";
const xmlChar xmlSecAttrAlgorithm[]             = "Algorithm";
const xmlChar xmlSecAttrFilter[]                = "Filter";
const xmlChar xmlSecAttrRecipient[]             = "Recipient";
const xmlChar xmlSecAttrTarget[]                = "Target";

/*************************************************************************
 *
 * AES strings
 *
 ************************************************************************/
const xmlChar xmlSecNameAESKeyValue[]           = "aes";
const xmlChar xmlSecNodeAESKeyValue[]           = "AESKeyValue";
const xmlChar xmlSecHrefAESKeyValue[]           = "http://www.aleksey.com/xmlsec/2002#AESKeyValue";

const xmlChar xmlSecNameAes128Cbc[]             = "aes128-cbc";
const xmlChar xmlSecHrefAes128Cbc[]             = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

const xmlChar xmlSecNameAes192Cbc[]             = "aes192-cbc";
const xmlChar xmlSecHrefAes192Cbc[]             = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";

const xmlChar xmlSecNameAes256Cbc[]             = "aes256-cbc";
const xmlChar xmlSecHrefAes256Cbc[]             = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

const xmlChar xmlSecNameAes128Gcm[]             = "aes128-gcm";
const xmlChar xmlSecHrefAes128Gcm[]             = "http://www.w3.org/2009/xmlenc11#aes128-gcm";

const xmlChar xmlSecNameAes192Gcm[]             = "aes192-gcm";
const xmlChar xmlSecHrefAes192Gcm[]             = "http://www.w3.org/2009/xmlenc11#aes192-gcm";

const xmlChar xmlSecNameAes256Gcm[]             = "aes256-gcm";
const xmlChar xmlSecHrefAes256Gcm[]             = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

const xmlChar xmlSecNameKWAes128[]              = "kw-aes128";
const xmlChar xmlSecHrefKWAes128[]              = "http://www.w3.org/2001/04/xmlenc#kw-aes128";

const xmlChar xmlSecNameKWAes192[]              = "kw-aes192";
const xmlChar xmlSecHrefKWAes192[]              = "http://www.w3.org/2001/04/xmlenc#kw-aes192";

const xmlChar xmlSecNameKWAes256[]              = "kw-aes256";
const xmlChar xmlSecHrefKWAes256[]              = "http://www.w3.org/2001/04/xmlenc#kw-aes256";

/*************************************************************************
 *
 * BASE64 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameBase64[]                = "base64";
const xmlChar xmlSecHrefBase64[]                = "http://www.w3.org/2000/09/xmldsig#base64";

/*************************************************************************
 *
 * C14N strings
 *
 ************************************************************************/
const xmlChar xmlSecNameC14N[]                  = "c14n";
const xmlChar xmlSecHrefC14N[]                  = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

const xmlChar xmlSecNameC14NWithComments[]      = "c14n-with-comments";
const xmlChar xmlSecHrefC14NWithComments[]      = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

const xmlChar xmlSecNameC14N11[]                = "c14n11";
const xmlChar xmlSecHrefC14N11[]                = "http://www.w3.org/2006/12/xml-c14n11";

const xmlChar xmlSecNameC14N11WithComments[]    = "c14n11-with-comments";
const xmlChar xmlSecHrefC14N11WithComments[]    = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

const xmlChar xmlSecNameExcC14N[]               = "exc-c14n";
const xmlChar xmlSecHrefExcC14N[]               = "http://www.w3.org/2001/10/xml-exc-c14n#";

const xmlChar xmlSecNameExcC14NWithComments[]   = "exc-c14n-with-comments";
const xmlChar xmlSecHrefExcC14NWithComments[]   = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

const xmlChar xmlSecNsExcC14N[]                 = "http://www.w3.org/2001/10/xml-exc-c14n#";
const xmlChar xmlSecNsExcC14NWithComments[]     = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

const xmlChar xmlSecNodeInclusiveNamespaces[]   = "InclusiveNamespaces";
const xmlChar xmlSecAttrPrefixList[]            = "PrefixList";


/*************************************************************************
 *
 * ConcatKDF strings
 *
 ************************************************************************/
const xmlChar xmlSecNameConcatKdfKeyValue[]     = "ConcatKDFKeyValue";

const xmlChar xmlSecNameConcatKdf[]             = "concatkdf";
const xmlChar xmlSecHrefConcatKdf[]             = "http://www.w3.org/2009/xmlenc11#ConcatKDF";

const xmlChar xmlSecNodeConcatKDFParams[]           = "ConcatKDFParams";
const xmlChar xmlSecNodeConcatKDFAttrAlgorithmID[]  = "AlgorithmID";
const xmlChar xmlSecNodeConcatKDFAttrPartyUInfo[]   = "PartyUInfo";
const xmlChar xmlSecNodeConcatKDFAttrPartyVInfo[]   = "PartyVInfo";
const xmlChar xmlSecNodeConcatKDFAttrSuppPubInfo[]  = "SuppPubInfo";
const xmlChar xmlSecNodeConcatKDFAttrSuppPrivInfo[] = "SuppPrivInfo";

/*************************************************************************
 *
 * DEREncodedKeyValue strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDEREncodedKeyValue[]        = "der-encoded-key-value";
const xmlChar xmlSecNodeDEREncodedKeyValue[]        = "DEREncodedKeyValue";
const xmlChar xmlSecHrefDEREncodedKeyValue[]        = "http://www.w3.org/2009/xmldsig11#DEREncodedKeyValue";

/*************************************************************************
 *
 * DES strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDESKeyValue[]           = "des";
const xmlChar xmlSecNodeDESKeyValue[]           = "DESKeyValue";
const xmlChar xmlSecHrefDESKeyValue[]           = "http://www.aleksey.com/xmlsec/2002#DESKeyValue";

const xmlChar xmlSecNameDes3Cbc[]               = "tripledes-cbc";
const xmlChar xmlSecHrefDes3Cbc[]               = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";

const xmlChar xmlSecNameKWDes3[]                = "kw-tripledes";
const xmlChar xmlSecHrefKWDes3[]                = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";

/*************************************************************************
 *
 * GOST2001 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameGOST2001KeyValue[]              = "gost2001";
const xmlChar xmlSecNodeGOST2001KeyValue[]              = "gostr34102001-gostr3411";
const xmlChar xmlSecHrefGOST2001KeyValue[]              = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

const xmlChar xmlSecNameGost2001GostR3411_94[]          = "gostr34102001-gostr3411";
const xmlChar xmlSecHrefGost2001GostR3411_94[]          = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

/*************************************************************************
 *
 * GOST R 34.10-2012 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameGostR3410_2012_256KeyValue[]              = "gostr34102012-256";
const xmlChar xmlSecNodeGostR3410_2012_256KeyValue[]              = "gostr34102012-256";
const xmlChar xmlSecHrefGostR3410_2012_256KeyValue[]              = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-256";

const xmlChar xmlSecNameGostR3410_2012_512KeyValue[]              = "gostr34102012-512";
const xmlChar xmlSecNodeGostR3410_2012_512KeyValue[]              = "gostr34102012-512";
const xmlChar xmlSecHrefGostR3410_2012_512KeyValue[]              = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-512";

/* see http://tools.ietf.org/html/draft-chudov-cryptopro-cpxmldsig-09#section-6.6 */
const xmlChar xmlSecNameGostR3410_2012GostR3411_2012_256[]    = "gostr34102012-gostr34112012-256";
const xmlChar xmlSecHrefGostR3410_2012GostR3411_2012_256[]    = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";

const xmlChar xmlSecNameGostR3410_2012GostR3411_2012_512[]    = "gostr34102012-gostr34112012-512";
const xmlChar xmlSecHrefGostR3410_2012GostR3411_2012_512[]    = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

/*************************************************************************
 *
 * DH key strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDHKeyValue[]            = "dh";
const xmlChar xmlSecNodeDHKeyValue[]            = "DHKeyValue";
const xmlChar xmlSecHrefDHKeyValue[]            = "http://www.w3.org/2001/04/xmlenc#DHKeyValue";
const xmlChar xmlSecNodeDHP[]                   = "P";
const xmlChar xmlSecNodeDHQ[]                   = "Q";
const xmlChar xmlSecNodeDHGenerator[]           = "Generator";
const xmlChar xmlSecNodeDHPublic[]              = "Public";
const xmlChar xmlSecNodeDHSeed[]                = "Seed";
const xmlChar xmlSecNodeDHPgenCounter[]         = "pgenCounter";

/*************************************************************************
 *
 * DH-ES key agreement strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDhEs[]                  = "dh-es";
const xmlChar xmlSecHrefDhEs[]                  = "http://www.w3.org/2009/xmlenc11#dh-es";

/*************************************************************************
 *
 * DSA strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDSAKeyValue[]           = "dsa";
const xmlChar xmlSecNodeDSAKeyValue[]           = "DSAKeyValue";
const xmlChar xmlSecHrefDSAKeyValue[]           = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";
const xmlChar xmlSecNodeDSAP[]                  = "P";
const xmlChar xmlSecNodeDSAQ[]                  = "Q";
const xmlChar xmlSecNodeDSAG[]                  = "G";
const xmlChar xmlSecNodeDSAJ[]                  = "J";
const xmlChar xmlSecNodeDSAX[]                  = "X";
const xmlChar xmlSecNodeDSAY[]                  = "Y";
const xmlChar xmlSecNodeDSASeed[]               = "Seed";
const xmlChar xmlSecNodeDSAPgenCounter[]        = "PgenCounter";

const xmlChar xmlSecNameDsaSha1[]               = "dsa-sha1";
const xmlChar xmlSecHrefDsaSha1[]               = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

const xmlChar xmlSecNameDsaSha256[]             = "dsa-sha256";
const xmlChar xmlSecHrefDsaSha256[]             = "http://www.w3.org/2009/xmldsig11#dsa-sha256";


/*************************************************************************
 *
 * EC key strings
 *
 ************************************************************************/
const xmlChar xmlSecNameECKeyValue[]            = "ec";
const xmlChar xmlSecNodeECKeyValue[]            = "ECKeyValue";
const xmlChar xmlSecHrefECKeyValue[]            = "http://www.w3.org/2009/xmldsig11#ECKeyValue";

const xmlChar xmlSecNodeNamedCurve[]            = "NamedCurve";
const xmlChar xmlSecNodePublicKey[]             = "PublicKey";

/*************************************************************************
 *
 * ECDH key agreement strings
 *
 ************************************************************************/
const xmlChar xmlSecNameEcdh[]                  = "ecdh-es";
const xmlChar xmlSecHrefEcdh[]                  = "http://www.w3.org/2009/xmlenc11#ECDH-ES";

/*************************************************************************
 *
 * ECDSA sigantures strings
 *
 * https://www.ietf.org/rfc/rfc9231.html#name-ecdsa-sha-ecdsa-ripemd160-e
 *
 ************************************************************************/
const xmlChar xmlSecNameEcdsaRipemd160[]        = "ecdsa-ripemd160";
const xmlChar xmlSecHrefEcdsaRipemd160[]        = "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160";

const xmlChar xmlSecNameEcdsaSha1[]             = "ecdsa-sha1";
const xmlChar xmlSecHrefEcdsaSha1[]             = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";

const xmlChar xmlSecNameEcdsaSha224[]           = "ecdsa-sha224";
const xmlChar xmlSecHrefEcdsaSha224[]           = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";

const xmlChar xmlSecNameEcdsaSha256[]           = "ecdsa-sha256";
const xmlChar xmlSecHrefEcdsaSha256[]           = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

const xmlChar xmlSecNameEcdsaSha384[]           = "ecdsa-sha384";
const xmlChar xmlSecHrefEcdsaSha384[]           = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

const xmlChar xmlSecNameEcdsaSha512[]           = "ecdsa-sha512";
const xmlChar xmlSecHrefEcdsaSha512[]           = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

const xmlChar xmlSecNameEcdsaSha3_224[]         = "ecdsa-sha3-224";
const xmlChar xmlSecHrefEcdsaSha3_224[]         = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224";

const xmlChar xmlSecNameEcdsaSha3_256[]         = "ecdsa-sha3-256";
const xmlChar xmlSecHrefEcdsaSha3_256[]         = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256";

const xmlChar xmlSecNameEcdsaSha3_384[]         = "ecdsa-sha3-384";
const xmlChar xmlSecHrefEcdsaSha3_384[]         = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384";

const xmlChar xmlSecNameEcdsaSha3_512[]         = "ecdsa-sha3-512";
const xmlChar xmlSecHrefEcdsaSha3_512[]         = "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512";

/*************************************************************************
 *
 * EncryptedKey
 *
 ************************************************************************/
const xmlChar xmlSecNameEncryptedKey[]          = "enc-key";
const xmlChar xmlSecNodeEncryptedKey[]          = "EncryptedKey";
const xmlChar xmlSecHrefEncryptedKey[]          = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

/*************************************************************************
 *
 * DerivedKey
 *
 ************************************************************************/
const xmlChar xmlSecNameDerivedKey[]            = "derived-key";
const xmlChar xmlSecNodeDerivedKey[]            = "DerivedKey";
const xmlChar xmlSecHrefDerivedKey[]            = "http://www.w3.org/2009/xmlenc11#DerivedKey";

const xmlChar xmlSecNodeKeyDerivationMethod[]   = "KeyDerivationMethod";
const xmlChar xmlSecNodeDerivedKeyName[]        = "DerivedKeyName";
const xmlChar xmlSecNodeMasterKeyName[]         = "MasterKeyName";

/*************************************************************************
 *
 * AgreementMethod
 *
 ************************************************************************/
const xmlChar xmlSecNameAgreementMethod[]       = "agreement-method";
const xmlChar xmlSecNodeAgreementMethod[]       = "AgreementMethod";
const xmlChar xmlSecHrefAgreementMethod[]       = "http://www.w3.org/2000/09/xmldsig#AgreementMethod";

const xmlChar xmlSecNodeOriginatorKeyInfo[]     = "OriginatorKeyInfo";
const xmlChar xmlSecNodeRecipientKeyInfo[]      = "RecipientKeyInfo";


/*************************************************************************
 *
 * Enveloped transform strings
 *
 ************************************************************************/
const xmlChar xmlSecNameEnveloped[]             = "enveloped-signature";
const xmlChar xmlSecHrefEnveloped[]             = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/*************************************************************************
 *
 * HMAC strings
 *
 ************************************************************************/
const xmlChar xmlSecNameHMACKeyValue[]          = "hmac";
const xmlChar xmlSecNodeHMACKeyValue[]          = "HMACKeyValue";
const xmlChar xmlSecHrefHMACKeyValue[]          = "http://www.aleksey.com/xmlsec/2002#HMACKeyValue";

const xmlChar xmlSecNodeHMACOutputLength[]      = "HMACOutputLength";

const xmlChar xmlSecNameHmacMd5[]               = "hmac-md5";
const xmlChar xmlSecHrefHmacMd5[]               = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";

const xmlChar xmlSecNameHmacRipemd160[]         = "hmac-ripemd160";
const xmlChar xmlSecHrefHmacRipemd160[]         = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

const xmlChar xmlSecNameHmacSha1[]              = "hmac-sha1";
const xmlChar xmlSecHrefHmacSha1[]              = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

const xmlChar xmlSecNameHmacSha224[]            = "hmac-sha224";
const xmlChar xmlSecHrefHmacSha224[]            = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224";

const xmlChar xmlSecNameHmacSha256[]            = "hmac-sha256";
const xmlChar xmlSecHrefHmacSha256[]            = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

const xmlChar xmlSecNameHmacSha384[]            = "hmac-sha384";
const xmlChar xmlSecHrefHmacSha384[]            = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";

const xmlChar xmlSecNameHmacSha512[]            = "hmac-sha512";
const xmlChar xmlSecHrefHmacSha512[]            = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";


/*************************************************************************
 *
 * KeyInfoReference
 *
 ************************************************************************/
const xmlChar xmlSecNameKeyInfoReference[]      = "key-info-reference";
const xmlChar xmlSecNodeKeyInfoReference[]      = "KeyInfoReference";


/*************************************************************************
 *
 * KeyName strings
 *
 ************************************************************************/
const xmlChar xmlSecNameKeyName[]               = "key-name";
const xmlChar xmlSecNodeKeyName[]               = "KeyName";

/*************************************************************************
 *
 * KeyValue strings
 *
 ************************************************************************/
const xmlChar xmlSecNameKeyValue[]              = "key-value";
const xmlChar xmlSecNodeKeyValue[]              = "KeyValue";

/*************************************************************************
 *
 * Memory Buffer strings
 *
 ************************************************************************/
const xmlChar xmlSecNameMemBuf[]                = "membuf-transform";

/*************************************************************************
 *
 * MD5 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameMd5[]                   = "md5";
const xmlChar xmlSecHrefMd5[]                   = "http://www.w3.org/2001/04/xmldsig-more#md5";

/*************************************************************************
 *
 * PBKDF2
 *
 ************************************************************************/
const xmlChar xmlSecNamePbkdf2KeyValue[]        = "PBKDF2KeyValue";

const xmlChar xmlSecNamePbkdf2[]                = "pbkdf2";
const xmlChar xmlSecHrefPbkdf2[]                = "http://www.w3.org/2009/xmlenc11#pbkdf2";

const xmlChar xmlSecNodePbkdf2Params[]          = "PBKDF2-params";
const xmlChar xmlSecNodePbkdf2Salt[]            = "Salt";
const xmlChar xmlSecNodePbkdf2SaltSpecified[]   = "Specified";
const xmlChar xmlSecNodePbkdf2IterationCount[]  = "IterationCount";
const xmlChar xmlSecNodePbkdf2KeyLength[]       = "KeyLength";
const xmlChar xmlSecNodePbkdf2PRF[]             = "PRF";

/*************************************************************************
 *
 * RetrievalMethod
 *
 ************************************************************************/
const xmlChar xmlSecNameRetrievalMethod[]       = "retrieval-method";
const xmlChar xmlSecNodeRetrievalMethod[]       = "RetrievalMethod";

/*************************************************************************
 *
 * RIPEMD160 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameRipemd160[]             = "ripemd160";
const xmlChar xmlSecHrefRipemd160[]             = "http://www.w3.org/2001/04/xmlenc#ripemd160";

/*************************************************************************
 *
 * RSA strings
 *
 ************************************************************************/
const xmlChar xmlSecNameRSAKeyValue[]           = "rsa";
const xmlChar xmlSecNodeRSAKeyValue[]           = "RSAKeyValue";
const xmlChar xmlSecHrefRSAKeyValue[]           = "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";
const xmlChar xmlSecNodeRSAModulus[]            = "Modulus";
const xmlChar xmlSecNodeRSAExponent[]           = "Exponent";
const xmlChar xmlSecNodeRSAPrivateExponent[]    = "PrivateExponent";

const xmlChar xmlSecNameRsaMd5[]                = "rsa-md5";
const xmlChar xmlSecHrefRsaMd5[]                = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";

const xmlChar xmlSecNameRsaRipemd160[]          = "rsa-ripemd160";
const xmlChar xmlSecHrefRsaRipemd160[]          = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";

const xmlChar xmlSecNameRsaSha1[]               = "rsa-sha1";
const xmlChar xmlSecHrefRsaSha1[]               = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

const xmlChar xmlSecNameRsaSha224[]             = "rsa-sha224";
const xmlChar xmlSecHrefRsaSha224[]             = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";

const xmlChar xmlSecNameRsaSha256[]             = "rsa-sha256";
const xmlChar xmlSecHrefRsaSha256[]             = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

const xmlChar xmlSecNameRsaSha384[]             = "rsa-sha384";
const xmlChar xmlSecHrefRsaSha384[]             = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

const xmlChar xmlSecNameRsaSha512[]             = "rsa-sha512";
const xmlChar xmlSecHrefRsaSha512[]             = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

const xmlChar xmlSecNameRsaPkcs1[]              = "rsa-1_5";
const xmlChar xmlSecHrefRsaPkcs1[]              = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

const xmlChar xmlSecNameRsaOaep[]               = "rsa-oaep-mgf1p";
const xmlChar xmlSecHrefRsaOaep[]               = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

const xmlChar xmlSecNameRsaOaepEnc11[]          = "rsa-oaep-enc11";
const xmlChar xmlSecHrefRsaOaepEnc11[]          = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

const xmlChar xmlSecNodeRsaOAEPparams[]         = "OAEPparams";
const xmlChar xmlSecNodeRsaMGF[]                = "MGF";

/* MGF1 urls (https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP) */
const xmlChar xmlSecHrefMgf1Sha1[]              = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
const xmlChar xmlSecHrefMgf1Sha224[]            = "http://www.w3.org/2009/xmlenc11#mgf1sha224";
const xmlChar xmlSecHrefMgf1Sha256[]            = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const xmlChar xmlSecHrefMgf1Sha384[]            = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
const xmlChar xmlSecHrefMgf1Sha512[]            = "http://www.w3.org/2009/xmlenc11#mgf1sha512";

/* RSS PSS https://www.rfc-editor.org/rfc/rfc9231.txt */
const xmlChar xmlSecNameRsaPssSha1[]            = "rsa-pss-sha1";
const xmlChar xmlSecHrefRsaPssSha1[]            = "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha224[]          = "rsa-pss-sha224";
const xmlChar xmlSecHrefRsaPssSha224[]          = "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha256[]          = "rsa-pss-sha256";
const xmlChar xmlSecHrefRsaPssSha256[]          = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha384[]          = "rsa-pss-sha384";
const xmlChar xmlSecHrefRsaPssSha384[]          = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha512[]          = "rsa-pss-sha512";
const xmlChar xmlSecHrefRsaPssSha512[]          = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha3_224[]        = "rsa-pss-sha3-224";
const xmlChar xmlSecHrefRsaPssSha3_224[]        = "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha3_256[]        = "rsa-pss-sha3-256";
const xmlChar xmlSecHrefRsaPssSha3_256[]        = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha3_384[]        = "rsa-pss-sha3-384";
const xmlChar xmlSecHrefRsaPssSha3_384[]        = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";

const xmlChar xmlSecNameRsaPssSha3_512[]        = "rsa-pss-sha3-512";
const xmlChar xmlSecHrefRsaPssSha3_512[]        = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";

/*************************************************************************
 *
 * GOSTR3411_94 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameGostR3411_94[]                  = "gostr3411";
const xmlChar xmlSecHrefGostR3411_94[]                  = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";

/*************************************************************************
 *
 * GOST R 34.11-2012 strings
 *
 ************************************************************************/

/* see http://tools.ietf.org/html/draft-chudov-cryptopro-cpxmldsig-09#section-6.2 */
const xmlChar xmlSecNameGostR3411_2012_256[]                  = "gostr34112012-256";
const xmlChar xmlSecHrefGostR3411_2012_256[]                  = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";

const xmlChar xmlSecNameGostR3411_2012_512[]                  = "gostr34112012-512";
const xmlChar xmlSecHrefGostR3411_2012_512[]                  = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";


/*************************************************************************
 *
 * SHA1 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameSha1[]                  = "sha1";
const xmlChar xmlSecHrefSha1[]                  = "http://www.w3.org/2000/09/xmldsig#sha1";

/*************************************************************************
 *
 * SHA2 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameSha224[]                = "sha224";
const xmlChar xmlSecHrefSha224[]                = "http://www.w3.org/2001/04/xmldsig-more#sha224";

const xmlChar xmlSecNameSha256[]                = "sha256";
const xmlChar xmlSecHrefSha256[]                = "http://www.w3.org/2001/04/xmlenc#sha256";

const xmlChar xmlSecNameSha384[]                = "sha384";
const xmlChar xmlSecHrefSha384[]                = "http://www.w3.org/2001/04/xmldsig-more#sha384";

const xmlChar xmlSecNameSha512[]                = "sha512";
const xmlChar xmlSecHrefSha512[]                = "http://www.w3.org/2001/04/xmlenc#sha512";

/*************************************************************************
 *
 * SHA3 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameSha3_224[]              = "sha3-224";
const xmlChar xmlSecHrefSha3_224[]              = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";

const xmlChar xmlSecNameSha3_256[]              = "sha3-256";
const xmlChar xmlSecHrefSha3_256[]              = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";

const xmlChar xmlSecNameSha3_384[]              = "sha3-384";
const xmlChar xmlSecHrefSha3_384[]              = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";

const xmlChar xmlSecNameSha3_512[]              = "sha3-512";
const xmlChar xmlSecHrefSha3_512[]              = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

/*************************************************************************
 *
 * X509 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameX509Data[]              = "x509";
const xmlChar xmlSecNodeX509Data[]              = "X509Data";
const xmlChar xmlSecHrefX509Data[]              = "http://www.w3.org/2000/09/xmldsig#X509Data";

const xmlChar xmlSecNodeX509Certificate[]       = "X509Certificate";
const xmlChar xmlSecNodeX509CRL[]               = "X509CRL";
const xmlChar xmlSecNodeX509SubjectName[]       = "X509SubjectName";
const xmlChar xmlSecNodeX509IssuerSerial[]      = "X509IssuerSerial";
const xmlChar xmlSecNodeX509IssuerName[]        = "X509IssuerName";
const xmlChar xmlSecNodeX509SerialNumber[]      = "X509SerialNumber";
const xmlChar xmlSecNodeX509SKI[]               = "X509SKI";
const xmlChar xmlSecNodeX509Digest[]            = "X509Digest";

const xmlChar xmlSecNameRawX509Cert[]           = "raw-x509-cert";
const xmlChar xmlSecHrefRawX509Cert[]           = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

const xmlChar xmlSecNameX509Store[]             = "x509-store";

/*************************************************************************
 *
 * PGP strings
 *
 ************************************************************************/
const xmlChar xmlSecNamePGPData[]               = "pgp";
const xmlChar xmlSecNodePGPData[]               = "PGPData";
const xmlChar xmlSecHrefPGPData[]               = "http://www.w3.org/2000/09/xmldsig#PGPData";

/*************************************************************************
 *
 * SPKI strings
 *
 ************************************************************************/
const xmlChar xmlSecNameSPKIData[]              = "spki";
const xmlChar xmlSecNodeSPKIData[]              = "SPKIData";
const xmlChar xmlSecHrefSPKIData[]              = "http://www.w3.org/2000/09/xmldsig#SPKIData";

/*************************************************************************
 *
 * XPath/XPointer strings
 *
 ************************************************************************/
const xmlChar xmlSecNameXPath[]                 = "xpath";
const xmlChar xmlSecNodeXPath[]                 = "XPath";

const xmlChar xmlSecNameXPath2[]                = "xpath2";
const xmlChar xmlSecNodeXPath2[]                = "XPath";
const xmlChar xmlSecXPath2FilterIntersect[]     = "intersect";
const xmlChar xmlSecXPath2FilterSubtract[]      = "subtract";
const xmlChar xmlSecXPath2FilterUnion[]         = "union";

const xmlChar xmlSecNameXPointer[]              = "xpointer";
const xmlChar xmlSecNodeXPointer[]              = "XPointer";

/*************************************************************************
 *
 * Relationship strings
 *
 ************************************************************************/
const xmlChar xmlSecNameRelationship[]          = "relationship";
const xmlChar xmlSecHrefRelationship[]          = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
const xmlChar xmlSecNodeRelationship[]          = "Relationship";
const xmlChar xmlSecNodeRelationshipReference[] = "RelationshipReference";
const xmlChar xmlSecRelationshipsNs[]           = "http://schemas.openxmlformats.org/package/2006/relationships";
const xmlChar xmlSecRelationshipReferenceNs[]   = "http://schemas.openxmlformats.org/package/2006/digital-signature";
const xmlChar xmlSecRelationshipAttrId[]        = "Id";
const xmlChar xmlSecRelationshipAttrSourceId[]  = "SourceId";
const xmlChar xmlSecRelationshipAttrTargetMode[]= "TargetMode";

/*************************************************************************
 *
 * Xslt strings
 *
 ************************************************************************/
const xmlChar xmlSecNameXslt[]                  = "xslt";
const xmlChar xmlSecHrefXslt[]                  = "http://www.w3.org/TR/1999/REC-xslt-19991116";

/*************************************************************************
 *
 * Utility strings
 *
 ************************************************************************/
const xmlChar xmlSecStringEmpty[]               = "";
const xmlChar xmlSecStringCR[]                  = "\n";
