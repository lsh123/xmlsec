/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef __XMLSEC_NSS_CRYPTO_H__
#define __XMLSEC_NSS_CRYPTO_H__

#include <nspr.h>
#include <nss.h>
#include <pk11func.h>

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

/*
 * MD5 was removed (https://bugs.gentoo.org/764437)
 *
 * RSA OAEP requires https://bugzilla.mozilla.org/show_bug.cgi?id=1666891
 * which was fixed in NSS 3.59 (https://firefox-source-docs.mozilla.org/security/nss/legacy/nss_releases/nss_3.59_release_notes/index.html)
 */
#if (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 59))
#define XMLSEC_NO_RSA_OAEP 1
#else  /* (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 59)) */
#define XMLSEC_NO_MD5 1
#endif /* (NSS_VMAJOR < 3) || ((NSS_VMAJOR == 3) && (NSS_VMINOR < 59)) */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_nss(void);

/********************************************************************
 *
 * Init shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecNssInit                   (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssShutdown               (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeysMngrInit           (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssGenerateRandom         (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);

XMLSEC_CRYPTO_EXPORT void               xmlSecNssErrorsDefaultCallback  (const char* file,
                                                                        int line,
                                                                        const char* func,
                                                                        const char* errorObject,
                                                                        const char* errorSubject,
                                                                        int reason,
                                                                        const char* msg);

XMLSEC_CRYPTO_EXPORT PK11SlotInfo * xmlSecNssGetInternalKeySlot(void);

/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecNssKeyDataAesId:
 *
 * The AES key data klass.
 */
#define xmlSecNssKeyDataAesId \
        xmlSecNssKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataAesGetKlass     (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataAesSet          (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * xmlSecNssTransformAes128CbcId:
 *
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes128CbcId \
        xmlSecNssTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes128CbcGetKlass(void);

/**
 * xmlSecNssTransformAes192CbcId:
 *
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes192CbcId \
        xmlSecNssTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes192CbcGetKlass(void);

/**
 * xmlSecNssTransformAes256CbcId:
 *
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecNssTransformAes256CbcId \
        xmlSecNssTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes256CbcGetKlass(void);


/**
 * xmlSecNssTransformAes128GcmId:
 *
 * The AES128 GCM cipher transform klass.
 */
#define xmlSecNssTransformAes128GcmId \
        xmlSecNssTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes128GcmGetKlass(void);

/**
 * xmlSecNssTransformAes192GcmId:
 *
 * The AES192 GCM cipher transform klass.
 */
#define xmlSecNssTransformAes192GcmId \
        xmlSecNssTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes192GcmGetKlass(void);

/**
 * xmlSecNssTransformAes256GcmId:
 *
 * The AES256 GCM cipher transform klass.
 */
#define xmlSecNssTransformAes256GcmId \
        xmlSecNssTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformAes256GcmGetKlass(void);


/**
 * xmlSecNssTransformKWAes128Id:
 *
 * The AES 128 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes128Id \
        xmlSecNssTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWAes128GetKlass(void);

/**
 * xmlSecNssTransformKWAes192Id:
 *
 * The AES 192 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes192Id \
        xmlSecNssTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWAes192GetKlass(void);

/**
 * xmlSecNssTransformKWAes256Id:
 *
 * The AES 256 key wrap transform klass.
 */
#define xmlSecNssTransformKWAes256Id \
        xmlSecNssTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecNssTransformKWAes256GetKlass(void);

#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * DES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecNssKeyDataDesId:
 *
 * The DES key data klass.
 */
#define xmlSecNssKeyDataDesId \
        xmlSecNssKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataDesGetKlass     (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataDesSet          (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * xmlSecNssTransformDes3CbcId:
 *
 * The Triple DES CBC cipher transform klass.
 */
#define xmlSecNssTransformDes3CbcId \
        xmlSecNssTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDes3CbcGetKlass(void);

/**
* xmlSecNssTransformKWDes3Id:
*
* The DES3 KW transform klass.
*/
#define xmlSecNssTransformKWDes3Id \
        xmlSecNssTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformKWDes3GetKlass(void);


#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecNssKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecNssKeyDataDsaId \
        xmlSecNssKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataDsaGetKlass     (void);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformDsaSha1Id:
 *
 * The DSA SHA1 signature transform klass.
 */
#define xmlSecNssTransformDsaSha1Id \
        xmlSecNssTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecNssTransformDsaSha256Id:
 *
 * The DSA SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformDsaSha256Id \
        xmlSecNssTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */


/********************************************************************
 *
 * ECDSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * xmlSecNssKeyDataEcId:
 *
 * The EC key klass.
 */
#define xmlSecNssKeyDataEcId            xmlSecNsskeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNsskeyDataEcGetKlass(void);

#ifndef XMLSEC_NO_SHA1

/**
 * xmlSecNssTransformEcdsaSha1Id:
 *
 * The ECDSA SHA1 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha1Id xmlSecNssTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha1GetKlass(void);

#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224

/**
 * xmlSecNssTransformEcdsaSha224Id:
 *
 * The ECDSA SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha224Id xmlSecNssTransformEcdsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha224GetKlass(void);

#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256

/**
 * xmlSecNssTransformEcdsaSha256Id:
 *
 * The ECDSA SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha256Id xmlSecNssTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha256GetKlass(void);

#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384

/**
 * xmlSecNssTransformEcdsaSha384Id:
 *
 * The ECDSA SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha384Id xmlSecNssTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha384GetKlass(void);

#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512

/**
 * xmlSecNssTransformEcdsaSha512Id:
 *
 * The ECDSA SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformEcdsaSha512Id xmlSecNssTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformEcdsaSha512GetKlass(void);

#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_EC */


/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * xmlSecNssKeyDataHmacId:
 *
 * The HMAC key data klass.
 */
#define xmlSecNssKeyDataHmacId \
        xmlSecNssKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataHmacGetKlass    (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataHmacSet         (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
#ifndef XMLSEC_NO_MD5
/**
 * xmlSecNssTransformHmacMd5Id:
 *
 * The HMAC with MD5 signature transform klass.
 */
#define xmlSecNssTransformHmacMd5Id \
        xmlSecNssTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_RIPEMD160
/**
 * xmlSecNssTransformHmacRipemd160Id:
 *
 * The HMAC with RipeMD160 signature transform klass.
 */
#define xmlSecNssTransformHmacRipemd160Id \
        xmlSecNssTransformHmacRipemd160GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacRipemd160GetKlass(void);
#endif /* XMLSEC_NO_RIPEMD160 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformHmacSha1Id:
 *
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecNssTransformHmacSha1Id \
        xmlSecNssTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecNssTransformHmacSha224Id:
 *
 * The HMAC with SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformHmacSha224Id \
        xmlSecNssTransformHmacSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecNssTransformHmacSha256Id:
 *
 * The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformHmacSha256Id \
        xmlSecNssTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecNssTransformHmacSha384Id:
 *
 * The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformHmacSha384Id \
        xmlSecNssTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecNssTransformHmacSha512Id:
 *
 * The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformHmacSha512Id \
        xmlSecNssTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#endif /* XMLSEC_NO_HMAC */


/********************************************************************
 *
 * PBKDF2 key and transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
 * xmlSecNssKeyDataPbkdf2Id:
 *
 * The PBKDF2 key data klass.
 */
#define xmlSecNssKeyDataPbkdf2Id \
        xmlSecNssKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataPbkdf2GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecNssKeyDataPbkdf2Set       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * xmlSecNssTransformPbkdf2Id:
 *
 * The PBKDF2 key derivation transform klass.
 */
#define xmlSecNssTransformPbkdf2Id \
        xmlSecNssTransformPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformPbkdf2GetKlass(void);

#endif /* XMLSEC_NO_PBKDF2 */


/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecNssKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecNssKeyDataRsaId \
        xmlSecNssKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecNssKeyDataRsaGetKlass     (void);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecNssTransformRsaMd5Id:
 *
 * The RSA-MD5 signature transform klass.
 */
#define xmlSecNssTransformRsaMd5Id  \
        xmlSecNssTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformRsaSha1Id:
 *
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecNssTransformRsaSha1Id     \
        xmlSecNssTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecNssTransformRsaSha224Id:
 *
 * The RSA-SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformRsaSha224Id       \
        xmlSecNssTransformRsaSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecNssTransformRsaSha256Id:
 *
 * The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformRsaSha256Id       \
        xmlSecNssTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecNssTransformRsaSha384Id:
 *
 * The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformRsaSha384Id       \
        xmlSecNssTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecNssTransformRsaSha512Id:
 *
 * The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformRsaSha512Id       \
        xmlSecNssTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformRsaPssSha1Id:
 *
 * The RSA-PSS-SHA1 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha1Id     \
        xmlSecNssTransformRsaPssSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecNssTransformRsaPssSha224Id:
 *
 * The RSA-PSS-SHA2-224 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha224Id       \
        xmlSecNssTransformRsaPssSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecNssTransformRsaPssSha256Id:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha256Id       \
        xmlSecNssTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecNssTransformRsaPssSha384Id:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha384Id       \
        xmlSecNssTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecNssTransformRsaPssSha512Id:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecNssTransformRsaPssSha512Id       \
        xmlSecNssTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


/**
 * xmlSecNssTransformRsaPkcs1Id:
 *
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecNssTransformRsaPkcs1Id \
        xmlSecNssTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaPkcs1GetKlass(void);


#ifndef XMLSEC_NO_RSA_OAEP
/**
 * xmlSecNssTransformRsaOaepId:
 *
 * The RSA OAEP key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecNssTransformRsaOaepId \
        xmlSecNssTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaOaepGetKlass(void);

/**
 * xmlSecNssTransformRsaOaepEnc11Id:
 *
 * The RSA OAEP key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecNssTransformRsaOaepEnc11Id \
        xmlSecNssTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformRsaOaepEnc11GetKlass(void);

#endif /* XMLSEC_NO_RSA_OAEP */

#endif /* XMLSEC_NO_RSA */


/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecNssTransformSha1Id:
 *
 * The SHA1 digest transform klass.
 */
#define xmlSecNssTransformSha1Id \
        xmlSecNssTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha1GetKlass   (void);
#endif /* XMLSEC_NO_SHA1 */

/********************************************************************
 *
 * SHA224 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA224
/**
 * xmlSecNssTransformSha224Id:
 *
 * The SHA2-224 digest transform klass.
 */
#define xmlSecNssTransformSha224Id \
        xmlSecNssTransformSha224GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha224GetKlass(void);
#endif /* XMLSEC_NO_SHA224 */

/********************************************************************
 *
 * SHA256 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecNssTransformSha256Id:
 *
 * The SHA2-256 digest transform klass.
 */
#define xmlSecNssTransformSha256Id \
        xmlSecNssTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

/********************************************************************
 *
 * SHA384 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecNssTransformSha384Id:
 *
 * The SHA2-384 digest transform klass.
 */
#define xmlSecNssTransformSha384Id \
        xmlSecNssTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

/********************************************************************
 *
 * SHA512 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecNssTransformSha512Id:
 *
 * The SHA2-512 digest transform klass.
 */
#define xmlSecNssTransformSha512Id \
        xmlSecNssTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/********************************************************************
 *
 * MD5 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * xmlSecNssTransformMd5Id:
 *
 * The MD5 digest transform klass.
 */
#define xmlSecNssTransformMd5Id \
        xmlSecNssTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecNssTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */



/********************************************************************
 *
 * DEREncodedKeyValue
 *
 *******************************************************************/
/**
 * xmlSecNssKeyDataDEREncodedKeyValueId:
 *
 * The Nss DEREncodedKeyValue data klass.
 */
#define xmlSecNssKeyDataDEREncodedKeyValueId    xmlSecNssKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecNssKeyDataDEREncodedKeyValueGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_CRYPTO_H__ */

#define __XMLSEC_NSS_CRYPTO_H__
