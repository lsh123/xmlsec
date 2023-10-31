/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2018 Miklos Vajna. All Rights Reserved.
 */
#ifndef __XMLSEC_MSCNG_CRYPTO_H__
#define __XMLSEC_MSCNG_CRYPTO_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_mscng(void);

XMLSEC_CRYPTO_EXPORT int xmlSecMSCngGenerateRandom(xmlSecBufferPtr buffer, xmlSecSize size);

/********************************************************************
 *
 * Init shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngInit              (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngShutdown          (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecMSCngKeysMngrInit      (xmlSecKeysMngrPtr mngr);

/********************************************************************
 *
 * ConcatKDF key and transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_CONCATKDF

 /**
 * xmlSecMSCngKeyDataConcatKdfId:
 *
 * The ConcatKDF key klass.
 */
#define xmlSecMSCngKeyDataConcatKdfId \
        xmlSecMSCngKeyDataConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataConcatKdfGetKlass(void);

/**
 * xmlSecMSCngTransformConcatKdfId:
 *
 * The ConcatKDF key derivation transform klass.
 */
#define xmlSecMSCngTransformConcatKdfId \
       xmlSecMSCngTransformConcatKdfGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformConcatKdfGetKlass(void);
#endif /* XMLSEC_NO_CONCATKDF */

/********************************************************************
 *
 * DSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecMSCngKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecMSCngKeyDataDsaId \
        xmlSecMSCngKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataDsaGetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformDsaSha1Id:
 *
 * The DSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformDsaSha1Id     \
       xmlSecMSCngTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#endif /* XMLSEC_NO_DSA */

/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecMSCngKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecMSCngKeyDataRsaId \
        xmlSecMSCngKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataRsaGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecMSCngTransformRsaMd5Id:
 *
 * The RSA-MD5 signature transform klass.
 */
#define xmlSecMSCngTransformRsaMd5Id     \
       xmlSecMSCngTransformRsaMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformRsaSha1Id:
 *
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha1Id     \
       xmlSecMSCngTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformRsaSha256Id:
 *
 * The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha256Id     \
       xmlSecMSCngTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformRsaSha384Id:
 *
 * The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha384Id     \
       xmlSecMSCngTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformRsaSha512Id:
 *
 * The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformRsaSha512Id     \
       xmlSecMSCngTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformRsaPssSha1Id:
 *
 * The RSA-PSS-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha1Id     \
       xmlSecMSCngTransformRsaPssSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformRsaPssSha256Id:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha256Id     \
       xmlSecMSCngTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformRsaPssSha384Id:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha384Id     \
       xmlSecMSCngTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformRsaPssSha512Id:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformRsaPssSha512Id     \
       xmlSecMSCngTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/**
 * xmlSecMSCngTransformRsaPkcs1Id:
 *
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecMSCngTransformRsaPkcs1Id \
        xmlSecMSCngTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaPkcs1GetKlass(void);

/**
 * xmlSecMSCngTransformRsaOaepId:
 *
 * The RSA OAEP key transport transform klass (XMLEnc 1.0).
 */
#define xmlSecMSCngTransformRsaOaepId \
        xmlSecMSCngTransformRsaOaepGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaOaepGetKlass(void);


/**
 * xmlSecMSCngTransformRsaOaepEnc11Id:
 *
 * The RSA OAEP key transport transform klass (XMLEnc 1.1).
 */
#define xmlSecMSCngTransformRsaOaepEnc11Id \
        xmlSecMSCngTransformRsaOaepEnc11GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformRsaOaepEnc11GetKlass(void);

#endif /* XMLSEC_NO_RSA */

/********************************************************************
 *
 * EC key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * xmlSecMSCngKeyDataEcId:
 *
 * The EC key klass.
 */
#define xmlSecMSCngKeyDataEcId          xmlSecMSCngKeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataEcGetKlass(void);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformEcdsaSha1Id:
 *
 * The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha1Id     \
       xmlSecMSCngTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformEcdsaSha256Id:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha256Id     \
       xmlSecMSCngTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformEcdsaSha384Id:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha384Id     \
       xmlSecMSCngTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformEcdsaSha512Id:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformEcdsaSha512Id     \
       xmlSecMSCngTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/**
 * xmlSecMSCngTransformEcdhId:
 *
 * The ECDH key agreement transform klass.
 */
#define xmlSecMSCngTransformEcdhId \
       xmlSecMSCngTransformEcdhGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformEcdhGetKlass(void);

#endif /* XMLSEC_NO_EC */

/********************************************************************
 *
 * DES transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES

/**
 * xmlSecMSCngKeyDataDesId:
 *
 * The DES key data klass.
 */
#define xmlSecMSCngKeyDataDesId \
        xmlSecMSCngKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataDesGetKlass(void);

/**
 * xmlSecMSCngTransformDes3CbcId:
 *
 * The DES3 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformDes3CbcId \
        xmlSecMSCngTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformDes3CbcGetKlass(void);

/**
 * xmlSecMSCngTransformKWDes3Id:
 *
 * The DES3 KW transform klass.
 */
#define xmlSecMSCngTransformKWDes3Id \
        xmlSecMSCngTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWDes3GetKlass(void);

#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * xmlSecMSCngKeyDataHmacId:
 *
 * The HMAC key klass.
 */
#define xmlSecMSCngKeyDataHmacId \
        xmlSecMSCngKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataHmacGetKlass(void);

#ifndef XMLSEC_NO_MD5
/**
 * xmlSecMSCngTransformHmacMd5Id:
 *
 * The HMAC-MD5 signature transform klass.
 */
#define xmlSecMSCngTransformHmacMd5Id     \
       xmlSecMSCngTransformHmacMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformHmacSha1Id:
 *
 * The HMAC-SHA1 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha1Id     \
       xmlSecMSCngTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformHmacSha256Id:
 *
 * The HMAC-SHA2-256 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha256Id     \
       xmlSecMSCngTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformHmacSha384Id:
 *
 * The HMAC-SHA2-384 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha384Id     \
       xmlSecMSCngTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformHmacSha512Id:
 *
 * The HMAC-SHA2-512 signature transform klass.
 */
#define xmlSecMSCngTransformHmacSha512Id     \
       xmlSecMSCngTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */

/********************************************************************
 *
 * MD5 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_MD5
/**
 * xmlSecMSCngTransformMd5Id:
 *
 * The MD5 digest transform klass.
 */
#define xmlSecMSCngTransformMd5Id \
       xmlSecMSCngTransformMd5GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformMd5GetKlass(void);
#endif /* XMLSEC_NO_MD5 */

/********************************************************************
 *
 * PBKDF2 key and transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
* xmlSecMSCngKeyDataPbkdf2Id:
*
* The PBKDF2 key klass.
*/
#define xmlSecMSCngKeyDataPbkdf2Id \
        xmlSecMSCngKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId xmlSecMSCngKeyDataPbkdf2GetKlass(void);

/**
 * xmlSecMSCngTransformPbkdf2Id:
 *
 * The PBDKF2 key derivation transform klass.
 */
#define xmlSecMSCngTransformPbkdf2Id \
       xmlSecMSCngTransformPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformPbkdf2GetKlass(void);
#endif /* XMLSEC_NO_PBKDF2 */

/********************************************************************
 *
 * SHA1 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecMSCngTransformSha1Id:
 *
 * The SHA1 digest transform klass.
 */
#define xmlSecMSCngTransformSha1Id \
       xmlSecMSCngTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

/********************************************************************
 *
 * SHA256 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecMSCngTransformSha256Id:
 *
 * The SHA2-256 digest transform klass.
 */
#define xmlSecMSCngTransformSha256Id \
       xmlSecMSCngTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

/********************************************************************
 *
 * SHA384 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecMSCngTransformSha384Id:
 *
 * The SHA2-384 digest transform klass.
 */
#define xmlSecMSCngTransformSha384Id \
       xmlSecMSCngTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

/********************************************************************
 *
 * SHA512 transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecMSCngTransformSha512Id:
 *
 * The SHA2-512 digest transform klass.
 */
#define xmlSecMSCngTransformSha512Id \
       xmlSecMSCngTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecMSCngKeyDataAesId:
 *
 * The AES key data klass.
 */
#define xmlSecMSCngKeyDataAesId \
        xmlSecMSCngKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecMSCngKeyDataAesGetKlass(void);

/**
 * xmlSecMSCngTransformAes128CbcId:
 *
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes128CbcId \
        xmlSecMSCngTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes128CbcGetKlass(void);

/**
 * xmlSecMSCngTransformAes192CbcId:
 *
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes192CbcId \
        xmlSecMSCngTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes192CbcGetKlass(void);

/**
 * xmlSecMSCngTransformAes256CbcId:
 *
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecMSCngTransformAes256CbcId \
        xmlSecMSCngTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes256CbcGetKlass(void);

/**
 * xmlSecMSCngTransformAes128GcmId:
 *
 * The AES128 GCM cipher transform klass.
 */
#define xmlSecMSCngTransformAes128GcmId \
        xmlSecMSCngTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes128GcmGetKlass(void);

/**
 * xmlSecMSCngTransformAes192GcmId:
 *
 * The AES192 GCM cipher transform klass.
 */
#define xmlSecMSCngTransformAes192GcmId \
        xmlSecMSCngTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes192GcmGetKlass(void);

/**
 * xmlSecMSCngTransformAes256GcmId:
 *
 * The AES256 GCM cipher transform klass.
 */
#define xmlSecMSCngTransformAes256GcmId \
        xmlSecMSCngTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecMSCngTransformAes256GcmGetKlass(void);

/**
 * xmlSecMSCngTransformKWAes128Id:
 *
 * The AES 128 key wrap transform klass.
 */
#define xmlSecMSCngTransformKWAes128Id \
        xmlSecMSCngTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWAes128GetKlass(void);

/**
 * xmlSecMSCngTransformKWAes192Id:
 *
 * The AES 192 key wrap transform klass.
 */
#define xmlSecMSCngTransformKWAes192Id \
        xmlSecMSCngTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWAes192GetKlass(void);

/**
 * xmlSecMSCngTransformKWAes256Id:
 *
 * The AES 256 key wrap transform klass.
 */
#define xmlSecMSCngTransformKWAes256Id \
        xmlSecMSCngTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecMSCngTransformKWAes256GetKlass(void);
#endif /* XMLSEC_NO_AES */


/**
 * xmlSecMSCngKeyDataDEREncodedKeyValueId:
 *
 * The MSCng DEREncodedKeyValue data klass.
 */
#define xmlSecMSCngKeyDataDEREncodedKeyValueId   xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecMSCngKeyDataDEREncodedKeyValueGetKlass(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_MSCNG_CRYPTO_H__ */
