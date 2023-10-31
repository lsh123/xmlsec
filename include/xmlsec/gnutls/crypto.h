/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_GNUTLS_CRYPTO_H__
#define __XMLSEC_GNUTLS_CRYPTO_H__

#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>
#include <gnutls/gnutls.h>
#ifndef XMLSEC_NO_DSA
#include <gnutls/x509.h>
#endif /* XMLSEC_NO_DSA */
#ifndef XMLSEC_NO_RSA
#include <gnutls/x509.h>
#endif /* XMLSEC_NO_RSA */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctions_gnutls(void);

/********************************************************************
 *
 * Init shutdown
 *
 ********************************************************************/
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSInit                (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSShutdown            (void);

XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeysMngrInit        (xmlSecKeysMngrPtr mngr);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSGenerateRandom      (xmlSecBufferPtr buffer,
                                                                         xmlSecSize size);



/********************************************************************
 *
 * Asymetric keys helpers
 *
 *******************************************************************/

XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr       xmlSecGCryptAsymetricKeyCreatePub       (gnutls_pubkey_t pubkey);
XMLSEC_CRYPTO_EXPORT xmlSecKeyPtr       xmlSecGCryptAsymetricKeyCreatePriv      (gnutls_privkey_t privkey);

XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGCryptAsymetricKeyGetPub          (xmlSecKeyPtr key);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGCryptAsymetricKeyGetPriv         (xmlSecKeyPtr key);

/********************************************************************
 *
 * AES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_AES
/**
 * xmlSecGnuTLSKeyDataAesId:
 *
 * The AES key data klass.
 */
#define xmlSecGnuTLSKeyDataAesId \
        xmlSecGnuTLSKeyDataAesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataAesGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataAesSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);
/**
 * xmlSecGnuTLSTransformAes128CbcId:
 *
 * The AES128 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes128CbcId \
        xmlSecGnuTLSTransformAes128CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes128CbcGetKlass(void);

/**
 * xmlSecGnuTLSTransformAes192CbcId:
 *
 * The AES192 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes192CbcId \
        xmlSecGnuTLSTransformAes192CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes192CbcGetKlass(void);

/**
 * xmlSecGnuTLSTransformAes256CbcId:
 *
 * The AES256 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes256CbcId \
        xmlSecGnuTLSTransformAes256CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes256CbcGetKlass(void);


/**
 * xmlSecGnuTLSTransformAes128GcmId:
 *
 * The AES128 GCM cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes128GcmId \
        xmlSecGnuTLSTransformAes128GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes128GcmGetKlass(void);

/**
 * xmlSecGnuTLSTransformAes192GcmId:
 *
 * The AES192 GCM cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes192GcmId \
        xmlSecGnuTLSTransformAes192GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes192GcmGetKlass(void);

/**
 * xmlSecGnuTLSTransformAes256GcmId:
 *
 * The AES256 GCM cipher transform klass.
 */
#define xmlSecGnuTLSTransformAes256GcmId \
        xmlSecGnuTLSTransformAes256GcmGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformAes256GcmGetKlass(void);


/**
 * xmlSecGnuTLSTransformKWAes128Id:
 *
 * The AES 128 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWAes128Id \
        xmlSecGnuTLSTransformKWAes128GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWAes128GetKlass(void);

/**
 * xmlSecGnuTLSTransformKWAes192Id:
 *
 * The AES 192 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWAes192Id \
        xmlSecGnuTLSTransformKWAes192GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWAes192GetKlass(void);

/**
 * xmlSecGnuTLSTransformKWAes256Id:
 *
 * The AES 256 key wrap transform klass.
 */
#define xmlSecGnuTLSTransformKWAes256Id \
        xmlSecGnuTLSTransformKWAes256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId  xmlSecGnuTLSTransformKWAes256GetKlass(void);


#endif /* XMLSEC_NO_AES */

/********************************************************************
 *
 * DES transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DES
/**
 * xmlSecGnuTLSKeyDataDesId:
 *
 * The DES key data klass.
 */
#define xmlSecGnuTLSKeyDataDesId \
        xmlSecGnuTLSKeyDataDesGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataDesGetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataDesSet       (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

/**
 * xmlSecGnuTLSTransformDes3CbcId:
 *
 * The DES3 CBC cipher transform klass.
 */
#define xmlSecGnuTLSTransformDes3CbcId \
        xmlSecGnuTLSTransformDes3CbcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDes3CbcGetKlass(void);

/**
 * xmlSecGnuTLSTransformKWDes3Id:
 *
 * The DES3 KW transform klass.
 */
#define xmlSecGnuTLSTransformKWDes3Id \
        xmlSecGnuTLSTransformKWDes3GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformKWDes3GetKlass(void);

#endif /* XMLSEC_NO_DES */

/********************************************************************
 *
 * DSA transform
 *
 *******************************************************************/
#ifndef XMLSEC_NO_DSA

/**
 * xmlSecGnuTLSKeyDataDsaId:
 *
 * The DSA key klass.
 */
#define xmlSecGnuTLSKeyDataDsaId \
        xmlSecGnuTLSKeyDataDsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataDsaGetKlass          (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataDsaAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataDsaGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataDsaGetPrivateKey     (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformDsaSha1Id:
 *
 * The DSA SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformDsaSha1Id \
        xmlSecGnuTLSTransformDsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformDsaSha256Id:
 *
 * The DSA SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformDsaSha256Id \
        xmlSecGnuTLSTransformDsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformDsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#endif /* XMLSEC_NO_DSA */


/********************************************************************
 *
 * EC key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_EC

/**
 * xmlSecGnuTLSKeyDataEcId:
 *
 * The EC key klass.
 */
#define xmlSecGnuTLSKeyDataEcId         xmlSecGnuTLSKeyDataEcGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataEcGetKlass           (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataEcAdoptKey           (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataEcGetPublicKey       (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataEcGetPrivateKey      (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformEcdsaSha1Id:
 *
 * The ECDSA-SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha1Id \
        xmlSecGnuTLSTransformEcdsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformEcdsaSha256Id:
 *
 * The ECDSA-SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha256Id       \
        xmlSecGnuTLSTransformEcdsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGnuTLSTransformEcdsaSha384Id:
 *
 * The ECDSA-SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha384Id       \
        xmlSecGnuTLSTransformEcdsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGnuTLSTransformEcdsaSha512Id:
 *
 * The ECDSA-SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha512Id       \
        xmlSecGnuTLSTransformEcdsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecGnuTLSTransformEcdsaSha3_256Id:
 *
 * The ECDSA-SHA3-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_256Id       \
        xmlSecGnuTLSTransformEcdsaSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_256GetKlass(void);

/**
 * xmlSecGnuTLSTransformEcdsaSha3_384Id:
 *
 * The ECDSA-SHA3-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_384Id       \
        xmlSecGnuTLSTransformEcdsaSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_384GetKlass(void);

/**
 * xmlSecGnuTLSTransformEcdsaSha3_512Id:
 *
 * The ECDSA-SHA3-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformEcdsaSha3_512Id       \
        xmlSecGnuTLSTransformEcdsaSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformEcdsaSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */

#endif /* XMLSEC_NO_EC */


/********************************************************************
 *
 * GOST 2001 key and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_GOST

/**
 * xmlSecGnuTLSKeyDataGost2001Id:
 *
 * The GOST 2001 key klass.
 */
#define xmlSecGnuTLSKeyDataGost2001Id   xmlSecGnuTLSKeyDataGost2001GetKlass     ()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataGost2001GetKlass     (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataGost2001AdoptKey     (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataGost2001GetPublicKey (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataGost2001GetPrivateKey(xmlSecKeyDataPtr data);

/**
 * xmlSecGnuTLSTransformGostR3411_94Id:
 *
 * The GOSTR3411_94 digest transform klass.
 */
#define xmlSecGnuTLSTransformGostR3411_94Id \
        xmlSecGnuTLSTransformGostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3411_94GetKlass(void);

/**
 * xmlSecGnuTLSTransformGost2001GostR3411_94Id:
 *
 * The GOST2001 GOSTR3411_94 signature transform klass.
 */
#define xmlSecGnuTLSTransformGost2001GostR3411_94Id \
        xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGost2001GostR3411_94GetKlass(void);

#endif /* XMLSEC_NO_GOST */


/********************************************************************
 *
 * GOST 2012 keys and transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_GOST2012

/**
 * xmlSecGnuTLSKeyDataGost2012_256Id:
 *
 * The GOST R 34.10-2012 256 bit key klass.
 */
#define xmlSecGnuTLSKeyDataGost2012_256Id   xmlSecGnuTLSKeyDataGost2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataGost2012_256GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataGost2012_256AdoptKey  (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataGost2012_256GetPublicKey (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataGost2012_256GetPrivateKey(xmlSecKeyDataPtr data);

/**
 * xmlSecGnuTLSKeyDataGost2012_512Id:
 *
 * The GOST R 34.10-2012 512 bit key klass.
 */
#define xmlSecGnuTLSKeyDataGost2012_512Id   xmlSecGnuTLSKeyDataGost2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataGost2012_512GetKlass  (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataGost2012_512AdoptKey  (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataGost2012_512GetPublicKey (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataGost2012_512GetPrivateKey(xmlSecKeyDataPtr data);



/**
 * xmlSecGnuTLSTransformGostR3411_2012_256Id:
 *
 * The GOST R 34.11-2012 256 bit digest transform klass.
 */
#define xmlSecGnuTLSTransformGostR3411_2012_256Id \
    xmlSecGnuTLSTransformGostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3411_2012_256GetKlass(void);


/**
 * xmlSecGnuTLSTransformGostR3411_2012_512Id:
 *
 * The GOST R 34.11-2012 512 bit digest transform klass.
 */
#define xmlSecGnuTLSTransformGostR3411_2012_512Id \
    xmlSecGnuTLSTransformGostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3411_2012_512GetKlass(void);


/**
 * xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Id:
 *
 * The GOST R 34.10-2012 - GOST R 3411-2012 256 bit signature transform klass.
 */
#define xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256Id \
        xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_256GetKlass(void);


/**
 * xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Id:
 *
 * The GOST R 34.10-2012 - GOST R 3411-2012 512 bit signature transform klass.
 */
#define xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512Id \
        xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformGostR3410_2012GostR3411_2012_512GetKlass(void);


#endif /* XMLSEC_NO_GOST2012 */

/********************************************************************
 *
 * HMAC transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_HMAC

/**
 * xmlSecGnuTLSKeyDataHmacId:
 *
 * The HMAC key klass.
 */
#define xmlSecGnuTLSKeyDataHmacId \
        xmlSecGnuTLSKeyDataHmacGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataHmacGetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataHmacSet      (xmlSecKeyDataPtr data,
                                                                         const xmlSecByte* buf,
                                                                         xmlSecSize bufSize);

#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformHmacSha1Id:
 *
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha1Id \
        xmlSecGnuTLSTransformHmacSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformHmacSha256Id:
 *
 * The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha256Id \
        xmlSecGnuTLSTransformHmacSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGnuTLSTransformHmacSha384Id:
 *
 * The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha384Id \
        xmlSecGnuTLSTransformHmacSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGnuTLSTransformHmacSha512Id:
 *
 * The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformHmacSha512Id \
        xmlSecGnuTLSTransformHmacSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformHmacSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */

#endif /* XMLSEC_NO_HMAC */


/********************************************************************
 *
 * PBKDF2 transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_PBKDF2

/**
 * xmlSecGnuTLSKeyDataPbkdf2Id:
 *
 * The PBKDF2 key klass.
 */
#define xmlSecGnuTLSKeyDataPbkdf2Id \
        xmlSecGnuTLSKeyDataPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataPbkdf2GetKlass (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataPbkdf2Set      (xmlSecKeyDataPtr data,
                                                                           const xmlSecByte* buf,
                                                                           xmlSecSize bufSize);

/**
 * xmlSecGnuTLSTransformPbkdf2Id:
 *
 * The PBKDF2 key derivation transform klass.
 */
#define xmlSecGnuTLSTransformPbkdf2Id \
        xmlSecGnuTLSTransformPbkdf2GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformPbkdf2GetKlass(void);

#endif /* XMLSEC_NO_PBKDF2 */

/********************************************************************
 *
 * RSA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_RSA

/**
 * xmlSecGnuTLSKeyDataRsaId:
 *
 * The RSA key klass.
 */
#define xmlSecGnuTLSKeyDataRsaId \
        xmlSecGnuTLSKeyDataRsaGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId    xmlSecGnuTLSKeyDataRsaGetKlass          (void);
XMLSEC_CRYPTO_EXPORT int                xmlSecGnuTLSKeyDataRsaAdoptKey          (xmlSecKeyDataPtr data,
                                                                                 gnutls_pubkey_t pubkey,
                                                                                 gnutls_privkey_t privkey);
XMLSEC_CRYPTO_EXPORT gnutls_pubkey_t    xmlSecGnuTLSKeyDataRsaGetPublicKey      (xmlSecKeyDataPtr data);
XMLSEC_CRYPTO_EXPORT gnutls_privkey_t   xmlSecGnuTLSKeyDataRsaGetPrivateKey     (xmlSecKeyDataPtr data);


#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformRsaSha1Id:
 *
 * The RSA-SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha1Id \
        xmlSecGnuTLSTransformRsaSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformRsaSha256Id:
 *
 * The RSA-SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha256Id       \
        xmlSecGnuTLSTransformRsaSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGnuTLSTransformRsaSha384Id:
 *
 * The RSA-SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha384Id       \
        xmlSecGnuTLSTransformRsaSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGnuTLSTransformRsaSha512Id:
 *
 * The RSA-SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaSha512Id       \
        xmlSecGnuTLSTransformRsaSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformRsaPssSha256Id:
 *
 * The RSA-PSS-SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaPssSha256Id       \
        xmlSecGnuTLSTransformRsaPssSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPssSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGnuTLSTransformRsaPssSha384Id:
 *
 * The RSA-PSS-SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaPssSha384Id       \
        xmlSecGnuTLSTransformRsaPssSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPssSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGnuTLSTransformRsaPssSha512Id:
 *
 * The RSA-PSS-SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformRsaPssSha512Id       \
        xmlSecGnuTLSTransformRsaPssSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPssSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


/**
 * xmlSecGnuTLSTransformRsaPkcs1Id:
 *
 * The RSA PKCS1 key transport transform klass.
 */
#define xmlSecGnuTLSTransformRsaPkcs1Id \
        xmlSecGnuTLSTransformRsaPkcs1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformRsaPkcs1GetKlass(void);

#endif /* XMLSEC_NO_RSA */


/********************************************************************
 *
 * SHA transforms
 *
 *******************************************************************/
#ifndef XMLSEC_NO_SHA1
/**
 * xmlSecGnuTLSTransformSha1Id:
 *
 * The HMAC with SHA1 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha1Id \
        xmlSecGnuTLSTransformSha1GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha1GetKlass(void);
#endif /* XMLSEC_NO_SHA1 */

#ifndef XMLSEC_NO_SHA256
/**
 * xmlSecGnuTLSTransformSha256Id:
 *
 * The HMAC with SHA2-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha256Id \
        xmlSecGnuTLSTransformSha256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha256GetKlass(void);
#endif /* XMLSEC_NO_SHA256 */

#ifndef XMLSEC_NO_SHA384
/**
 * xmlSecGnuTLSTransformSha384Id:
 *
 * The HMAC with SHA2-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha384Id \
        xmlSecGnuTLSTransformSha384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha384GetKlass(void);
#endif /* XMLSEC_NO_SHA384 */

#ifndef XMLSEC_NO_SHA512
/**
 * xmlSecGnuTLSTransformSha512Id:
 *
 * The HMAC with SHA2-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha512Id \
        xmlSecGnuTLSTransformSha512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha512GetKlass(void);
#endif /* XMLSEC_NO_SHA512 */


#ifndef XMLSEC_NO_SHA3
/**
 * xmlSecGnuTLSTransformSha3_256Id:
 *
 * The HMAC with SHA3-256 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha3_256Id \
        xmlSecGnuTLSTransformSha3_256GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_256GetKlass(void);

/**
 * xmlSecGnuTLSTransformSha3_384Id:
 *
 * The HMAC with SHA3-384 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha3_384Id \
        xmlSecGnuTLSTransformSha3_384GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_384GetKlass(void);

/**
 * xmlSecGnuTLSTransformSha3_512Id:
 *
 * The HMAC with SHA3-512 signature transform klass.
 */
#define xmlSecGnuTLSTransformSha3_512Id \
        xmlSecGnuTLSTransformSha3_512GetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecTransformId xmlSecGnuTLSTransformSha3_512GetKlass(void);
#endif /* XMLSEC_NO_SHA3 */


/**
 * xmlSecGnuTLSKeyDataDEREncodedKeyValueId:
 *
 * The GnuTLS DEREncodedKeyValue data klass.
 */
#define xmlSecGnuTLSKeyDataDEREncodedKeyValueId  xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass()
XMLSEC_CRYPTO_EXPORT xmlSecKeyDataId             xmlSecGnuTLSKeyDataDEREncodedKeyValueGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_GNUTLS_CRYPTO_H__ */

#define __XMLSEC_GNUTLS_CRYPTO_H__
