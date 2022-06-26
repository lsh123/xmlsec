/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:pkikeys
 * @Short_description: Private/public keys implementation for NSS.
 * @Stability: Stable
 *
 */

#include "globals.h"

#include <string.h>

#include <pk11func.h>
#include <keyhi.h>
#include <pk11pqg.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/private.h>
#include <xmlsec/transforms.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/bignum.h>
#include <xmlsec/nss/pkikeys.h>

#include "../cast_helpers.h"
#include "../keysdata_helpers.h"


/**************************************************************************
 *
 * Internal NSS PKI key CTX
 *
 *************************************************************************/
typedef struct _xmlSecNssPKIKeyDataCtx  xmlSecNssPKIKeyDataCtx,
                                                *xmlSecNssPKIKeyDataCtxPtr;
struct _xmlSecNssPKIKeyDataCtx {
    SECKEYPublicKey  *pubkey;
    SECKEYPrivateKey *privkey;
};

/******************************************************************************
 *
 * PKI key data (dsa/rsa)
 *
 *****************************************************************************/
XMLSEC_KEY_DATA_DECLARE(NssPKIKeyData, xmlSecNssPKIKeyDataCtx)
#define xmlSecNssPKIKeyDataSize XMLSEC_KEY_DATA_SIZE(NssPKIKeyData)

static int              xmlSecNssPKIKeyDataInitialize   (xmlSecKeyDataPtr data);
static void             xmlSecNssPKIKeyDataFinalize     (xmlSecKeyDataPtr data);


static void             xmlSecNSSPKIKeyDataCtxFree      (xmlSecNssPKIKeyDataCtxPtr ctx);
static int              xmlSecNSSPKIKeyDataCtxDup       (xmlSecNssPKIKeyDataCtxPtr ctxDst,
                                                         xmlSecNssPKIKeyDataCtxPtr ctxSrc);
static int              xmlSecNssPKIKeyDataAdoptKey     (xmlSecKeyDataPtr data,
                                                         SECKEYPrivateKey *privkey,
                                                         SECKEYPublicKey  *pubkey);


static int
xmlSecNssPKIKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssPKIKeyDataSize), -1);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssPKIKeyDataCtx));

    return(0);
}


static void
xmlSecNssPKIKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecKeyDataIsValid(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecNssPKIKeyDataSize));

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    xmlSecNSSPKIKeyDataCtxFree(ctx);
    memset(ctx, 0, sizeof(xmlSecNssPKIKeyDataCtx));
}


static void
xmlSecNSSPKIKeyDataCtxFree(xmlSecNssPKIKeyDataCtxPtr ctx)
{
    xmlSecAssert(ctx != NULL);
    if (ctx->privkey != NULL) {
        SECKEY_DestroyPrivateKey(ctx->privkey);
        ctx->privkey = NULL;
    }

    if (ctx->pubkey)
    {
        SECKEY_DestroyPublicKey(ctx->pubkey);
        ctx->pubkey = NULL;
    }

}

static int
xmlSecNSSPKIKeyDataCtxDup(xmlSecNssPKIKeyDataCtxPtr ctxDst,
                          xmlSecNssPKIKeyDataCtxPtr ctxSrc)
{
    xmlSecNSSPKIKeyDataCtxFree(ctxDst);
    if (ctxSrc->privkey != NULL) {
        ctxDst->privkey = SECKEY_CopyPrivateKey(ctxSrc->privkey);
        if(ctxDst->privkey == NULL) {
            xmlSecNssError("SECKEY_CopyPrivateKey", NULL);
            return(-1);
        }
    }

    if (ctxSrc->pubkey != NULL) {
        ctxDst->pubkey = SECKEY_CopyPublicKey(ctxSrc->pubkey);
        if(ctxDst->pubkey == NULL) {
            xmlSecNssError("SECKEY_CopyPublicKey", NULL);
            return(-1);
        }
    }
    return (0);
}

static int
xmlSecNssPKIKeyDataAdoptKey(xmlSecKeyDataPtr data,
                            SECKEYPrivateKey *privkey,
                            SECKEYPublicKey  *pubkey)
{
    xmlSecNssPKIKeyDataCtxPtr ctx;
    KeyType pubType = nullKey;
    KeyType priType = nullKey;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssPKIKeyDataSize), -1);

    if(privkey != NULL) {
        priType = SECKEY_GetPrivateKeyType(privkey);
    }

    if(pubkey != NULL) {
        pubType = SECKEY_GetPublicKeyType(pubkey);
    }

    if(priType != nullKey && pubType != nullKey) {
        if(pubType != priType) {
            xmlSecNssError3("SECKEY_GetPrivateKeyType/SECKEY_GetPublicKeyType", NULL,
                "pubType=%u; priType=%u", pubType, priType);
            return -1;
        }
    }

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if (ctx->privkey) {
        SECKEY_DestroyPrivateKey(ctx->privkey);
    }
    ctx->privkey = privkey;

    if (ctx->pubkey) {
        SECKEY_DestroyPublicKey(ctx->pubkey);
    }
    ctx->pubkey = pubkey;

    return(0);
}

/**
 * xmlSecNssPKIAdoptKey:
 * @privkey:        the NSS Private Key handle
 * @pubkey:         the NSS Public Key handle
 *
 * Build a KeyData object from the given Private Key and Public
 * Key handles.
 *
 * Returns: pointer to KeyData object or NULL if an error occurs.
 */
xmlSecKeyDataPtr
xmlSecNssPKIAdoptKey(SECKEYPrivateKey *privkey,
                     SECKEYPublicKey  *pubkey)
{
    xmlSecKeyDataPtr data = NULL;
    int ret;
    KeyType pubType = nullKey;
    KeyType priType = nullKey;

    if(privkey != NULL) {
        priType = SECKEY_GetPrivateKeyType(privkey);
    }

    if(pubkey != NULL) {
        pubType = SECKEY_GetPublicKeyType(pubkey);
    }

    if(priType != nullKey && pubType != nullKey) {
        if(pubType != priType) {
            xmlSecNssError3("SECKEY_GetPrivateKeyType/SECKEY_GetPublicKeyType", NULL,
                "pubType=%u; priType=%u", pubType, priType);
            return(NULL);
        }
    }

    pubType = (priType != nullKey) ? priType : pubType;
    switch(pubType) {
#ifndef XMLSEC_NO_RSA
    case rsaKey:
        data = xmlSecKeyDataCreate(xmlSecNssKeyDataRsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(KeyDataRsaId)", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_RSA */
#ifndef XMLSEC_NO_DSA
    case dsaKey:
        data = xmlSecKeyDataCreate(xmlSecNssKeyDataDsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_DSA */
#ifndef XMLSEC_NO_ECDSA
    case ecKey:
        data = xmlSecKeyDataCreate(xmlSecNssKeyDataEcdsaId);
        if(data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_ECDSA */
    default:
        xmlSecUnsupportedEnumValueError("pubType", pubType, NULL);
        return(NULL);
    }

    xmlSecAssert2(data != NULL, NULL);
    ret = xmlSecNssPKIKeyDataAdoptKey(data, privkey, pubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssPKIKeyDataAdoptKey", NULL);
        xmlSecKeyDataDestroy(data);
        return(NULL);
    }
    return(data);
}

/**
 * xmlSecNssPKIKeyDataGetPubKey:
 * @data:               the pointer to NSS Key data.
 *
 * Gets the Public Key from the key data.
 *
 * Returns: pointer to SECKEYPublicKey or NULL if an error occurs.
 * Caller is responsible for freeing the key when done
 */
SECKEYPublicKey *
xmlSecNssPKIKeyDataGetPubKey(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;
    SECKEYPublicKey *ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssPKIKeyDataSize), NULL);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->pubkey != NULL, NULL);

    ret = SECKEY_CopyPublicKey(ctx->pubkey);
    return(ret);
}

/**
 * xmlSecNssPKIKeyDataGetPrivKey:
 * @data:               the pointer to NSS Key data.
 *
 * Gets the Private Key from the key data.
 *
 * Returns: pointer to SECKEYPrivateKey or NULL if an error occurs.
 * Caller is responsible for freeing the key when done
 */
SECKEYPrivateKey*
xmlSecNssPKIKeyDataGetPrivKey(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;
    SECKEYPrivateKey* ret;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssPKIKeyDataSize), NULL);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);
    xmlSecAssert2(ctx->privkey != NULL, NULL);

    ret = SECKEY_CopyPrivateKey(ctx->privkey);
    return(ret);
}

/**
 * xmlSecNssPKIKeyDataGetKeyType:
 * @data:               the pointer to NSS Key data.
 *
 * Gets the Key Type from the key data.
 *
 * Returns: Key Type
 */
KeyType
xmlSecNssPKIKeyDataGetKeyType(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;
    KeyType kt;

    xmlSecAssert2(xmlSecKeyDataIsValid(data), nullKey);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssPKIKeyDataSize), nullKey);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, nullKey);

    if (ctx->pubkey != NULL) {
        kt = SECKEY_GetPublicKeyType(ctx->pubkey);
    } else {
        kt = SECKEY_GetPrivateKeyType(ctx->privkey);
    }
    return(kt);
}

/**
 * xmlSecNssPKIKeyDataDuplicate
 * @dst:               the pointer to NSS Key data to copy to.
 * @src:               the pointer to NSS Key data to copy from.
 *
 * Duplicates the keydata from src to dst
 *
 * Returns: -1 on error, 0 on success
 */
int
xmlSecNssPKIKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecNssPKIKeyDataCtxPtr ctxDst;
    xmlSecNssPKIKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecKeyDataIsValid(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecNssPKIKeyDataSize), -1);
    xmlSecAssert2(xmlSecKeyDataIsValid(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecNssPKIKeyDataSize), -1);

    ctxDst = xmlSecNssPKIKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);

    ctxSrc = xmlSecNssPKIKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    if (xmlSecNSSPKIKeyDataCtxDup(ctxDst, ctxSrc) != 0) {
        xmlSecInternalError("xmlSecNssPKIKeydataCtxDup",
                            xmlSecKeyDataGetName(dst));
        return(-1);
    }

    return(0);
}

/**************************************************************************
 *
 * Helpers
 *
 *************************************************************************/
static int
xmlSecNssGetBigNumValue(xmlSecBufferPtr buf, PRArenaPool *arena, SECItem *val) {
    xmlSecByte* data;
    xmlSecSize size;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(arena != NULL, -1);
    xmlSecAssert2(val != NULL, -1);
    xmlSecAssert2(val->data == NULL, -1);
    xmlSecAssert2(val->len == 0, -1);

    data = xmlSecBufferGetData(buf);
    size = xmlSecBufferGetSize(buf);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_UINT(size, val->len, return(-1), NULL);
    val->data = PORT_ArenaZAlloc(arena, val->len);
    if(val->data == NULL) {
        xmlSecMallocError(size, NULL);
        val->len = 0;
        return(-1);
    }
    PORT_Memcpy(val->data, data, val->len);
    return(0);
}

static int
xmlSecNssSetBigNumValue(const SECItem *val, xmlSecBufferPtr buf) {
    int ret;

    xmlSecAssert2(val != NULL, -1);
    xmlSecAssert2(val->data != NULL, -1);
    xmlSecAssert2(val->len > 0, -1);
    xmlSecAssert2(buf != NULL, -1);

    ret = xmlSecBufferSetData(buf, val->data, val->len);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetData", NULL,
            "size=%u", val->len);
        return(-1);
    }
    return(0);
}

#ifndef XMLSEC_NO_DSA
/**************************************************************************
 *
 * <dsig:DSAKeyValue> processing
 *
 *
 * The DSAKeyValue Element (http://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue)
 *
 * DSA keys and the DSA signature algorithm are specified in [DSS].
 * DSA public key values can have the following fields:
 *
 *   * P - a prime modulus meeting the [DSS] requirements
 *   * Q - an integer in the range 2**159 < Q < 2**160 which is a prime
 *         divisor of P-1
 *   * G - an integer with certain properties with respect to P and Q
 *   * Y - G**X mod P (where X is part of the private key and not made
 *         public)
 *   * J - (P - 1) / Q
 *   * seed - a DSA prime generation seed
 *   * pgenCounter - a DSA prime generation counter
 *
 * Parameter J is available for inclusion solely for efficiency as it is
 * calculatable from P and Q. Parameters seed and pgenCounter are used in the
 * DSA prime number generation algorithm specified in [DSS]. As such, they are
 * optional but must either both be present or both be absent. This prime
 * generation algorithm is designed to provide assurance that a weak prime is
 * not being used and it yields a P and Q value. Parameters P, Q, and G can be
 * public and common to a group of users. They might be known from application
 * context. As such, they are optional but P and Q must either both appear or
 * both be absent. If all of P, Q, seed, and pgenCounter are present,
 * implementations are not required to check if they are consistent and are
 * free to use either P and Q or seed and pgenCounter. All parameters are
 * encoded as base64 [MIME] values.
 *
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *
 * Schema Definition:
 *
 * <element name="DSAKeyValue" type="ds:DSAKeyValueType"/>
 * <complexType name="DSAKeyValueType">
 *   <sequence>
 *     <sequence minOccurs="0">
 *        <element name="P" type="ds:CryptoBinary"/>
 *        <element name="Q" type="ds:CryptoBinary"/>
 *     </sequence>
 *     <element name="G" type="ds:CryptoBinary" minOccurs="0"/>
 *     <element name="Y" type="ds:CryptoBinary"/>
 *     <element name="J" type="ds:CryptoBinary" minOccurs="0"/>
 *     <sequence minOccurs="0">
 *       <element name="Seed" type="ds:CryptoBinary"/>
 *       <element name="PgenCounter" type="ds:CryptoBinary"/>
 *     </sequence>
 *   </sequence>
 * </complexType>
 *
 * DTD Definition:
 *
 *  <!ELEMENT DSAKeyValue ((P, Q)?, G?, Y, J?, (Seed, PgenCounter)?) >
 *  <!ELEMENT P (#PCDATA) >
 *  <!ELEMENT Q (#PCDATA) >
 *  <!ELEMENT G (#PCDATA) >
 *  <!ELEMENT Y (#PCDATA) >
 *  <!ELEMENT J (#PCDATA) >
 *  <!ELEMENT Seed (#PCDATA) >
 *  <!ELEMENT PgenCounter (#PCDATA) >
 *
 * ============================================================================
 *
 * To support reading/writing private keys an X element added (before Y).
 * todo: The current implementation does not support Seed and PgenCounter!
 * by this the P, Q and G are *required*!
 *
 *************************************************************************/
static int              xmlSecNssKeyDataDsaInitialize   (xmlSecKeyDataPtr data);
static int              xmlSecNssKeyDataDsaDuplicate    (xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecNssKeyDataDsaFinalize     (xmlSecKeyDataPtr data);
static int              xmlSecNssKeyDataDsaXmlRead      (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecNssKeyDataDsaXmlWrite     (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecNssKeyDataDsaGenerate     (xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                         xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecNssKeyDataDsaGetType     (xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecNssKeyDataDsaGetSize     (xmlSecKeyDataPtr data);
static void              xmlSecNssKeyDataDsaDebugDump   (xmlSecKeyDataPtr data,
                                                         FILE* output);
static void              xmlSecNssKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data,
                                                         FILE* output);


static xmlSecKeyDataPtr xmlSecNssKeyDataDsaRead         (xmlSecKeyDataId id,
                                                         xmlSecKeyValueDsaPtr dsaValue);
static int              xmlSecNssKeyDataDsaWrite        (xmlSecKeyDataId id,
                                                         xmlSecKeyDataPtr data,
                                                         xmlSecKeyValueDsaPtr dsaValue,
                                                         int writePrivateKey);

static xmlSecKeyDataKlass xmlSecNssKeyDataDsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssPKIKeyDataSize,

    /* data */
    xmlSecNameDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefDSAKeyValue,              /* const xmlChar* href; */
    xmlSecNodeDSAKeyValue,              /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecNssKeyDataDsaInitialize,      /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssKeyDataDsaDuplicate,       /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssKeyDataDsaFinalize,        /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecNssKeyDataDsaGenerate,        /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecNssKeyDataDsaGetType,         /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssKeyDataDsaGetSize,         /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecNssKeyDataDsaXmlRead,         /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssKeyDataDsaXmlWrite,        /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssKeyDataDsaDebugDump,       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssKeyDataDsaDebugXmlDump,    /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/**
 * xmlSecNssKeyDataDsaGetKlass:
 *
 * The DSA key data klass.
 *
 * Returns: pointer to DSA key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataDsaGetKlass(void) {
    return(&xmlSecNssKeyDataDsaKlass);
}


static int
xmlSecNssKeyDataDsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId), -1);

    return(xmlSecNssPKIKeyDataInitialize(data));
}

static int
xmlSecNssKeyDataDsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecNssKeyDataDsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecNssKeyDataDsaId), -1);

    return(xmlSecNssPKIKeyDataDuplicate(dst, src));
}

static void
xmlSecNssKeyDataDsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId));

    xmlSecNssPKIKeyDataFinalize(data);
}

static int
xmlSecNssKeyDataDsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                           xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecNssKeyDataDsaRead));
}

static int
xmlSecNssKeyDataDsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                                xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataDsaId, -1);
    return(xmlSecKeyDataDsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecNssKeyDataDsaWrite));
}

static int
xmlSecNssKeyDataDsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    PQGParams    *pqgParams = NULL;
    PQGVerify    *pqgVerify = NULL;
    SECStatus     rv;
    SECStatus     res;
    PK11SlotInfo *slot = NULL;
    SECKEYPrivateKey *privkey = NULL;
    SECKEYPublicKey  *pubkey = NULL;
    int               ret = -1;
    int               index;
    unsigned int      uIndex;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    index = PQG_PBITS_TO_INDEX(sizeBits);
    if(index < 0) {
        xmlSecNssError2("PQG_PBITS_TO_INDEX", xmlSecKeyDataGetName(data),
            "size=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }
    XMLSEC_SAFE_CAST_INT_TO_UINT(index, uIndex, goto done, xmlSecKeyDataGetName(data));

    rv = PK11_PQG_ParamGen(uIndex, &pqgParams, &pqgVerify);
    if (rv != SECSuccess) {
        xmlSecNssError2("PK11_PQG_ParamGen", xmlSecKeyDataGetName(data),
            "size=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }

    rv = PK11_PQG_VerifyParams(pqgParams, pqgVerify, &res);
    if (rv != SECSuccess || res != SECSuccess) {
        xmlSecNssError2("PK11_PQG_VerifyParams", xmlSecKeyDataGetName(data),
            "size=" XMLSEC_SIZE_FMT, sizeBits);
        goto done;
    }

    slot = PK11_GetBestSlot(CKM_DSA_KEY_PAIR_GEN, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", xmlSecKeyDataGetName(data));
        goto done;
    }

    rv = PK11_Authenticate(slot, PR_TRUE, NULL /* default pwd callback */);
    if (rv != SECSuccess) {
        xmlSecNssError2("PK11_Authenticate", xmlSecKeyDataGetName(data),
                        "token=%s", xmlSecErrorsSafeString(PK11_GetTokenName(slot)));
        goto done;
    }

    privkey = PK11_GenerateKeyPair(slot, CKM_DSA_KEY_PAIR_GEN, pqgParams,
                                   &pubkey, PR_FALSE, PR_TRUE, NULL);

    if((privkey == NULL) || (pubkey == NULL)) {
        xmlSecNssError("PK11_GenerateKeyPair", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecNssPKIKeyDataAdoptKey(data, privkey, pubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssPKIKeyDataAdoptKey",
                            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = 0;

done:
    if (slot != NULL) {
        PK11_FreeSlot(slot);
    }
    if (pqgParams != NULL) {
        PK11_PQG_DestroyParams(pqgParams);
    }
    if (pqgVerify != NULL) {
        PK11_PQG_DestroyVerify(pqgVerify);
    }
    if (ret == 0) {
        return (0);
    }
    if (pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (privkey != NULL) {
        SECKEY_DestroyPrivateKey(privkey);
    }
    return(-1);
}

static xmlSecKeyDataType
xmlSecNssKeyDataDsaGetType(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(SECKEY_GetPublicKeyType(ctx->pubkey) == dsaKey, xmlSecKeyDataTypeUnknown);

    if (ctx->privkey != NULL) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    } else {
        return(xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecNssKeyDataDsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId), 0);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    xmlSecAssert2(ctx->pubkey != NULL, 0);
    xmlSecAssert2(SECKEY_GetPublicKeyType(ctx->pubkey) == dsaKey, 0);

    return(8 * SECKEY_PublicKeyStrength(ctx->pubkey));
}

static void
xmlSecNssKeyDataDsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== dsa key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecNssKeyDataDsaGetSize(data));
}

static void
xmlSecNssKeyDataDsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<DSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecNssKeyDataDsaGetSize(data));
}

static xmlSecKeyDataPtr
xmlSecNssKeyDataDsaRead(xmlSecKeyDataId id, xmlSecKeyValueDsaPtr dsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    PK11SlotInfo *slot = NULL;
    CK_OBJECT_HANDLE handle;
    SECKEYPublicKey *pubkey=NULL;
    PRArenaPool *arena = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataDsaId, NULL);
    xmlSecAssert2(dsaValue != NULL, NULL);

    slot = PK11_GetBestSlot(CKM_DSA, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if(arena == NULL) {
        xmlSecNssError("PORT_NewArena", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    pubkey = (SECKEYPublicKey *)PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
    if(pubkey == NULL) {
        xmlSecNssError2("PORT_ArenaZAlloc", xmlSecKeyDataKlassGetName(id),
            "size=" XMLSEC_SIZE_T_FMT, sizeof(SECKEYPublicKey));
        goto done;
    }
    pubkey->arena = arena;
    pubkey->u.dsa.params.arena = arena;
    pubkey->keyType = dsaKey;
    arena = NULL; /* owned by pubkey */

    /*** p ***/
    ret = xmlSecNssGetBigNumValue(&(dsaValue->p), pubkey->arena, &(pubkey->u.dsa.params.prime));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssGetBigNumValue(p)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** q ***/
    ret = xmlSecNssGetBigNumValue(&(dsaValue->q), pubkey->arena, &(pubkey->u.dsa.params.subPrime));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssGetBigNumValue(q)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** g ***/
    ret = xmlSecNssGetBigNumValue(&(dsaValue->g), pubkey->arena, &(pubkey->u.dsa.params.base));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssGetBigNumValue(g)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* next is X (priv key). NSS does not support it, we just ignore it */

    /*** y ***/
    ret = xmlSecNssGetBigNumValue(&(dsaValue->y), pubkey->arena, &(pubkey->u.dsa.publicValue));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssGetBigNumValue(y)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* todo: add support for J , seed, pgencounter */

    /* create key */
    handle = PK11_ImportPublicKey(slot, pubkey, PR_FALSE);
    if(handle == CK_INVALID_HANDLE) {
        xmlSecNssError("PK11_ImportPublicKey",
                       xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    ret = xmlSecNssPKIKeyDataAdoptKey(data, NULL, pubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssPKIKeyDataAdoptKey",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    pubkey = NULL; /* owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    if (slot != NULL) {
        PK11_FreeSlot(slot);
    }
    if (arena != NULL) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    if (pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecNssKeyDataDsaWrite(xmlSecKeyDataId id, xmlSecKeyDataPtr data,
                         xmlSecKeyValueDsaPtr dsaValue,
                         int writePrivateKey ATTRIBUTE_UNUSED) {
    xmlSecNssPKIKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataDsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDsaId), -1);
    xmlSecAssert2(dsaValue != NULL, -1);
    UNREFERENCED_PARAMETER(writePrivateKey);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(SECKEY_GetPublicKeyType(ctx->pubkey) == dsaKey, -1);

    /*** p ***/
    ret = xmlSecNssSetBigNumValue(&(ctx->pubkey->u.dsa.params.prime), &(dsaValue->p));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssNodeSetBigNumValue(p)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /*** q ***/
    ret = xmlSecNssSetBigNumValue(&(ctx->pubkey->u.dsa.params.subPrime), &(dsaValue->q));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssNodeSetBigNumValue(q)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /*** g ***/
    ret = xmlSecNssSetBigNumValue(&(ctx->pubkey->u.dsa.params.base), &(dsaValue->g));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssNodeSetBigNumValue(g)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /*** x: not supported in NSS ***/

    /*** y ***/
    ret = xmlSecNssSetBigNumValue(&(ctx->pubkey->u.dsa.publicValue), &(dsaValue->y));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssNodeSetBigNumValue(y)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /* done */
    return(0);
}

#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
/**************************************************************************
 *
 * <dsig:RSAKeyValue> processing
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue
 * The RSAKeyValue Element
 *
 * RSA key values have two fields: Modulus and Exponent.
 *
 * <RSAKeyValue>
 *   <Modulus>xA7SEU+e0yQH5rm9kbCDN9o3aPIo7HbP7tX6WOocLZAtNfyxSZDU16ksL6W
 *     jubafOqNEpcwR3RdFsT7bCqnXPBe5ELh5u4VEy19MzxkXRgrMvavzyBpVRgBUwUlV
 *        5foK5hhmbktQhyNdy/6LpQRhDUDsTvK+g9Ucj47es9AQJ3U=
 *   </Modulus>
 *   <Exponent>AQAB</Exponent>
 * </RSAKeyValue>
 *
 * Arbitrary-length integers (e.g. "bignums" such as RSA moduli) are
 * represented in XML as octet strings as defined by the ds:CryptoBinary type.
 *
 * Schema Definition:
 *
 * <element name="RSAKeyValue" type="ds:RSAKeyValueType"/>
 * <complexType name="RSAKeyValueType">
 *   <sequence>
 *     <element name="Modulus" type="ds:CryptoBinary"/>
 *     <element name="Exponent" type="ds:CryptoBinary"/>
 *   </sequence>
 * </complexType>
 *
 * DTD Definition:
 *
 * <!ELEMENT RSAKeyValue (Modulus, Exponent) >
 * <!ELEMENT Modulus (#PCDATA) >
 * <!ELEMENT Exponent (#PCDATA) >
 *
 * ============================================================================
 *
 * To support reading/writing private keys an PrivateExponent element is added
 * to the end
 *
 *************************************************************************/

static int              xmlSecNssKeyDataRsaInitialize   (xmlSecKeyDataPtr data);
static int              xmlSecNssKeyDataRsaDuplicate    (xmlSecKeyDataPtr dst,
                                                         xmlSecKeyDataPtr src);
static void             xmlSecNssKeyDataRsaFinalize     (xmlSecKeyDataPtr data);
static int              xmlSecNssKeyDataRsaXmlRead      (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecNssKeyDataRsaXmlWrite     (xmlSecKeyDataId id,
                                                         xmlSecKeyPtr key,
                                                         xmlNodePtr node,
                                                         xmlSecKeyInfoCtxPtr keyInfoCtx);
static int              xmlSecNssKeyDataRsaGenerate     (xmlSecKeyDataPtr data,
                                                         xmlSecSize sizeBits,
                                                        xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecNssKeyDataRsaGetType     (xmlSecKeyDataPtr data);
static xmlSecSize        xmlSecNssKeyDataRsaGetSize     (xmlSecKeyDataPtr data);
static void             xmlSecNssKeyDataRsaDebugDump    (xmlSecKeyDataPtr data,
                                                         FILE* output);
static void             xmlSecNssKeyDataRsaDebugXmlDump (xmlSecKeyDataPtr data,
                                                         FILE* output);

static xmlSecKeyDataPtr xmlSecNssKeyDataRsaRead         (xmlSecKeyDataId id,
                                                         xmlSecKeyValueRsaPtr rsaValue);
static int              xmlSecNssKeyDataRsaWrite        (xmlSecKeyDataId id,
                                                         xmlSecKeyDataPtr data,
                                                         xmlSecKeyValueRsaPtr rsaValue,
                                                         int writePrivateKey);

static xmlSecKeyDataKlass xmlSecNssKeyDataRsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssPKIKeyDataSize,

    /* data */
    xmlSecNameRSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                        /* xmlSecKeyDataUsage usage; */
    xmlSecHrefRSAKeyValue,              /* const xmlChar* href; */
    xmlSecNodeRSAKeyValue,              /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                       /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecNssKeyDataRsaInitialize,      /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssKeyDataRsaDuplicate,       /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssKeyDataRsaFinalize,        /* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecNssKeyDataRsaGenerate,        /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecNssKeyDataRsaGetType,         /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssKeyDataRsaGetSize,         /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                               /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecNssKeyDataRsaXmlRead,         /* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssKeyDataRsaXmlWrite,        /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                               /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                               /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssKeyDataRsaDebugDump,       /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssKeyDataRsaDebugXmlDump,    /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                               /* void* reserved0; */
    NULL,                               /* void* reserved1; */
};

/**
 * xmlSecNssKeyDataRsaGetKlass:
 *
 * The RSA key data klass.
 *
 * Returns: pointer to RSA key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataRsaGetKlass(void) {
    return(&xmlSecNssKeyDataRsaKlass);
}

static int
xmlSecNssKeyDataRsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId), -1);

    return(xmlSecNssPKIKeyDataInitialize(data));
}

static int
xmlSecNssKeyDataRsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecNssKeyDataRsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecNssKeyDataRsaId), -1);

    return(xmlSecNssPKIKeyDataDuplicate(dst, src));
}

static void
xmlSecNssKeyDataRsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId));

    xmlSecNssPKIKeyDataFinalize(data);
}

static int
xmlSecNssKeyDataRsaXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
                           xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlRead(id, key, node, keyInfoCtx,
        xmlSecNssKeyDataRsaRead));
}

static int
xmlSecNssKeyDataRsaXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
                            xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecNssKeyDataRsaId, -1);
    return(xmlSecKeyDataRsaXmlWrite(id, key, node, keyInfoCtx,
        xmlSecBase64GetDefaultLineSize(), 1, /* add line breaks */
        xmlSecNssKeyDataRsaWrite));
}

static xmlSecKeyDataType
xmlSecNssKeyDataRsaGetType(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(ctx->pubkey == NULL || SECKEY_GetPublicKeyType(ctx->pubkey) == rsaKey, xmlSecKeyDataTypeUnknown);

    if (ctx->privkey != NULL) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    } else {
        return(xmlSecKeyDataTypePublic);
    }

    return(xmlSecKeyDataTypeUnknown);
}

static xmlSecSize
xmlSecNssKeyDataRsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId), 0);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    xmlSecAssert2(ctx->pubkey != NULL, 0);
    xmlSecAssert2(SECKEY_GetPublicKeyType(ctx->pubkey) == rsaKey, 0);

    return(8 * SECKEY_PublicKeyStrength(ctx->pubkey));
}

static void
xmlSecNssKeyDataRsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== rsa key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecNssKeyDataRsaGetSize(data));
}

static void
xmlSecNssKeyDataRsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<RSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecNssKeyDataRsaGetSize(data));
}

static xmlSecKeyDataPtr
xmlSecNssKeyDataRsaRead(xmlSecKeyDataId id, xmlSecKeyValueRsaPtr rsaValue) {
    xmlSecKeyDataPtr data = NULL;
    xmlSecKeyDataPtr res = NULL;
    PK11SlotInfo *slot = NULL;
    SECKEYPublicKey *pubkey=NULL;
    PRArenaPool *arena = NULL;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataRsaId, NULL);
    xmlSecAssert2(rsaValue != NULL, NULL);

    slot = PK11_GetBestSlot(CKM_RSA_PKCS, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if(arena == NULL) {
        xmlSecNssError("PORT_NewArena", xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    pubkey = (SECKEYPublicKey *)PORT_ArenaZAlloc(arena,
                                                 sizeof(SECKEYPublicKey));
    if(pubkey == NULL) {
        xmlSecNssError("PORT_ArenaZAlloc", xmlSecKeyDataKlassGetName(id));
        goto done;
    }
    pubkey->arena = arena;
    pubkey->keyType = rsaKey;
    arena = NULL; /* owned by pubkey */

    /*** Modulus ***/
    ret = xmlSecNssGetBigNumValue(&(rsaValue->modulus), pubkey->arena, &(pubkey->u.rsa.modulus));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssGetBigNumValue(Modulus)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /*** Exponent ***/
    ret = xmlSecNssGetBigNumValue(&(rsaValue->publicExponent), pubkey->arena, &(pubkey->u.rsa.publicExponent));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssGetBigNumValue(Exponent)",
                            xmlSecKeyDataKlassGetName(id));
        goto done;
    }

    /* next is PrivateExponent (priv key). NSS does not support it, we just ignore it */

    /* create key */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate",
                            xmlSecKeyDataKlassGetName(id));
        ret = -1;
        goto done;
    }

    ret = xmlSecNssPKIKeyDataAdoptKey(data, NULL, pubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssPKIKeyDataAdoptKey",
                            xmlSecKeyDataKlassGetName(id));
        xmlSecKeyDataDestroy(data);
        goto done;
    }
    pubkey = NULL; /* owned by data now */

    /* success */
    res = data;
    data = NULL;

done:
    if (slot != 0) {
        PK11_FreeSlot(slot);
    }
    if(arena != NULL) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    if (pubkey != 0) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (data != 0) {
        xmlSecKeyDataDestroy(data);
    }
    return(res);
}

static int
xmlSecNssKeyDataRsaWrite(xmlSecKeyDataId id,xmlSecKeyDataPtr data,
                         xmlSecKeyValueRsaPtr rsaValue,
                         int writePrivateKey ATTRIBUTE_UNUSED) {
    xmlSecNssPKIKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(id == xmlSecNssKeyDataRsaId, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId), -1);
    xmlSecAssert2(rsaValue != NULL, -1);
    UNREFERENCED_PARAMETER(writePrivateKey);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2(SECKEY_GetPublicKeyType(ctx->pubkey) == rsaKey, -1);

    /*** Modulus ***/
    ret = xmlSecNssSetBigNumValue(&(ctx->pubkey->u.rsa.modulus), &(rsaValue->modulus));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssNodeSetBigNumValue(Modulus)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /*** Exponent ***/
    ret = xmlSecNssSetBigNumValue(&(ctx->pubkey->u.rsa.publicExponent), &(rsaValue->publicExponent));
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssNodeSetBigNumValue(Exponent)",
                            xmlSecKeyDataKlassGetName(id));
        return(-1);
    }

    /* next is PrivateExponent node: not supported in NSS */

    return(0);
}

static int
xmlSecNssKeyDataRsaGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    PK11RSAGenParams  params;
    PK11SlotInfo *slot = NULL;
    SECKEYPrivateKey *privkey = NULL;
    SECKEYPublicKey  *pubkey = NULL;
    SECStatus rv;
    int  ret = -1;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataRsaId), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    XMLSEC_SAFE_CAST_SIZE_TO_INT(sizeBits, params.keySizeInBits, return(-1), xmlSecKeyDataGetName(data));
    params.pe = 65537;

    slot = PK11_GetBestSlot(CKM_RSA_PKCS_KEY_PAIR_GEN, NULL);
    if(slot == NULL) {
        xmlSecNssError("PK11_GetBestSlot", xmlSecKeyDataGetName(data));
        goto done;
    }

    rv = PK11_Authenticate(slot, PR_TRUE, NULL /* default pwd callback */);
    if (rv != SECSuccess) {
        xmlSecNssError2("PK11_Authenticate", xmlSecKeyDataGetName(data),
                        "token=%s", xmlSecErrorsSafeString(PK11_GetTokenName(slot)));
        goto done;
    }

    privkey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &params,
                                   &pubkey, PR_FALSE, PR_TRUE, NULL);
    if(privkey == NULL || pubkey == NULL) {
        xmlSecNssError("PK11_GenerateKeyPair", xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = xmlSecNssPKIKeyDataAdoptKey(data, privkey, pubkey);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssPKIKeyDataAdoptKey",
                            xmlSecKeyDataGetName(data));
        goto done;
    }

    ret = 0;

done:
    if (slot != NULL) {
        PK11_FreeSlot(slot);
    }
    if (ret == 0) {
        return (0);
    }

    if (pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (privkey != NULL) {
        SECKEY_DestroyPrivateKey(privkey);
    }
    return(-1);
}

#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_ECDSA
static int xmlSecNssKeyDataEcdsaInitialize(xmlSecKeyDataPtr data);
static int xmlSecNssKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst,
                                          xmlSecKeyDataPtr src);
static void xmlSecNssKeyDataEcdsaFinalize(xmlSecKeyDataPtr data);

static xmlSecKeyDataType xmlSecNssKeyDataEcdsaGetType(xmlSecKeyDataPtr data);
static xmlSecSize xmlSecNssKeyDataEcdsaGetSize(xmlSecKeyDataPtr data);
static void xmlSecNssKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data,
                                           FILE* output);
static void xmlSecNssKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data,
                                              FILE* output);

static xmlSecKeyDataKlass xmlSecNssKeyDataEcdsaKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssPKIKeyDataSize,

    /* data */
    xmlSecNameECDSAKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml,
                                                /* xmlSecKeyDataUsage usage; */
    xmlSecHrefECDSAKeyValue,                    /* const xmlChar* href; */
    xmlSecNodeECDSAKeyValue,                    /* const xmlChar* dataNodeName; */
    xmlSecDSigNs,                               /* const xmlChar* dataNodeNs; */

    /* constructors/destructor */
    xmlSecNssKeyDataEcdsaInitialize,            /* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssKeyDataEcdsaDuplicate,             /* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssKeyDataEcdsaFinalize,              /* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,                                       /* xmlSecKeyDataGenerateMethod generate; */

    /* get info */
    xmlSecNssKeyDataEcdsaGetType,               /* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssKeyDataEcdsaGetSize,               /* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,                                       /* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    NULL,                                       /* xmlSecKeyDataXmlReadMethod xmlRead; */
    NULL,                                       /* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,                                       /* xmlSecKeyDataBinReadMethod binRead; */
    NULL,                                       /* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssKeyDataEcdsaDebugDump,             /* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssKeyDataEcdsaDebugXmlDump,          /* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssKeyDataEcdsaGetKlass:
 *
 * The ECDSA key data klass.
 *
 * Returns: pointer to ECDSA key data klass.
 */
xmlSecKeyDataId
xmlSecNssKeyDataEcdsaGetKlass(void) {
    return(&xmlSecNssKeyDataEcdsaKlass);
}

static int
xmlSecNssKeyDataEcdsaInitialize(xmlSecKeyDataPtr data) {
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataEcdsaId), -1);

    return(xmlSecNssPKIKeyDataInitialize(data));
}

static int
xmlSecNssKeyDataEcdsaDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecAssert2(xmlSecKeyDataCheckId(dst, xmlSecNssKeyDataEcdsaId), -1);
    xmlSecAssert2(xmlSecKeyDataCheckId(src, xmlSecNssKeyDataEcdsaId), -1);

    return(xmlSecNssPKIKeyDataDuplicate(dst, src));
}

static void
xmlSecNssKeyDataEcdsaFinalize(xmlSecKeyDataPtr data) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataEcdsaId));

    xmlSecNssPKIKeyDataFinalize(data);
}

static xmlSecKeyDataType
xmlSecNssKeyDataEcdsaGetType(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataEcdsaId), xmlSecKeyDataTypeUnknown);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, xmlSecKeyDataTypeUnknown);
    xmlSecAssert2(ctx->pubkey == NULL || SECKEY_GetPublicKeyType(ctx->pubkey) == ecKey, xmlSecKeyDataTypeUnknown);

    if (ctx->privkey != NULL) {
        return(xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic);
    } else {
        return(xmlSecKeyDataTypePublic);
    }
}

static xmlSecSize
xmlSecNssKeyDataEcdsaGetSize(xmlSecKeyDataPtr data) {
    xmlSecNssPKIKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataEcdsaId), 0);

    ctx = xmlSecNssPKIKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, 0);
    xmlSecAssert2(ctx->pubkey != NULL, 0);
    xmlSecAssert2(SECKEY_GetPublicKeyType(ctx->pubkey) == ecKey, 0);

    return(SECKEY_SignatureLen(ctx->pubkey));
}

static void
xmlSecNssKeyDataEcdsaDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "=== ecdsa key: size = " XMLSEC_SIZE_FMT "\n",
        xmlSecNssKeyDataEcdsaGetSize(data));
}

static void
xmlSecNssKeyDataEcdsaDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataEcdsaId));
    xmlSecAssert(output != NULL);

    fprintf(output, "<ECDSAKeyValue size=\"" XMLSEC_SIZE_FMT "\" />\n",
        xmlSecNssKeyDataEcdsaGetSize(data));
}
#endif /* XMLSEC_NO_ECDSA */
