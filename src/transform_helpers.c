/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Helper functions for transform implementations.
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */

#include "globals.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpointer.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/base64.h>
#include <xmlsec/io.h>
#include <xmlsec/membuf.h>
#include <xmlsec/parser.h>
#include <xmlsec/errors.h>

#include "cast_helpers.h"
#include "transform_helpers.h"



/*********************************************************************
 *
 * Helper transform functions
 *
 ********************************************************************/

#ifndef XMLSEC_NO_CONCATKDF

#define XMLSEC_TRANSFORM_CONCATKDF_DEFAULT_BUF_SIZE       64

/* reads optional attribute and decodes it as bit string (https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF):
 *
 * 1/ The bitstring is divided into octets using big-endian encoding. If the length of the bitstring is not
 *    a multiple of 8 then add padding bits (value 0) as necessary to the last octet to make it a multiple of 8.
 * 2/ Prepend one octet to the octets string from step 1. This octet shall identify (in a big-endian representation)
 *    the number of padding bits added to the last octet in step 1.
 * 3/ Encode the octet string resulting from step 2 as a hexBinary string.
 *
 * Example: the bitstring 11011, which is 5 bits long, gets 3 additional padding bits to become the bitstring
 * 11011000 (or D8 in hex). This bitstring is then prepended with one octet identifying the number of padding bits
 * to become the octet string (in hex) 03D8, which then finally is encoded as a hexBinary string value of "03D8".
 *
 * While any bit string can be used with ConcatKDF, it is RECOMMENDED to keep byte aligned for greatest interoperability.
 *
 * TODO: only bit aligned bit strings are supported (https://github.com/lsh123/xmlsec/issues/514)
 */
static int
xmlSecTransformConcatKdfParamsReadsBitsAttr(xmlSecBufferPtr buf, xmlNodePtr node, const xmlChar* attrName) {
    xmlChar * attrValue;
    xmlSecByte* data;
    xmlSecSize size;
    int ret;

    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(node!= NULL, -1);
    xmlSecAssert2(attrName != NULL, -1);

    attrValue = xmlGetProp(node, attrName);
    if(attrValue == NULL) {
        xmlSecBufferEmpty(buf);
        return(0);
    }

    ret = xmlSecBufferHexRead(buf, attrValue);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferHexRead", NULL);
        xmlFree(attrValue);
        return(-1);
    }
    xmlFree(attrValue);

    data = xmlSecBufferGetData(buf);
    size = xmlSecBufferGetSize(buf);
    if((data == NULL) || (size <= 0)) {
        /* xmlSecInvalidSizeDataError("size", size, "at least one byte is expected", NULL); */
        /* ignore empty buffer */
        return(0);
    }

    /* only byte aligned bit strings are supported */
    if(data[0] != 0) {
        xmlSecInvalidDataError("First bit string byte should be 0 (only byte aligned bit strings are supported)", NULL);
        return (-1);
    }

    ret = xmlSecBufferRemoveHead(buf, 1);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferHexRead", NULL);
        return(-1);
    }

    /* done */
    return(0);
}


int
xmlSecTransformConcatKdfParamsInitialize(xmlSecTransformConcatKdfParamsPtr params) {
    int ret;

    xmlSecAssert2(params != NULL, -1);
    memset(params, 0, sizeof(*params));

    ret = xmlSecBufferInitialize(&(params->bufAlgorithmID), XMLSEC_TRANSFORM_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufAlgorithmID)", NULL);
        xmlSecTransformConcatKdfParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufPartyUInfo), XMLSEC_TRANSFORM_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufPartyUInfo)", NULL);
        xmlSecTransformConcatKdfParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufPartyVInfo), XMLSEC_TRANSFORM_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufPartyVInfo)", NULL);
        xmlSecTransformConcatKdfParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufSuppPubInfo), XMLSEC_TRANSFORM_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufSuppPubInfo)", NULL);
        xmlSecTransformConcatKdfParamsFinalize(params);
        return(-1);
    }
    ret = xmlSecBufferInitialize(&(params->bufSuppPrivInfo), XMLSEC_TRANSFORM_CONCATKDF_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufSuppPrivInfo)", NULL);
        xmlSecTransformConcatKdfParamsFinalize(params);
        return(-1);
    }

    /* done */
    return(0);
}

void
xmlSecTransformConcatKdfParamsFinalize(xmlSecTransformConcatKdfParamsPtr params) {
    xmlSecAssert(params != NULL);

    if(params->digestMethod != NULL) {
        xmlFree(params->digestMethod);
    }
    xmlSecBufferFinalize(&(params->bufAlgorithmID));
    xmlSecBufferFinalize(&(params->bufPartyUInfo));
    xmlSecBufferFinalize(&(params->bufPartyVInfo));
    xmlSecBufferFinalize(&(params->bufSuppPubInfo));
    xmlSecBufferFinalize(&(params->bufSuppPrivInfo));

    memset(params, 0, sizeof(*params));
}

int
xmlSecTransformConcatKdfParamsRead(xmlSecTransformConcatKdfParamsPtr params, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first (and only) node is required DigestMethod */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeDigestMethod, xmlSecDSigNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeDigestMethod, NULL);
        return(-1);
    }
    params->digestMethod = xmlGetProp(cur, xmlSecAttrAlgorithm);
    if(params->digestMethod == NULL) {
        xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm, NULL, "empty");
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* if we have something else then it's an error */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* now read all attributes */
    ret = xmlSecTransformConcatKdfParamsReadsBitsAttr(&(params->bufAlgorithmID), node, xmlSecNodeConcatKDFAttrAlgorithmID);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsReadsBitsAttr(AlgorithmID)", NULL);
        return(-1);
    }
    ret = xmlSecTransformConcatKdfParamsReadsBitsAttr(&(params->bufPartyUInfo), node, xmlSecNodeConcatKDFAttrPartyUInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsReadsBitsAttr(PartyUInfo)", NULL);
        return(-1);
    }
    ret = xmlSecTransformConcatKdfParamsReadsBitsAttr(&(params->bufPartyVInfo), node, xmlSecNodeConcatKDFAttrPartyVInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsReadsBitsAttr(PartyVInfo)", NULL);
        return(-1);
    }
    ret = xmlSecTransformConcatKdfParamsReadsBitsAttr(&(params->bufSuppPubInfo), node, xmlSecNodeConcatKDFAttrSuppPubInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsReadsBitsAttr(SuppPubInfo)", NULL);
        return(-1);
    }
    ret = xmlSecTransformConcatKdfParamsReadsBitsAttr(&(params->bufSuppPrivInfo), node, xmlSecNodeConcatKDFAttrSuppPrivInfo);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformConcatKdfParamsReadsBitsAttr(ASuppPrivInfo)", NULL);
        return(-1);
    }

    /* done! */
    return(0);
}

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
 * For this format, FixedInfo is a bit string equal to the following concatenation:
 *
 * AlgorithmID || PartyUInfo || PartyVInfo {|| SuppPubInfo }{|| SuppPrivInfo }
 */
int
xmlSecTransformConcatKdfParamsGetFixedInfo(xmlSecTransformConcatKdfParamsPtr params, xmlSecBufferPtr bufFixedInfo) {
    xmlSecSize size;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(bufFixedInfo != NULL, -1);

    size = xmlSecBufferGetSize(&(params->bufAlgorithmID)) +
        xmlSecBufferGetSize(&(params->bufPartyUInfo)) +
        xmlSecBufferGetSize(&(params->bufPartyVInfo)) +
        xmlSecBufferGetSize(&(params->bufSuppPubInfo)) +
        xmlSecBufferGetSize(&(params->bufSuppPrivInfo));

    ret = xmlSecBufferSetMaxSize(bufFixedInfo, size);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferSetMaxSize", NULL,
            "size=" XMLSEC_SIZE_FMT, size);
        return (-1);
    }

    ret = xmlSecBufferSetData(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufAlgorithmID)),
        xmlSecBufferGetSize(&(params->bufAlgorithmID)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferSetData(AlgorithmID)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufPartyUInfo)),
        xmlSecBufferGetSize(&(params->bufPartyUInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(PartyUInfo)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufPartyVInfo)),
        xmlSecBufferGetSize(&(params->bufPartyVInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(PartyVInfo)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufSuppPubInfo)),
        xmlSecBufferGetSize(&(params->bufSuppPubInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(SuppPubInfo)", NULL);
        return (-1);
    }
    ret = xmlSecBufferAppend(bufFixedInfo,
        xmlSecBufferGetData(&(params->bufSuppPrivInfo)),
        xmlSecBufferGetSize(&(params->bufSuppPrivInfo)));
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferAppend(SuppPrivInfo)", NULL);
        return (-1);
    }

    /* done */
    return(0);
}

#endif /* XMLSEC_NO_CONCATKDF */

/**************************** Common Key Agreement Params ********************************/
int
xmlSecTransformKeyAgreementParamsInitialize(xmlSecTransformKeyAgreementParamsPtr params) {
    int ret;

    xmlSecAssert2(params != NULL, -1);

    memset(params, 0, sizeof(*params));

    ret = xmlSecKeyInfoCtxInitialize(&(params->kdfKeyInfoCtx), NULL); /* no keys manager needed */
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxInitialize", NULL);
        xmlSecTransformKeyAgreementParamsFinalize(params);
        return(-1);
    }

    /* done */
    return(0);
}

void
xmlSecTransformKeyAgreementParamsFinalize(xmlSecTransformKeyAgreementParamsPtr params) {
    xmlSecAssert(params != NULL);


    xmlSecKeyInfoCtxFinalize(&(params->kdfKeyInfoCtx));

    if(params->kdfTransform != NULL) {
        xmlSecTransformDestroy(params->kdfTransform);
    }
    if(params->memBufTransform != NULL) {
        xmlSecTransformDestroy(params->memBufTransform);
    }
    if(params->keyOriginator != NULL) {
        xmlSecKeyDestroy(params->keyOriginator);
    }
    if(params->keyRecipient != NULL) {
        xmlSecKeyDestroy(params->keyRecipient);
    }

    /* cleanup */
    memset(params, 0, sizeof(*params));
}

static xmlSecKeyPtr
xmlSecTransformKeyAgreementReadKey(xmlSecKeyDataType keyType, xmlNodePtr node,
    xmlSecTransformPtr kaTransform, xmlSecTransformCtxPtr transformCtx)
{
    xmlSecKeyInfoCtx keyInfoCtx;
    xmlSecKeysMngrPtr keysMngr;
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr res = NULL;
    int ret;

    xmlSecAssert2(node != NULL, NULL);
    xmlSecAssert2(kaTransform != NULL, NULL);
    xmlSecAssert2(transformCtx != NULL, NULL);
    xmlSecAssert2(transformCtx->parentKeyInfoCtx != NULL, NULL);

    keysMngr = transformCtx->parentKeyInfoCtx->keysMngr;
    xmlSecAssert2(keysMngr != NULL, NULL);
    xmlSecAssert2(keysMngr->getKey != NULL, NULL);

     /* create keyinfo ctx */
    ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, keysMngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxInitialize(recipient)", xmlSecNodeGetName(node));
        return(NULL);
    }
    ret = xmlSecKeyInfoCtxCopyUserPref(&keyInfoCtx, transformCtx->parentKeyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxCopyUserPref(recipient)", xmlSecNodeGetName(node));
        goto done;
    }
    keyInfoCtx.mode = xmlSecKeyInfoModeRead;

    ret = xmlSecTransformSetKeyReq(kaTransform, &(keyInfoCtx.keyReq));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKeyReq(originator)", xmlSecNodeGetName(node));
        goto done;
    }
    keyInfoCtx.keyReq.keyType = keyType;

    key = (keysMngr->getKey)(node, &keyInfoCtx);
    if(key == NULL) {
        xmlSecOtherError(XMLSEC_ERRORS_R_KEY_NOT_FOUND, xmlSecNodeGetName(node), "key not found");
        goto done;
    }
    if(!xmlSecKeyMatch(key, NULL, &(keyInfoCtx.keyReq))) {
        xmlSecOtherError(XMLSEC_ERRORS_R_KEY_NOT_FOUND, xmlSecNodeGetName(node), "key doesn't match requiremetns");
        goto done;
    }

    /* success */
    res = key;
    key = NULL;

done:
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
    return(res);
}


static int
xmlSecTransformKeyAgreementWriteKey(xmlSecKeyPtr key, xmlNodePtr node,
    xmlSecTransformPtr kaTransform, xmlSecTransformCtxPtr transformCtx)
{
    xmlSecKeyInfoCtx keyInfoCtx;
    int ret;
    int res = -1;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(kaTransform != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(transformCtx->parentKeyInfoCtx != NULL, -1);


     /* create keyinfo ctx */
    ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, NULL);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxInitialize(recipient)", xmlSecNodeGetName(node));
        return(-1);
    }
    ret = xmlSecKeyInfoCtxCopyUserPref(&keyInfoCtx, transformCtx->parentKeyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoCtxCopyUserPref(recipient)", xmlSecNodeGetName(node));
        goto done;
    }
    keyInfoCtx.mode = xmlSecKeyInfoModeWrite;
    keyInfoCtx.keyReq.keyType = xmlSecKeyDataTypePublic; /* write public keys only */

    /* write node */
    ret = xmlSecKeyInfoNodeWrite(node, key, &(keyInfoCtx));
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyInfoNodeWrite", NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
    return(res);
}


int
xmlSecTransformKeyAgreementParamsRead(xmlSecTransformKeyAgreementParamsPtr params, xmlNodePtr node,
    xmlSecTransformPtr kaTransform, xmlSecTransformCtxPtr transformCtx)
{
    xmlNodePtr cur;
    xmlSecKeyDataType originatorKeyType, recipientKeyType;
    int ret;
    int res = -1;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(params->kdfTransform == NULL, -1);
    xmlSecAssert2(params->memBufTransform == NULL, -1);
    xmlSecAssert2(params->keyOriginator == NULL, -1);
    xmlSecAssert2(params->keyRecipient == NULL, -1);
    xmlSecAssert2(kaTransform != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(transformCtx->parentKeyInfoCtx != NULL, -1);

    if(transformCtx->parentKeyInfoCtx->operation == xmlSecTransformOperationEncrypt) {
        /* we are encrypting on originator side which needs private key */
        originatorKeyType = xmlSecKeyDataTypePrivate;
        recipientKeyType = xmlSecKeyDataTypePublic;
    } else {
        /* we are decrypting on recipient side which needs private key */
        originatorKeyType = xmlSecKeyDataTypePublic;
        recipientKeyType = xmlSecKeyDataTypePrivate;
    }

    /* first is required KeyDerivationMethod */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeKeyDerivationMethod, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeKeyDerivationMethod, NULL);
        goto done;
    }
    params->kdfTransform = xmlSecTransformNodeRead(cur, xmlSecTransformUsageKeyDerivationMethod, transformCtx);
    if(params->kdfTransform  == NULL) {
        xmlSecInternalError("xmlSecTransformNodeRead", xmlSecNodeGetName(node));
        goto done;
    }
    ret = xmlSecTransformSetKeyReq(params->kdfTransform, &(params->kdfKeyInfoCtx.keyReq));
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformSetKeyReq", xmlSecNodeGetName(node));
        goto done;
    }

    /* next node is required OriginatorKeyInfo (we need public key)*/
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeOriginatorKeyInfo, xmlSecEncNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeOriginatorKeyInfo, NULL);
        goto done;
    }
    params->keyOriginator = xmlSecTransformKeyAgreementReadKey(originatorKeyType, cur, kaTransform, transformCtx);
    if(params->keyOriginator  == NULL) {
        xmlSecInternalError("xmlSecTransformKeyAgreementReadKey(OriginatorKeyInfo)", xmlSecNodeGetName(node));
        goto done;
    }

    /* next node is required RecipientKeyInfo (we need private key)*/
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRecipientKeyInfo, xmlSecEncNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRecipientKeyInfo, NULL);
        goto done;
    }
    params->keyRecipient = xmlSecTransformKeyAgreementReadKey(recipientKeyType, cur, kaTransform, transformCtx);
    if(params->keyRecipient  == NULL) {
        xmlSecInternalError("xmlSecTransformKeyAgreementReadKey(RecipientKeyInfo)", xmlSecNodeGetName(node));
        goto done;
    }

    /* if there is something left than it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        goto done;
    }

    /* append MemBuf transform after kdf transform to collect results */
    params->memBufTransform = xmlSecTransformCreate(xmlSecTransformMemBufId);
    if(!xmlSecTransformIsValid(params->memBufTransform )) {
        xmlSecInternalError("xmlSecTransformCreate(MemBufId)",  xmlSecNodeGetName(node));
        goto done;
    }
    params->kdfTransform->next = params->memBufTransform;
    params->memBufTransform->prev = params->kdfTransform;

    /* success */
    res = 0;

done:
    return(res);
}

int
xmlSecTransformKeyAgreementParamsWrite(xmlSecTransformKeyAgreementParamsPtr params, xmlNodePtr node,
    xmlSecTransformPtr kaTransform, xmlSecTransformCtxPtr transformCtx)
{
    xmlNodePtr cur;
    int ret;
    int res = -1;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(kaTransform != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);
    xmlSecAssert2(transformCtx->parentKeyInfoCtx != NULL, -1);

    /* first is required KeyDerivationMethod */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeKeyDerivationMethod, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeKeyDerivationMethod, NULL);
        goto done;
    }
    /* do nothing for KeyDerivationMethod for now */

    /* next node is required OriginatorKeyInfo (we need public key)*/
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeOriginatorKeyInfo, xmlSecEncNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeOriginatorKeyInfo, NULL);
        goto done;
    }
    if(params->keyOriginator != NULL) {
        ret = xmlSecTransformKeyAgreementWriteKey(params->keyOriginator, cur, kaTransform, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformKeyAgreementWriteKey(OriginatorKeyInfo)", xmlSecNodeGetName(node));
            goto done;
        }
    }

    /* next node is required RecipientKeyInfo (we need private key)*/
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeRecipientKeyInfo, xmlSecEncNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeRecipientKeyInfo, NULL);
        goto done;
    }
    if(params->keyRecipient != NULL) {
        ret = xmlSecTransformKeyAgreementWriteKey(params->keyRecipient, cur, kaTransform, transformCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecTransformKeyAgreementWriteKey(RecipientKeyInfo)", xmlSecNodeGetName(node));
            goto done;
        }
    }

    /* if there is something left than it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        goto done;
    }

    /* success */
    res = 0;

done:
    return(res);
}

#ifndef XMLSEC_NO_HMAC

/* min output for hmac transform in bits */
static xmlSecSize g_xmlsec_transform_hmac_min_output_bits_size = 80;

/**
 * xmlSecTransformHmacGetMinOutputBitsSize:
 *
 * Gets the minimum size in bits for HMAC output.
 *
 * Returns: the min HMAC output size in bits.
 */
xmlSecSize
xmlSecTransformHmacGetMinOutputBitsSize(void) {
    return(g_xmlsec_transform_hmac_min_output_bits_size);
}

/**
 * xmlSecTransformHmacSetMinOutputBitsSize:
 * @val: the new min hmac output size in bits.
 *
 * Sets the min HMAC output size in bits. Low value for min output size
 * might create a security vulnerability and is not recommended.
 */
void xmlSecTransformHmacSetMinOutputBitsSize(xmlSecSize val) {
    g_xmlsec_transform_hmac_min_output_bits_size = val;
}

/*
 * HMAC (http://www.w3.org/TR/xmldsig-core/#sec-HMAC):
 *
 * The HMAC algorithm (RFC2104 [HMAC]) takes the truncation length in bits
 * as a parameter; if the parameter is not specified then all the bits of the
 * hash are output. An example of an HMAC SignatureMethod element:
 * <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
 *   <HMACOutputLength>128</HMACOutputLength>
 * </SignatureMethod>
 *
 * Schema Definition:
 *
 * <simpleType name="HMACOutputLengthType">
 *   <restriction base="integer"/>
 * </simpleType>
 *
 * DTD:
 *
 * <!ELEMENT HMACOutputLength (#PCDATA)>
 */
int
xmlSecTransformHmacReadOutputBitsSize(xmlNodePtr node, xmlSecSize defaultSize, xmlSecSize* res) {
    xmlNodePtr cur;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if ((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeHMACOutputLength, xmlSecDSigNs)) {
        xmlSecSize minSize;
        int ret;

        ret = xmlSecGetNodeContentAsSize(cur, defaultSize, res);
        if (ret != 0) {
            xmlSecInternalError("xmlSecGetNodeContentAsSize(HMACOutputLength)", NULL);
            return(-1);
        }

        /* Ensure that HMAC length is greater than min specified.
           Otherwise, an attacker can set this length to 0 or very
           small value
        */
        minSize = xmlSecTransformHmacGetMinOutputBitsSize();
        if ((*res) < minSize) {
            xmlSecInvalidNodeContentError3(cur, NULL,
                "HMAC output length=" XMLSEC_SIZE_FMT "; HMAC min output length=" XMLSEC_SIZE_FMT,
                (*res), minSize);
            return(-1);
        }

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* no other nodes expected */
    if (cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }
    return(0);
}

static xmlSecByte g_hmac_last_byte_masks[] = { 0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

int
xmlSecTransformHmacWriteOutput(const xmlSecByte * hmac, xmlSecSize hmacSizeInBits, xmlSecSize hmacMaxSizeInBytes, xmlSecBufferPtr out)
{
    xmlSecSize hmacSize;
    xmlSecByte lastByteMask;
    xmlSecByte* outData;
    int ret;

    xmlSecAssert2(hmac != NULL, -1);
    xmlSecAssert2(hmacSizeInBits > 0, -1);
    xmlSecAssert2(out != NULL, -1);

    hmacSize = (hmacSizeInBits + 7) / 8;
    xmlSecAssert2(hmacSize > 0, -1);
    xmlSecAssert2(hmacSize <= hmacMaxSizeInBytes, -1);

    ret = xmlSecBufferAppend(out, hmac, hmacSize);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecBufferAppend", NULL, "size=" XMLSEC_SIZE_FMT, hmacSize);
        return(-1);
    }

    /* fix up last byte */
    lastByteMask = g_hmac_last_byte_masks[hmacSizeInBits % 8];
    outData = xmlSecBufferGetData(out);
    if(outData == NULL) {
        xmlSecInternalError("xmlSecBufferGetData", NULL);
        return(-1);
    }
    outData[hmacSize - 1] &= lastByteMask;

    /* success */
    return(0);
}

/* Returns 1 for match, 0 for no match, <0 for errors. */
int
xmlSecTransformHmacVerify(const xmlSecByte* data, xmlSecSize dataSize,
    const xmlSecByte * hmac, xmlSecSize hmacSizeInBits, xmlSecSize hmacMaxSizeInBytes)
{
    xmlSecSize hmacSize;
    xmlSecByte lastByteMask;

    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(hmac != NULL, -1);
    xmlSecAssert2(hmacSizeInBits > 0, -1);

    hmacSize = (hmacSizeInBits + 7) / 8;
    xmlSecAssert2(hmacSize > 0, -1);
    xmlSecAssert2(hmacSize <= hmacMaxSizeInBytes, -1);

    if(dataSize != hmacSize){
        xmlSecInvalidSizeError("HMAC digest", dataSize, hmacSize, NULL);
        return(0);
    }

    /* we check the last byte separately */
    lastByteMask = g_hmac_last_byte_masks[hmacSizeInBits % 8];
    if((hmac[hmacSize - 1] & lastByteMask) != (data[dataSize - 1] & lastByteMask)) {
        xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH, NULL, "data and digest do not match (last byte)");
        return(0);
    }

    /* now check the rest of the digest */
    if((hmacSize > 1) && (memcmp(hmac, data, hmacSize - 1) != 0)) {
        xmlSecOtherError(XMLSEC_ERRORS_R_DATA_NOT_MATCH, NULL, "data and digest do not match");
        return(0);
    }

    /* success */
    return(1);
}

#endif /* XMLSEC_NO_HMAC */


/********************************** ML-DSA *******************************/
#ifndef XMLSEC_NO_MLDSA


/**
 * THIS IS EXPERIMENTAL AND NON-STANDARD
 *
 * <SignatureMethod Algorithm="http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-dsa-44">
 *   <mldsa:MLDSAContextString>base64 encoded context string</mldsa:MLDSAContextString>
 * </SignatureMethod>
 */
int
xmlSecTransformMLDSAReadContextString(xmlNodePtr node, xmlSecBufferPtr res) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if ((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeMLDSAContextString, xmlSecMLDSANs)) {

        ret = xmlSecBufferBase64NodeContentRead(res, cur);
        if (ret != 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(MLDSAContextString)", NULL);
            return(-1);
        }

        /* ensure length is not exceeded */
        if (xmlSecBufferGetSize(res) > XMLSEC_MLDSA_MAX_SIZE) {
            xmlSecInvalidNodeContentError3(cur, NULL,
                "MLDSA context string length=" XMLSEC_SIZE_FMT " exceeds max expected length =" XMLSEC_SIZE_FMT,
                xmlSecBufferGetSize(res), XMLSEC_MLDSA_MAX_SIZE);
            return(-1);
        }

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* no other nodes expected */
    if (cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }
    return(0);
}
#endif /* XMLSEC_NO_MLDSA */


/********************************** SLH-DSA *******************************/
#ifndef XMLSEC_NO_SLHDSA

/**
 * THIS IS EXPERIMENTAL AND NON-STANDARD
 *
 * <SignatureMethod Algorithm="http://www.aleksey.com/xmlsec/2025/12/xmldsig-more#ml-dsa-44">
 *   <slhdsa:SLHDSAContextString>base64 encoded context string</slhdsa:SLHDSAContextString>
 * </SignatureMethod>
 */
int
xmlSecTransformSLHDSAReadContextString(xmlNodePtr node, xmlSecBufferPtr res) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if ((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeSLHDSAContextString, xmlSecSLHDSANs)) {

        ret = xmlSecBufferBase64NodeContentRead(res, cur);
        if (ret != 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(SLHDSAContextString)", NULL);
            return(-1);
        }

        /* ensure length is not exceeded */
        if (xmlSecBufferGetSize(res) > XMLSEC_SLHDSA_MAX_SIZE) {
            xmlSecInvalidNodeContentError3(cur, NULL,
                "SLHDSA context string length=" XMLSEC_SIZE_FMT " exceeds max expected length =" XMLSEC_SIZE_FMT,
                xmlSecBufferGetSize(res), XMLSEC_SLHDSA_MAX_SIZE);
            return(-1);
        }

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* no other nodes expected */
    if (cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }
    return(0);
}
#endif /* XMLSEC_NO_SLHDSA */


/********************************** EdDSA *******************************/
#ifndef XMLSEC_NO_EDDSA

/**
 * THIS IS EXPERIMENTAL AND NON-STANDARD
 *
 * <SignatureMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519ctx">
 *   <eddsa:EdDSAContextString>base64 encoded context string</eddsa:EdDSAContextString>
 * </SignatureMethod>
 */
int
xmlSecTransformEdDSAReadContextString(xmlNodePtr node, xmlSecBufferPtr res) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(res != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if ((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeEdDSAContextString, xmlSecEdDSANs)) {

        ret = xmlSecBufferBase64NodeContentRead(res, cur);
        if (ret != 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(EdDSAContextString)", NULL);
            return(-1);
        }

        /* ensure length is not exceeded */
        if (xmlSecBufferGetSize(res) > XMLSEC_EDDSA_MAX_SIZE) {
            xmlSecInvalidNodeContentError3(cur, NULL,
                "EdDSA context string length=" XMLSEC_SIZE_FMT " exceeds max expected length =" XMLSEC_SIZE_FMT,
                xmlSecBufferGetSize(res), XMLSEC_EDDSA_MAX_SIZE);
            return(-1);
        }

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* no other nodes expected */
    if (cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }
    return(0);
}
#endif /* XMLSEC_NO_EDDSA */


/********************************** PBKDF2 *******************************/

#ifndef XMLSEC_NO_PBKDF2

#define XMLSEC_TRANSFORM_PBKDF2_DEFAULT_BUF_SIZE       64

int
xmlSecTransformPbkdf2ParamsInitialize(xmlSecTransformPbkdf2ParamsPtr params) {
    int ret;

    xmlSecAssert2(params != NULL, -1);
    memset(params, 0, sizeof(*params));

    ret = xmlSecBufferInitialize(&(params->salt), XMLSEC_TRANSFORM_PBKDF2_DEFAULT_BUF_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(bufAlgorithmID)", NULL);
        xmlSecTransformPbkdf2ParamsFinalize(params);
        return(-1);
    }

    /* done */
    return(0);
}

void
xmlSecTransformPbkdf2ParamsFinalize(xmlSecTransformPbkdf2ParamsPtr params) {
    xmlSecAssert(params != NULL);

    if(params->prfAlgorithmHref != NULL) {
        xmlFree(params->prfAlgorithmHref);
    }
    xmlSecBufferFinalize(&(params->salt));

    memset(params, 0, sizeof(*params));
}

/*
 * https://www.w3.org/TR/xmlenc-core1/#sec-PBKDF2
 *
 *  <element name="PBKDF2-params" type="xenc11:PBKDF2ParameterType"/>
 *  <complexType name="PBKDF2ParameterType">
 *      <sequence>
 *          <element name="Salt">
 *              <complexType>
 *                  <choice>
 *                      <element name="Specified" type="base64Binary"/>
 *                      <element name="OtherSource" type="xenc11:AlgorithmIdentifierType"/>
 *                  </choice>
 *              </complexType>
 *          </element>
 *          <element name="IterationCount" type="positiveInteger"/>
 *          <element name="KeyLength" type="positiveInteger"/>
 *          <element name="PRF" type="xenc11:PRFAlgorithmIdentifierType"/>
 *      </sequence>
 *  </complexType>
 *
 *  <complexType name="AlgorithmIdentifierType">
 *      <sequence>
 *          <element name="Parameters" type="anyType" minOccurs="0"/>
 *      </sequence>
 *      <attribute name="Algorithm" type="anyURI"/>
 *  </complexType>
 *
 *  <complexType name="PRFAlgorithmIdentifierType">
 *      <complexContent>
 *          <restriction base="xenc11:AlgorithmIdentifierType">
 *              <attribute name="Algorithm" type="anyURI"/>
 *          </restriction>
 *      </complexContent>
 * </complexType>
 *
 * - Salt / OtherSource is not supported
 * - PRF algorithm parameters are not supported
*/
static int
xmlSecTransformPbkdf2ParamsReadSalt(xmlSecTransformPbkdf2ParamsPtr params, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first and onluy node is required Salt / Specified (Salt / OtherSource is not supported)*/
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2SaltSpecified, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2SaltSpecified, NULL);
        return(-1);
    }
    ret = xmlSecBufferBase64NodeContentRead(&(params->salt), cur);
    if((ret < 0) || (xmlSecBufferGetSize(&(params->salt)) <= 0)) {
        xmlSecInternalError("xmlSecBufferBase64NodeContentRead(Salt)", NULL);
        return(-1);
    }

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* done! */
    return(0);
}

int
xmlSecTransformPbkdf2ParamsRead(xmlSecTransformPbkdf2ParamsPtr params, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(params->prfAlgorithmHref == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* first node is required Salt */
    cur  = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2Salt, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2Salt, NULL);
        return(-1);
    }
    ret = xmlSecTransformPbkdf2ParamsReadSalt(params, cur);
    if(ret < 0) {
        xmlSecInternalError("xmlSecTransformPbkdf2ParamsReadSalt", NULL);
        return(-1);
    }

    /* next is required IterationCount */
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2IterationCount, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2IterationCount, NULL);
        return(-1);
    }
    ret = xmlSecGetNodeContentAsSize(cur, 0, &(params->iterationCount));
    if((ret < 0) || (params->iterationCount <= 0)) {
        xmlSecInternalError("xmlSecGetNodeContentAsSize(iterationCount)", NULL);
        return(-1);
    }

    /* next is required KeyLength */
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2KeyLength, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2KeyLength, NULL);
        return(-1);
    }
    ret = xmlSecGetNodeContentAsSize(cur, 0, &(params->keyLength));
    if((ret < 0) || (params->keyLength <= 0)) {
        xmlSecInternalError("xmlSecGetNodeContentAsSize(keyLength)", NULL);
        return(-1);
    }

    /* next is required PRF */
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodePbkdf2PRF, xmlSecEnc11Ns))) {
        xmlSecInvalidNodeError(cur, xmlSecNodePbkdf2PRF, NULL);
        return(-1);
    }
    params->prfAlgorithmHref = xmlGetProp(cur, xmlSecAttrAlgorithm);
    if(params->prfAlgorithmHref == NULL) {
        xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm, NULL, "empty");
        return(-1);
    }
    /* PRF algorithm parameters are not supported */

    /* if we have something else then it's an error */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur,  NULL);
        return(-1);
    }

    /* done! */
    return(0);
}

#endif /* XMLSEC_NO_CONCATKDF */


#ifndef XMLSEC_NO_HKDF

/**************************************************************************
 *
 * HKDF params
 *
 **************************************************************************/
int
xmlSecTransformHkdfParamsInitialize(xmlSecTransformHkdfParamsPtr params) {
    int ret;

    xmlSecAssert2(params != NULL, -1);

    memset(params, 0, sizeof(xmlSecTransformHkdfParams));

    ret = xmlSecBufferInitialize(&(params->salt), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(salt)", NULL);
        return(-1);
    }

    ret = xmlSecBufferInitialize(&(params->info), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize(info)", NULL);
        xmlSecBufferFinalize(&(params->salt));
        return(-1);
    }

    return(0);
}

void
xmlSecTransformHkdfParamsFinalize(xmlSecTransformHkdfParamsPtr params) {
    xmlSecAssert(params != NULL);

    if(params->prfAlgorithmHref != NULL) {
        xmlFree(params->prfAlgorithmHref);
    }
    xmlSecBufferFinalize(&(params->salt));
    xmlSecBufferFinalize(&(params->info));
    memset(params, 0, sizeof(xmlSecTransformHkdfParams));
}

int
xmlSecTransformHkdfParamsRead(xmlSecTransformHkdfParamsPtr params, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(params != NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    /* iterate over child nodes */
    cur = xmlSecGetNextElementNode(node->children);

    /* required: PRF */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeHkdfPRF, xmlSecXmldsig2021MoreNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeHkdfPRF, NULL);
        return(-1);
    }
    params->prfAlgorithmHref = xmlGetProp(cur, xmlSecAttrAlgorithm);
    if(params->prfAlgorithmHref == NULL) {
        xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm, NULL, "empty");
        return(-1);
    }
    cur = xmlSecGetNextElementNode(cur->next);

    /* optional: Salt */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeHkdfSalt, xmlSecXmldsig2021MoreNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(params->salt), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(salt)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* optional: Info */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeHkdfInfo, xmlSecXmldsig2021MoreNs))) {
        ret = xmlSecBufferBase64NodeContentRead(&(params->info), cur);
        if(ret < 0) {
            xmlSecInternalError("xmlSecBufferBase64NodeContentRead(info)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* optional: KeyLength */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeHkdfKeyLength, xmlSecXmldsig2021MoreNs))) {
        ret = xmlSecGetNodeContentAsSize(cur, 1, &(params->keyLength));
        if(ret < 0) {
            xmlSecInternalError("xmlSecGetNodeContentAsSize(KeyLength)", NULL);
            return(-1);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* no more nodes allowed */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    return(0);
}

#endif /* XMLSEC_NO_HKDF */


/********************************** ChaCha20 *******************************/
#ifndef XMLSEC_NO_CHACHA20


/*
 * https://www.w3.org/TR/draft-eastlake-rfc9231bis-xmlsec-uris-06/#sec-ChaCha20
 *
 * <xenc:EncryptionMethod Algorithm="...#chacha20">
 *   <dsig-more:Nonce>0123456789abcdef01234567</dsig-more:Nonce>
 *   <dsig-more:Counter>fedcba09</dsig-more:Counter>
 * </xenc:EncryptionMethod>
 */

 /* IV: 16 bytes: 4 byte counter + 12 byte nonce */
int
xmlSecTransformChaCha20ParamsRead(xmlNodePtr node, xmlSecByte *iv, xmlSecSize ivSize, xmlSecSize *ivSizeOut, int *noncePresent) {
    xmlSecBuffer buf;
    xmlSecByte* bufData;
    xmlSecSize bufSize;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_CHACHA20_IV_SIZE, -1);
    xmlSecAssert2(ivSizeOut != NULL, -1);
    xmlSecAssert2(noncePresent != NULL, -1);

    /* prep output params */
    memset(iv, 0, XMLSEC_CHACHA20_IV_SIZE);
    (*ivSizeOut) = 0;
    (*noncePresent) = 0;

    ret = xmlSecBufferInitialize(&buf, XMLSEC_CHACHA20_IV_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGetNodeContentAsHex(Nonce)", NULL);
        return(-1);
    }

    /* first optional Nonce node (12 bytes, hex-encoded) */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs))) {
        ret = xmlSecGetNodeContentAsHex(cur, &buf);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGetNodeContentAsHex(Nonce)", NULL);
            xmlSecBufferFinalize(&buf);
            return(-1);
        }

        bufData = xmlSecBufferGetData(&buf);
        bufSize = xmlSecBufferGetSize(&buf);
        if((bufData == NULL) || (bufSize != XMLSEC_CHACHA20_NONCE_SIZE)) {
            xmlSecInvalidSizeDataError("Nonce", bufSize, "12 bytes", NULL);
            xmlSecBufferFinalize(&buf);
            return(-1);
        }
        memcpy(iv + XMLSEC_CHACHA20_COUNTER_SIZE, bufData, bufSize);
        xmlSecBufferEmpty(&buf);
        (*noncePresent) = 1;

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* second is required Counter node (4 bytes, hex-encoded) */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeChaCha20Counter, xmlSecXmldsig2021MoreNs))) {
        xmlSecInvalidNodeError(cur, xmlSecNodeChaCha20Counter, NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    ret = xmlSecGetNodeContentAsHex(cur, &buf);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGetNodeContentAsHex(Counter)", NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    bufData = xmlSecBufferGetData(&buf);
    bufSize = xmlSecBufferGetSize(&buf);
    if((bufData == NULL) || (bufSize != XMLSEC_CHACHA20_COUNTER_SIZE)) {
        xmlSecInvalidSizeDataError("Counter", bufSize, "4 bytes", NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }
    memcpy(iv, bufData, bufSize);
    xmlSecBufferEmpty(&buf);

    cur = xmlSecGetNextElementNode(cur->next);

    /* nothing else is expected */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* done */
    (*ivSizeOut) = XMLSEC_CHACHA20_IV_SIZE;
    xmlSecBufferFinalize(&buf);
    return(0);
}

int
xmlSecTransformChaCha20ParamsWrite(xmlNodePtr node, const xmlSecByte *iv, xmlSecSize ivSize) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_CHACHA20_IV_SIZE, -1);

    /* add nonce node if needed */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs))) {
        xmlNodePtr nonceNode;

         /* add nonce node */
        if (cur != NULL) {
            nonceNode = xmlSecAddPrevSibling(cur, xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs);
        } else {
            nonceNode = xmlSecAddChild(node, xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs);
        }
        if(nonceNode == NULL) {
            xmlSecInternalError2("xmlSecAddChild or xmlSecAddPrevSibling", NULL, "node=%s", xmlSecErrorsSafeString(xmlSecNodeChaCha20Nonce));
            return(-1);
        }
        cur = nonceNode;
    }
    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs), -1);

    /* set nonce content */
    ret = xmlSecSetNodeContentAsHex(cur, iv + XMLSEC_CHACHA20_COUNTER_SIZE, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecSetNodeContentAsHex(Nonce)", NULL);
        return(-1);
    }

    /* add counter node if needed */
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Counter, xmlSecXmldsig2021MoreNs))) {
        xmlNodePtr counterNode;

         /* add counter node */
        if (cur != NULL) {
            counterNode = xmlSecAddPrevSibling(cur, xmlSecNodeChaCha20Counter, xmlSecXmldsig2021MoreNs);
        } else {
            counterNode = xmlSecAddChild(node, xmlSecNodeChaCha20Counter, xmlSecXmldsig2021MoreNs);
        }
        if(counterNode == NULL) {
            xmlSecInternalError2("xmlSecAddChild or xmlSecAddPrevSibling", NULL, "node=%s", xmlSecErrorsSafeString(xmlSecNodeChaCha20Counter));
            return(-1);
        }
        cur = counterNode;
    }
    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Counter, xmlSecXmldsig2021MoreNs), -1);

    /* set counter content */
    ret = xmlSecSetNodeContentAsHex(cur, iv, XMLSEC_CHACHA20_COUNTER_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecSetNodeContentAsHex(Counter)", NULL);
        return(-1);
    }

    /* nothing else is expected */
    cur = xmlSecGetNextElementNode(cur->next);
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

/*
 * https://www.w3.org/TR/draft-eastlake-rfc9231bis-xmlsec-uris-06/#sec-ChaCha20-Poly1305
 *
 * <xenc:EncryptionMethod Algorithm="...#chacha20poly1305">
 *   <dsig-more:Nonce>0123456789abcdef01234567</dsig-more:Nonce>
 *   <dsig-more:AAD>optional additional authenticated data</dsig-more:AAD>
 * </xenc:EncryptionMethod>
 */

int
xmlSecTransformChaCha20Poly1305ParamsRead(xmlNodePtr node, xmlSecBufferPtr aad,
                                          xmlSecByte *iv, xmlSecSize ivSize,
                                          xmlSecSize *ivSizeOut, int *noncePresent) {
    xmlSecBuffer buf;
    xmlSecByte* bufData;
    xmlSecSize bufSize;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(aad != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_CHACHA20_NONCE_SIZE, -1);
    xmlSecAssert2(ivSizeOut != NULL, -1);
    xmlSecAssert2(noncePresent != NULL, -1);

    /* prep output params */
    memset(iv, 0, XMLSEC_CHACHA20_NONCE_SIZE);
    xmlSecBufferEmpty(aad);
    (*ivSizeOut) = 0;
    (*noncePresent) = 0;

    ret = xmlSecBufferInitialize(&buf, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecGetNodeContentAsHex(Nonce)", NULL);
        return(-1);
    }

    /* first optional Nonce node (12 bytes, hex-encoded) */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs))) {
        ret = xmlSecGetNodeContentAsHex(cur, &buf);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGetNodeContentAsHex(Nonce)", NULL);
            xmlSecBufferFinalize(&buf);
            return(-1);
        }
        bufData = xmlSecBufferGetData(&buf);
        bufSize = xmlSecBufferGetSize(&buf);
        if((bufData == NULL) || (bufSize != XMLSEC_CHACHA20_NONCE_SIZE)) {
            xmlSecInvalidSizeDataError("Nonce", bufSize, "12 bytes", NULL);
            xmlSecBufferFinalize(&buf);
            return(-1);
        }
        memcpy(iv, bufData, bufSize);
        xmlSecBufferEmpty(&buf);
        (*noncePresent) = 1;

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* second optional AAD node (plain text string) */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeChaCha20Poly1305AAD, xmlSecXmldsig2021MoreNs))) {
        xmlChar* aadContent = xmlNodeGetContent(cur);
        if(aadContent != NULL) {
            int aadContentLen = xmlStrlen(aadContent);

            if(aadContentLen > 0) {
                ret = xmlSecBufferSetData(aad, aadContent, (xmlSecSize)aadContentLen);
                if(ret < 0) {
                    xmlSecInternalError("xmlSecBufferSetData(aad)", NULL);
                    xmlFree(aadContent);
                    xmlSecBufferFinalize(&buf);
                    return(-1);
                }
            }
            xmlFree(aadContent);
        }

        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* nothing else is expected */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        xmlSecBufferFinalize(&buf);
        return(-1);
    }

    /* done */
    (*ivSizeOut) = XMLSEC_CHACHA20_NONCE_SIZE;
    xmlSecBufferFinalize(&buf);
    return(0);
}

int
xmlSecTransformChaCha20Poly1305ParamsWrite(xmlNodePtr node, const xmlSecByte *iv, xmlSecSize ivSize) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(iv != NULL, -1);
    xmlSecAssert2(ivSize >= XMLSEC_CHACHA20_NONCE_SIZE, -1);

    /* add nonce node if needed */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur == NULL) || (!xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs))) {
        xmlNodePtr nonceNode;

         /* add nonce node */
        if (cur != NULL) {
            nonceNode = xmlSecAddPrevSibling(cur, xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs);
        } else {
            nonceNode = xmlSecAddChild(node, xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs);
        }
        if(nonceNode == NULL) {
            xmlSecInternalError2("xmlSecAddChild or xmlSecAddPrevSibling", NULL, "node=%s", xmlSecErrorsSafeString(xmlSecNodeChaCha20Nonce));
            return(-1);
        }
        cur = nonceNode;
    }
    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(xmlSecCheckNodeName(cur,  xmlSecNodeChaCha20Nonce, xmlSecXmldsig2021MoreNs), -1);

    /* set nonce content */
    ret = xmlSecSetNodeContentAsHex(cur, iv, XMLSEC_CHACHA20_NONCE_SIZE);
    if(ret < 0) {
        xmlSecInternalError("xmlSecSetNodeContentAsHex(Nonce)", NULL);
        return(-1);
    }

    /* next is optional AAD node (plain text string) */
    cur = xmlSecGetNextElementNode(cur->next);
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeChaCha20Poly1305AAD, xmlSecXmldsig2021MoreNs))) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* nothing else is expected */
    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, NULL);
        return(-1);
    }

    /* done */
    return(0);
}

#endif /* XMLSEC_NO_CHACHA20 */


#ifndef XMLSEC_NO_RSA
#ifndef XMLSEC_NO_RSA_OAEP
int
xmlSecTransformRsaOaepParamsInitialize(xmlSecTransformRsaOaepParamsPtr oaepParams) {
    int ret;

    xmlSecAssert2(oaepParams != NULL, -1);

    memset(oaepParams, 0, sizeof(xmlSecTransformRsaOaepParams));

    ret = xmlSecBufferInitialize(&(oaepParams->oaepParams), 0);
    if(ret < 0) {
        xmlSecInternalError("xmlSecBufferInitialize", NULL);
        return(-1);
    }

    return(0);
}

void
xmlSecTransformRsaOaepParamsFinalize(xmlSecTransformRsaOaepParamsPtr oaepParams) {
    xmlSecAssert(oaepParams != NULL);

    xmlSecBufferFinalize(&(oaepParams->oaepParams));
    if(oaepParams->digestAlgorithm != NULL) {
        xmlFree(oaepParams->digestAlgorithm);
    }
    if(oaepParams->mgf1DigestAlgorithm != NULL) {
        xmlFree(oaepParams->mgf1DigestAlgorithm);
    }
    memset(oaepParams, 0, sizeof(xmlSecTransformRsaOaepParams));
}

/*
 * See https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP
 *  <EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
 *      <OAEPparams>9lWu3Q==</OAEPparams>
 *      <xenc11:MGF Algorithm="http://www.w3.org/2001/04/xmlenc#MGF1withSHA1" />
 *      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
 *  <EncryptionMethod>
*/
int
xmlSecTransformRsaOaepParamsRead(xmlSecTransformRsaOaepParamsPtr oaepParams, xmlNodePtr node) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(oaepParams != NULL, -1);
    xmlSecAssert2(xmlSecBufferGetSize(&(oaepParams->oaepParams)) == 0, -1);
    xmlSecAssert2(oaepParams->digestAlgorithm == NULL, -1);
    xmlSecAssert2(oaepParams->mgf1DigestAlgorithm == NULL, -1);
    xmlSecAssert2(node != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    while (cur != NULL) {
        if (xmlSecCheckNodeName(cur, xmlSecNodeRsaOAEPparams, xmlSecEncNs)) {
            ret = xmlSecBufferBase64NodeContentRead(&(oaepParams->oaepParams), cur);
            if (ret < 0) {
                xmlSecInternalError("xmlSecBufferBase64NodeContentRead", NULL);
                return(-1);
            }
        } else if (xmlSecCheckNodeName(cur, xmlSecNodeDigestMethod, xmlSecDSigNs)) {
            /* digest algorithm attribute is required */
            oaepParams->digestAlgorithm = xmlGetProp(cur, xmlSecAttrAlgorithm);
            if (oaepParams->digestAlgorithm == NULL) {
                xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm, NULL, "empty");
                return(-1);
            }
        } else if (xmlSecCheckNodeName(cur, xmlSecNodeRsaMGF, xmlSecEnc11Ns)) {
            /* mgf1 digest algorithm attribute is required */
            oaepParams->mgf1DigestAlgorithm = xmlGetProp(cur, xmlSecAttrAlgorithm);
            if (oaepParams->mgf1DigestAlgorithm == NULL) {
                xmlSecInvalidNodeAttributeError(cur, xmlSecAttrAlgorithm, NULL, "empty");
                return(-1);
            }
        } else {
            /* node not recognized */
            xmlSecUnexpectedNodeError(cur, NULL);
                return(-1);
        }

        /* next node */
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* done */
    return(0);
}
#endif /* XMLSEC_NO_RSA_OAEP */
#endif /* XMLSEC_NO_RSA */

