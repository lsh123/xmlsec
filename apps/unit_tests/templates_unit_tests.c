/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * templates unit tests
 *
 * See Copyright for the status of this software.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

/* must be included before any other xmlsec header */
#include "xmlsec_unit_tests.h"
#include <xmlsec/templates.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/strings.h>

/*
 * Use core transforms (from the base library, no crypto backend needed):
 *   xmlSecTransformInclC14NId  => xmlSecTransformInclC14NGetKlass()   (c14n)
 *   xmlSecTransformEnvelopedId => xmlSecTransformEnvelopedGetKlass()  (enveloped-signature)
 *   xmlSecTransformExclC14NId  => xmlSecTransformExclC14NGetKlass()   (exc-c14n)
 *
 * Template functions only dereference ->href from the klass struct; they do not
 * require the crypto backend to be initialized.
 */

/*************************************************************************
 * xmlSecTmplSignatureCreate
 *************************************************************************/
static void
test_xmlSecTmplSignatureCreate_structure(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr signedInfoNode;
    xmlNodePtr signValueNode;
    xmlNodePtr c14nNode;
    xmlNodePtr signMethodNode;
    xmlChar*   algo;

    testStart("xmlSecTmplSignatureCreate: creates correct node structure");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    /* root must be <dsig:Signature> */
    if(!xmlSecCheckNodeName(signNode, xmlSecNodeSignature, xmlSecDSigNs)) {
        testLog("Error: root is not <dsig:Signature>\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    /* required: <dsig:SignedInfo> */
    signedInfoNode = xmlSecFindChild(signNode, xmlSecNodeSignedInfo, xmlSecDSigNs);
    if(signedInfoNode == NULL) {
        testLog("Error: <dsig:SignedInfo> not found\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    /* required: <dsig:SignatureValue> */
    signValueNode = xmlSecFindChild(signNode, xmlSecNodeSignatureValue, xmlSecDSigNs);
    if(signValueNode == NULL) {
        testLog("Error: <dsig:SignatureValue> not found\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    /* required: <dsig:CanonicalizationMethod Algorithm="..."> inside SignedInfo */
    c14nNode = xmlSecFindChild(signedInfoNode, xmlSecNodeCanonicalizationMethod, xmlSecDSigNs);
    if(c14nNode == NULL) {
        testLog("Error: <dsig:CanonicalizationMethod> not found\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    algo = xmlGetProp(c14nNode, xmlSecAttrAlgorithm);
    if(algo == NULL || xmlStrcmp(algo, xmlSecHrefC14N) != 0) {
        testLog("Error: CanonicalizationMethod Algorithm='%s', expected '%s'\n",
                algo ? (char*)algo : "NULL", (char*)xmlSecHrefC14N);
        xmlFree(algo);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(algo);

    /* required: <dsig:SignatureMethod Algorithm="..."> inside SignedInfo */
    signMethodNode = xmlSecFindChild(signedInfoNode, xmlSecNodeSignatureMethod, xmlSecDSigNs);
    if(signMethodNode == NULL) {
        testLog("Error: <dsig:SignatureMethod> not found\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    algo = xmlGetProp(signMethodNode, xmlSecAttrAlgorithm);
    if(algo == NULL || xmlStrcmp(algo, xmlSecHrefEnveloped) != 0) {
        testLog("Error: SignatureMethod Algorithm='%s', expected '%s'\n",
                algo ? (char*)algo : "NULL", (char*)xmlSecHrefEnveloped);
        xmlFree(algo);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(algo);

    xmlFreeNode(signNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplSignatureCreate_with_id(void) {
    xmlNodePtr signNode = NULL;
    xmlChar* id;

    testStart("xmlSecTmplSignatureCreate: Id attribute is set when provided");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        BAD_CAST "sig1");
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    id = xmlGetProp(signNode, BAD_CAST "Id");
    if(id == NULL || xmlStrcmp(id, BAD_CAST "sig1") != 0) {
        testLog("Error: expected Id='sig1', got '%s'\n", id ? (char*)id : "NULL");
        xmlFree(id);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(id);
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplSignatureCreateNsPref
 *************************************************************************/
static void
test_xmlSecTmplSignatureCreateNsPref_prefix_applied(void) {
    xmlNodePtr signNode = NULL;
    xmlNsPtr ns;

    testStart("xmlSecTmplSignatureCreateNsPref: namespace prefix is applied");

    signNode = xmlSecTmplSignatureCreateNsPref(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL,
        BAD_CAST "dsig");
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreateNsPref returned NULL\n");
        testFinishedFailure();
        return;
    }

    /* The Signature node's namespace should have the requested prefix */
    ns = signNode->ns;
    if(ns == NULL || ns->prefix == NULL ||
       xmlStrcmp(ns->prefix, BAD_CAST "dsig") != 0) {
        testLog("Error: expected ns prefix 'dsig', got '%s'\n",
                (ns && ns->prefix) ? (char*)ns->prefix : "NULL");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    if(xmlStrcmp(ns->href, xmlSecDSigNs) != 0) {
        testLog("Error: expected ns href '%s', got '%s'\n",
                (char*)xmlSecDSigNs, ns->href ? (char*)ns->href : "NULL");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplSignatureCreateNsPref_null_prefix(void) {
    xmlNodePtr signNode = NULL;

    testStart("xmlSecTmplSignatureCreateNsPref: NULL prefix produces valid node");

    signNode = xmlSecTmplSignatureCreateNsPref(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreateNsPref returned NULL\n");
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(signNode, xmlSecNodeSignature, xmlSecDSigNs)) {
        testLog("Error: result is not a valid <dsig:Signature> node\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplSignatureGetSignMethodNode / xmlSecTmplSignatureGetC14NMethodNode
 *************************************************************************/
static void
test_xmlSecTmplSignatureGetSignMethodNode(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr methodNode;
    xmlChar* algo;

    testStart("xmlSecTmplSignatureGetSignMethodNode: returns SignatureMethod node");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    methodNode = xmlSecTmplSignatureGetSignMethodNode(signNode);
    if(methodNode == NULL) {
        testLog("Error: xmlSecTmplSignatureGetSignMethodNode returned NULL\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(methodNode, xmlSecNodeSignatureMethod, xmlSecDSigNs)) {
        testLog("Error: returned node is not <dsig:SignatureMethod>\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    algo = xmlGetProp(methodNode, xmlSecAttrAlgorithm);
    if(algo == NULL || xmlStrcmp(algo, xmlSecHrefEnveloped) != 0) {
        testLog("Error: SignatureMethod Algorithm mismatch\n");
        xmlFree(algo);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(algo);
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplSignatureGetC14NMethodNode(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr methodNode;
    xmlChar* algo;

    testStart("xmlSecTmplSignatureGetC14NMethodNode: returns CanonicalizationMethod node");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    methodNode = xmlSecTmplSignatureGetC14NMethodNode(signNode);
    if(methodNode == NULL) {
        testLog("Error: xmlSecTmplSignatureGetC14NMethodNode returned NULL\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(methodNode, xmlSecNodeCanonicalizationMethod, xmlSecDSigNs)) {
        testLog("Error: returned node is not <dsig:CanonicalizationMethod>\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    algo = xmlGetProp(methodNode, xmlSecAttrAlgorithm);
    if(algo == NULL || xmlStrcmp(algo, xmlSecHrefC14N) != 0) {
        testLog("Error: CanonicalizationMethod Algorithm mismatch\n");
        xmlFree(algo);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(algo);
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplSignatureEnsureKeyInfo
 *************************************************************************/
static void
test_xmlSecTmplSignatureEnsureKeyInfo_adds_node(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr keyInfoNode;

    testStart("xmlSecTmplSignatureEnsureKeyInfo: adds KeyInfo when absent");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    /* initially no KeyInfo */
    if(xmlSecFindChild(signNode, xmlSecNodeKeyInfo, xmlSecDSigNs) != NULL) {
        testLog("Error: unexpected KeyInfo present before ensure call\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        testLog("Error: xmlSecTmplSignatureEnsureKeyInfo returned NULL\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(keyInfoNode, xmlSecNodeKeyInfo, xmlSecDSigNs)) {
        testLog("Error: returned node is not <dsig:KeyInfo>\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplSignatureEnsureKeyInfo_idempotent(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr keyInfoNode1;
    xmlNodePtr keyInfoNode2;

    testStart("xmlSecTmplSignatureEnsureKeyInfo: second call returns same node");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    keyInfoNode1 = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    keyInfoNode2 = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode1 == NULL || keyInfoNode2 == NULL ||
       keyInfoNode1 != keyInfoNode2) {
        testLog("Error: expected same KeyInfo node on second call\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplSignatureAddReference
 *************************************************************************/
static void
test_xmlSecTmplSignatureAddReference_with_uri(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode;
    xmlNodePtr digestMethodNode;
    xmlChar* attr;

    testStart("xmlSecTmplSignatureAddReference: creates Reference with URI and DigestMethod");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    refNode = xmlSecTmplSignatureAddReference(signNode,
        xmlSecTransformInclC14NId,
        BAD_CAST "ref1",
        BAD_CAST "#data",
        NULL);
    if(refNode == NULL) {
        testLog("Error: xmlSecTmplSignatureAddReference returned NULL\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    /* check Reference node name / namespace */
    if(!xmlSecCheckNodeName(refNode, xmlSecNodeReference, xmlSecDSigNs)) {
        testLog("Error: result is not <dsig:Reference>\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    /* check URI attribute */
    attr = xmlGetProp(refNode, xmlSecAttrURI);
    if(attr == NULL || xmlStrcmp(attr, BAD_CAST "#data") != 0) {
        testLog("Error: expected URI='#data', got '%s'\n", attr ? (char*)attr : "NULL");
        xmlFree(attr);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(attr);

    /* check Id attribute */
    attr = xmlGetProp(refNode, xmlSecAttrId);
    if(attr == NULL || xmlStrcmp(attr, BAD_CAST "ref1") != 0) {
        testLog("Error: expected Id='ref1', got '%s'\n", attr ? (char*)attr : "NULL");
        xmlFree(attr);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(attr);

    /* check DigestMethod child with Algorithm attribute */
    digestMethodNode = xmlSecFindChild(refNode, xmlSecNodeDigestMethod, xmlSecDSigNs);
    if(digestMethodNode == NULL) {
        testLog("Error: <dsig:DigestMethod> not found inside Reference\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    attr = xmlGetProp(digestMethodNode, xmlSecAttrAlgorithm);
    if(attr == NULL || xmlStrcmp(attr, xmlSecHrefC14N) != 0) {
        testLog("Error: DigestMethod Algorithm mismatch: '%s'\n",
                attr ? (char*)attr : "NULL");
        xmlFree(attr);
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFree(attr);

    xmlFreeNode(signNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplSignatureAddReference_multiple(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr ref1, ref2;

    testStart("xmlSecTmplSignatureAddReference: can add multiple references");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    ref1 = xmlSecTmplSignatureAddReference(signNode,
        xmlSecTransformInclC14NId, BAD_CAST "r1", BAD_CAST "#d1", NULL);
    ref2 = xmlSecTmplSignatureAddReference(signNode,
        xmlSecTransformInclC14NId, BAD_CAST "r2", BAD_CAST "#d2", NULL);
    if(ref1 == NULL || ref2 == NULL || ref1 == ref2) {
        testLog("Error: expected two distinct Reference nodes\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplEncDataCreate
 *************************************************************************/
static void
test_xmlSecTmplEncDataCreate_structure(void) {
    xmlNodePtr encNode = NULL;
    xmlNodePtr methodNode;
    xmlNodePtr cipherDataNode;
    xmlChar* algo;

    testStart("xmlSecTmplEncDataCreate: creates correct EncryptedData structure");

    encNode = xmlSecTmplEncDataCreate(NULL,
        xmlSecTransformExclC14NId,
        BAD_CAST "enc1",
        NULL, NULL, NULL);
    if(encNode == NULL) {
        testLog("Error: xmlSecTmplEncDataCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    /* root must be <enc:EncryptedData> */
    if(!xmlSecCheckNodeName(encNode, xmlSecNodeEncryptedData, xmlSecEncNs)) {
        testLog("Error: root is not <enc:EncryptedData>\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }

    /* required: <enc:EncryptionMethod Algorithm="..."> */
    methodNode = xmlSecFindChild(encNode, xmlSecNodeEncryptionMethod, xmlSecEncNs);
    if(methodNode == NULL) {
        testLog("Error: <enc:EncryptionMethod> not found\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    algo = xmlGetProp(methodNode, xmlSecAttrAlgorithm);
    if(algo == NULL || xmlStrcmp(algo, xmlSecHrefExcC14N) != 0) {
        testLog("Error: EncryptionMethod Algorithm='%s', expected '%s'\n",
                algo ? (char*)algo : "NULL", (char*)xmlSecHrefExcC14N);
        xmlFree(algo);
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    xmlFree(algo);

    /* required: <enc:CipherData> */
    cipherDataNode = xmlSecFindChild(encNode, xmlSecNodeCipherData, xmlSecEncNs);
    if(cipherDataNode == NULL) {
        testLog("Error: <enc:CipherData> not found\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }

    /* check Id attribute is set */
    algo = xmlGetProp(encNode, xmlSecAttrId);
    if(algo == NULL || xmlStrcmp(algo, BAD_CAST "enc1") != 0) {
        testLog("Error: expected Id='enc1', got '%s'\n", algo ? (char*)algo : "NULL");
        xmlFree(algo);
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    xmlFree(algo);

    xmlFreeNode(encNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplEncDataCreate_null_method(void) {
    xmlNodePtr encNode = NULL;
    xmlNodePtr methodNode;
    xmlNodePtr cipherDataNode;

    testStart("xmlSecTmplEncDataCreate: NULL encMethodId omits EncryptionMethod child");

    encNode = xmlSecTmplEncDataCreate(NULL, NULL, NULL, NULL, NULL, NULL);
    if(encNode == NULL) {
        testLog("Error: xmlSecTmplEncDataCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    /* no EncryptionMethod when method is NULL */
    methodNode = xmlSecFindChild(encNode, xmlSecNodeEncryptionMethod, xmlSecEncNs);
    if(methodNode != NULL) {
        testLog("Error: unexpected <enc:EncryptionMethod> with NULL encMethodId\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }

    /* CipherData must still be present */
    cipherDataNode = xmlSecFindChild(encNode, xmlSecNodeCipherData, xmlSecEncNs);
    if(cipherDataNode == NULL) {
        testLog("Error: <enc:CipherData> not found\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }

    xmlFreeNode(encNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplEncDataEnsureCipherValue
 *************************************************************************/
static void
test_xmlSecTmplEncDataEnsureCipherValue_adds_node(void) {
    xmlNodePtr encNode = NULL;
    xmlNodePtr cipherValueNode;

    testStart("xmlSecTmplEncDataEnsureCipherValue: adds CipherValue inside CipherData");

    encNode = xmlSecTmplEncDataCreate(NULL, xmlSecTransformExclC14NId,
        NULL, NULL, NULL, NULL);
    if(encNode == NULL) {
        testLog("Error: xmlSecTmplEncDataCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    cipherValueNode = xmlSecTmplEncDataEnsureCipherValue(encNode);
    if(cipherValueNode == NULL) {
        testLog("Error: xmlSecTmplEncDataEnsureCipherValue returned NULL\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(cipherValueNode, xmlSecNodeCipherValue, xmlSecEncNs)) {
        testLog("Error: returned node is not <enc:CipherValue>\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(encNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplEncDataEnsureCipherValue_idempotent(void) {
    xmlNodePtr encNode = NULL;
    xmlNodePtr cv1, cv2;

    testStart("xmlSecTmplEncDataEnsureCipherValue: second call returns same node");

    encNode = xmlSecTmplEncDataCreate(NULL, xmlSecTransformExclC14NId,
        NULL, NULL, NULL, NULL);
    if(encNode == NULL) {
        testLog("Error: xmlSecTmplEncDataCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    cv1 = xmlSecTmplEncDataEnsureCipherValue(encNode);
    cv2 = xmlSecTmplEncDataEnsureCipherValue(encNode);
    if(cv1 == NULL || cv2 == NULL || cv1 != cv2) {
        testLog("Error: expected same CipherValue node on second call\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(encNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplEncDataEnsureKeyInfo
 *************************************************************************/
static void
test_xmlSecTmplEncDataEnsureKeyInfo_adds_node(void) {
    xmlNodePtr encNode = NULL;
    xmlNodePtr keyInfoNode;

    testStart("xmlSecTmplEncDataEnsureKeyInfo: adds KeyInfo before CipherData");

    encNode = xmlSecTmplEncDataCreate(NULL, xmlSecTransformExclC14NId,
        NULL, NULL, NULL, NULL);
    if(encNode == NULL) {
        testLog("Error: xmlSecTmplEncDataCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    /* initially no KeyInfo */
    if(xmlSecFindChild(encNode, xmlSecNodeKeyInfo, xmlSecDSigNs) != NULL) {
        testLog("Error: unexpected KeyInfo before ensure call\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }

    keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encNode, NULL);
    if(keyInfoNode == NULL) {
        testLog("Error: xmlSecTmplEncDataEnsureKeyInfo returned NULL\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(keyInfoNode, xmlSecNodeKeyInfo, xmlSecDSigNs)) {
        testLog("Error: returned node is not <dsig:KeyInfo>\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(encNode);
    testFinishedSuccess();
}

static void
test_xmlSecTmplEncDataEnsureKeyInfo_idempotent(void) {
    xmlNodePtr encNode = NULL;
    xmlNodePtr ki1, ki2;

    testStart("xmlSecTmplEncDataEnsureKeyInfo: second call returns same node");

    encNode = xmlSecTmplEncDataCreate(NULL, xmlSecTransformExclC14NId,
        NULL, NULL, NULL, NULL);
    if(encNode == NULL) {
        testLog("Error: xmlSecTmplEncDataCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    ki1 = xmlSecTmplEncDataEnsureKeyInfo(encNode, NULL);
    ki2 = xmlSecTmplEncDataEnsureKeyInfo(encNode, NULL);
    if(ki1 == NULL || ki2 == NULL || ki1 != ki2) {
        testLog("Error: expected same KeyInfo node on second call\n");
        xmlFreeNode(encNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(encNode);
    testFinishedSuccess();
}

/*************************************************************************
 * xmlSecTmplKeyInfoAddKeyName
 *************************************************************************/
static void
test_xmlSecTmplKeyInfoAddKeyName_with_name(void) {
    xmlDocPtr doc = NULL;
    xmlNodePtr signNode = NULL;
    xmlNodePtr keyInfoNode;
    xmlNodePtr keyNameNode;
    xmlChar* content;

    testStart("xmlSecTmplKeyInfoAddKeyName: adds KeyName with correct content");

    /* xmlSecNodeEncodeAndSetContent requires node->doc != NULL, so create a
     * real document and attach the signature node to it. */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
        testLog("Error: failed to create doc\n");
        testFinishedFailure();
        return;
    }

    signNode = xmlSecTmplSignatureCreate(doc,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlDocSetRootElement(doc, signNode);

    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        testLog("Error: xmlSecTmplSignatureEnsureKeyInfo returned NULL\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }

    keyNameNode = xmlSecTmplKeyInfoAddKeyName(keyInfoNode, BAD_CAST "my-key-name");
    if(keyNameNode == NULL) {
        testLog("Error: xmlSecTmplKeyInfoAddKeyName returned NULL\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(keyNameNode, xmlSecNodeKeyName, xmlSecDSigNs)) {
        testLog("Error: returned node is not <dsig:KeyName>\n");
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    content = xmlNodeGetContent(keyNameNode);
    if(content == NULL || xmlStrcmp(content, BAD_CAST "my-key-name") != 0) {
        testLog("Error: expected KeyName content 'my-key-name', got '%s'\n",
                content ? (char*)content : "NULL");
        xmlFree(content);
        xmlFreeDoc(doc);
        testFinishedFailure();
        return;
    }
    xmlFree(content);
    xmlFreeDoc(doc);
    testFinishedSuccess();
}

static void
test_xmlSecTmplKeyInfoAddKeyName_null_name(void) {
    xmlNodePtr signNode = NULL;
    xmlNodePtr keyInfoNode;
    xmlNodePtr keyNameNode;

    testStart("xmlSecTmplKeyInfoAddKeyName: NULL name produces empty KeyName");

    signNode = xmlSecTmplSignatureCreate(NULL,
        xmlSecTransformInclC14NId,
        xmlSecTransformEnvelopedId,
        NULL);
    if(signNode == NULL) {
        testLog("Error: xmlSecTmplSignatureCreate returned NULL\n");
        testFinishedFailure();
        return;
    }

    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        testLog("Error: xmlSecTmplSignatureEnsureKeyInfo returned NULL\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }

    keyNameNode = xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL);
    if(keyNameNode == NULL) {
        testLog("Error: xmlSecTmplKeyInfoAddKeyName returned NULL for NULL name\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    if(!xmlSecCheckNodeName(keyNameNode, xmlSecNodeKeyName, xmlSecDSigNs)) {
        testLog("Error: returned node is not <dsig:KeyName>\n");
        xmlFreeNode(signNode);
        testFinishedFailure();
        return;
    }
    xmlFreeNode(signNode);
    testFinishedSuccess();
}

/*************************************************************************
 * exported entry point
 *************************************************************************/
int
test_templates(void) {
    int success = 1;

    testGroupStart("xmlSecTmplSignatureCreate");
    test_xmlSecTmplSignatureCreate_structure();
    test_xmlSecTmplSignatureCreate_with_id();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplSignatureCreateNsPref");
    test_xmlSecTmplSignatureCreateNsPref_prefix_applied();
    test_xmlSecTmplSignatureCreateNsPref_null_prefix();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplSignatureGetMethodNodes");
    test_xmlSecTmplSignatureGetSignMethodNode();
    test_xmlSecTmplSignatureGetC14NMethodNode();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplSignatureEnsureKeyInfo");
    test_xmlSecTmplSignatureEnsureKeyInfo_adds_node();
    test_xmlSecTmplSignatureEnsureKeyInfo_idempotent();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplSignatureAddReference");
    test_xmlSecTmplSignatureAddReference_with_uri();
    test_xmlSecTmplSignatureAddReference_multiple();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplEncDataCreate");
    test_xmlSecTmplEncDataCreate_structure();
    test_xmlSecTmplEncDataCreate_null_method();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplEncDataEnsureCipherValue");
    test_xmlSecTmplEncDataEnsureCipherValue_adds_node();
    test_xmlSecTmplEncDataEnsureCipherValue_idempotent();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplEncDataEnsureKeyInfo");
    test_xmlSecTmplEncDataEnsureKeyInfo_adds_node();
    test_xmlSecTmplEncDataEnsureKeyInfo_idempotent();
    if(testGroupFinished() != 1) { success = 0; }

    testGroupStart("xmlSecTmplKeyInfoAddKeyName");
    test_xmlSecTmplKeyInfoAddKeyName_with_name();
    test_xmlSecTmplKeyInfoAddKeyName_null_name();
    if(testGroupFinished() != 1) { success = 0; }

    return(success);
}
