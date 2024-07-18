/*
 * XML Security Library
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef __XMLSEC_GNUTLS_PRIVATE_H__
#define __XMLSEC_GNUTLS_PRIVATE_H__

#ifndef XMLSEC_PRIVATE
#error "gnutls/private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */



/**************************************************************************
 *
 * Keys
 *
 *****************************************************************************/
xmlSecKeyDataPtr        xmlSecGnuTLSAsymKeyDataCreate           (gnutls_pubkey_t pubkey,
                                                                 gnutls_privkey_t privkey);


gnutls_pubkey_t         xmlSecGnuTLSAsymKeyDataGetPublicKey     (xmlSecKeyDataPtr data);
gnutls_privkey_t        xmlSecGnuTLSAsymKeyDataGetPrivateKey    (xmlSecKeyDataPtr data);
xmlSecKeyDataType       xmlSecGnuTLSAsymKeyDataGetType          (xmlSecKeyDataPtr data);
xmlSecSize              xmlSecGnuTLSAsymKeyDataGetSize          (xmlSecKeyDataPtr data);

#ifndef XMLSEC_NO_X509

/**************************************************************************
 *
 * X509 certs list
 *
 *****************************************************************************/
#define xmlSecGnuTLSX509CrtListId   \
        xmlSecGnuTLSX509CrtListGetKlass()
xmlSecPtrListId         xmlSecGnuTLSX509CrtListGetKlass         (void);

/**************************************************************************
 *
 * X509 crls list
 *
 *****************************************************************************/
#define xmlSecGnuTLSX509CrlListId   \
        xmlSecGnuTLSX509CrlListGetKlass()
xmlSecPtrListId         xmlSecGnuTLSX509CrlListGetKlass         (void);


xmlSecPtrListPtr        xmlSecGnuTLSKeyDataX509GetCerts         (xmlSecKeyDataPtr data);
xmlSecPtrListPtr        xmlSecGnuTLSKeyDataX509GetCrls          (xmlSecKeyDataPtr data);

/*************************************************************************
 *
 * x509 certs utils/helpers
 *
 ************************************************************************/
gnutls_x509_crt_t       xmlSecGnuTLSX509CertDup                 (gnutls_x509_crt_t src);
int                     xmlSecGnuTLSX509CertIsSelfSigned        (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetSubjectDN        (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetIssuerDN         (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetIssuerSerial     (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetSKI              (gnutls_x509_crt_t cert);

int                     xmlSecGnuTLSX509DigestWrite             (gnutls_x509_crt_t cert,
                                                                 const xmlChar* algorithm,
                                                                 xmlSecBufferPtr buf);

gnutls_x509_crt_t       xmlSecGnuTLSX509CertRead                (const xmlSecByte* buf,
                                                                 xmlSecSize size,
                                                                 xmlSecKeyDataFormat format);
int                     xmlSecGnuTLSX509CertDerWrite            (gnutls_x509_crt_t cert,
                                                                 xmlSecBufferPtr buf);
void                    xmlSecGnuTLSX509CertDebugDump           (gnutls_x509_crt_t cert,
                                                                 FILE* output);
void                    xmlSecGnuTLSX509CertDebugXmlDump        (gnutls_x509_crt_t cert,
                                                                 FILE* output);


gnutls_x509_crt_t       xmlSecGnuTLSX509StoreFindCertByValue    (xmlSecKeyDataStorePtr store,
                                                                 xmlSecKeyX509DataValuePtr x509Value);
xmlSecKeyPtr            xmlSecGnuTLSX509FindKeyByValue          (xmlSecPtrListPtr keysList,
                                                                 xmlSecKeyX509DataValuePtr x509Value);

gnutls_digest_algorithm_t  xmlSecGnuTLSX509GetDigestFromAlgorithm(const xmlChar* href);

/*************************************************************************
 *
 * x509 certs search ctx
 *
 ************************************************************************/
typedef struct _xmlSecGnuTLSX509FindCertCtx {
    const xmlChar *subjectName;         /* NOT OWNED */

    const xmlChar *issuerName;          /* NOT OWNED */
    const xmlChar *issuerSerial;        /* NOT OWNED */

    const xmlSecByte * ski;             /* NOT OWNED */
    xmlSecSize skiSize;

    const xmlSecByte * digestValue;     /* NOT OWNED */
    size_t digestLen;
    gnutls_digest_algorithm_t digestAlgo;
} xmlSecGnuTLSX509FindCertCtx, *xmlSecGnuTLSX509FindCertCtxPtr;

int        xmlSecGnuTLSX509FindCertCtxInitialize            (xmlSecGnuTLSX509FindCertCtxPtr ctx,
                                                             const xmlChar *subjectName,
                                                             const xmlChar *issuerName,
                                                             const xmlChar *issuerSerial,
                                                             const xmlSecByte * ski,
                                                             xmlSecSize skiSize);
int        xmlSecGnuTLSX509FindCertCtxInitializeFromValue   (xmlSecGnuTLSX509FindCertCtxPtr ctx,
                                                             xmlSecKeyX509DataValuePtr x509Value);
void       xmlSecGnuTLSX509FindCertCtxFinalize              (xmlSecGnuTLSX509FindCertCtxPtr ctx);

int        xmlSecGnuTLSX509FindCertCtxMatch                 (xmlSecGnuTLSX509FindCertCtxPtr ctx,
                                                             gnutls_x509_crt_t cert);

int         xmlSecGnuTLSX509StoreVerifyKey                  (xmlSecKeyDataStorePtr store,
                                                             xmlSecKeyPtr key,
                                                             xmlSecKeyInfoCtxPtr keyInfoCtx);

/*************************************************************************
 *
 * x509 crls utils/helpers
 *
 ************************************************************************/
gnutls_x509_crl_t       xmlSecGnuTLSX509CrlDup                  (gnutls_x509_crl_t src);
xmlChar *               xmlSecGnuTLSX509CrlGetIssuerDN          (gnutls_x509_crl_t crl);
gnutls_x509_crl_t       xmlSecGnuTLSX509CrlRead                 (const xmlSecByte* buf,
                                                                 xmlSecSize size,
                                                                 xmlSecKeyDataFormat format);
int                     xmlSecGnuTLSX509CrlDerWrite             (gnutls_x509_crl_t crl,
                                                                 xmlSecBufferPtr buf);
void                    xmlSecGnuTLSX509CrlDebugDump            (gnutls_x509_crl_t crl,
                                                                 FILE* output);
void                    xmlSecGnuTLSX509CrlDebugXmlDump         (gnutls_x509_crl_t crl,
                                                                 FILE* output);


/*************************************************************************
 *
 * Misc. utils/helpers
 *
 ************************************************************************/
xmlChar*                xmlSecGnuTLSASN1IntegerWrite            (const unsigned char * data,
                                                                 size_t len);

int                     xmlSecGnuTLSX509DnsEqual                (const xmlChar * ll,
                                                                 const xmlChar * rr);
int                     xmlSecGnuTLSX509CertCompareSKI          (gnutls_x509_crt_t cert,
                                                                 const xmlSecByte * ski,
                                                                  xmlSecSize skiSize);

/*************************************************************************
 *
 * pkcs12 utils/helpers
 *
 ************************************************************************/
int                     xmlSecGnuTLSPkcs12LoadMemory            (const xmlSecByte* data,
                                                                 xmlSecSize dataSize,
                                                                 const char *pwd,
                                                                 gnutls_x509_privkey_t * priv_key,
                                                                 gnutls_x509_crt_t * key_cert,
                                                                 xmlSecPtrListPtr certsList,
                                                                 xmlChar ** keyName);

/*************************************************************************
 *
 * LDAP DN parser
 *
 ************************************************************************/
typedef struct _xmlSecGnuTLSDnAttr {
    xmlChar * key;
    xmlChar * value;
} xmlSecGnuTLSDnAttr;

void                    xmlSecGnuTLSDnAttrsInitialize           (xmlSecGnuTLSDnAttr * attrs,
                                                                 xmlSecSize attrsSize);
void                    xmlSecGnuTLSDnAttrsDeinitialize         (xmlSecGnuTLSDnAttr * attrs,
                                                                 xmlSecSize attrsSize);
const xmlSecGnuTLSDnAttr * xmlSecGnuTLSDnAttrrsFind             (const xmlSecGnuTLSDnAttr * attrs,
                                                                 xmlSecSize attrsSize,
                                                                 const xmlChar * key);
int                     xmlSecGnuTLSDnAttrsEqual                (const xmlSecGnuTLSDnAttr * ll,
                                                                 xmlSecSize llSize,
                                                                 const xmlSecGnuTLSDnAttr * rr,
                                                                 xmlSecSize rrSize);
int                     xmlSecGnuTLSDnAttrsParse                (const xmlChar * dn,
                                                                 xmlSecGnuTLSDnAttr * attrs,
                                                                 xmlSecSize attrsSize);
#endif /* XMLSEC_NO_X509 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ! __XMLSEC_GNUTLS_PRIVATE_H__ */
