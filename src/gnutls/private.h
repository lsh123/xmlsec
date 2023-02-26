/*
 * XML Security Library
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
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

/*************************************************************************
 *
 * x509 certs utils/helpers
 *
 ************************************************************************/
gnutls_x509_crt_t       xmlSecGnuTLSX509CertDup                 (gnutls_x509_crt_t src);
xmlChar *               xmlSecGnuTLSX509CertGetSubjectDN        (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetIssuerDN         (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetIssuerSerial     (gnutls_x509_crt_t cert);
xmlChar *               xmlSecGnuTLSX509CertGetSKI              (gnutls_x509_crt_t cert);


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
    unsigned int digestLen;
    /* TODO: const EVP_MD* digestMd; */
} xmlSecGnuTLSX509FindCertCtx, *xmlSecGnuTLSX509FindCertCtxPtr;

XMLSEC_CRYPTO_EXPORT int        xmlSecGnuTLSX509FindCertCtxInitialize      (xmlSecGnuTLSX509FindCertCtxPtr ctx,
                                                                             const xmlChar *subjectName,
                                                                             const xmlChar *issuerName,
                                                                             const xmlChar *issuerSerial,
                                                                             const xmlSecByte * ski,
                                                                             xmlSecSize skiSize);
XMLSEC_CRYPTO_EXPORT int        xmlSecGnuTLSX509FindCertCtxInitializeFromValue(xmlSecGnuTLSX509FindCertCtxPtr ctx,
                                                                             xmlSecKeyX509DataValuePtr x509Value);
XMLSEC_CRYPTO_EXPORT void       xmlSecGnuTLSX509FindCertCtxFinalize        (xmlSecGnuTLSX509FindCertCtxPtr ctx);

XMLSEC_CRYPTO_EXPORT int        xmlSecGnuTLSX509FindCertCtxMatch          (xmlSecGnuTLSX509FindCertCtxPtr ctx,
                                                                           gnutls_x509_crt_t cert);



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
                                                                 xmlSecPtrListPtr certsList);

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
