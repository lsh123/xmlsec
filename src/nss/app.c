/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Application support functions for NSS.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * SECTION:app
 * @Short_description: Application support functions for NSS.
 * @Stability: Stable
 *
 * Common functions for xmlsec1 command line utility tool for NSS.
 */

#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <cert.h>
#include <certdb.h>
#include <keyhi.h>
#include <pk11func.h>
#include <pkcs12.h>
#include <p12plcy.h>
/*
#include <ssl.h>
*/

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>
#include <xmlsec/private.h>

#include <xmlsec/nss/app.h>
#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>
#include <xmlsec/nss/pkikeys.h>
#include <xmlsec/nss/keysstore.h>

#include "../cast_helpers.h"
#include "private.h"

static int xmlSecNssAppCreateSECItem                            (SECItem *contents,
                                                                 const xmlSecByte* data,
                                                                 xmlSecSize dataSize);
static int xmlSecNssAppReadSECItem                              (SECItem *contents,
                                                                 const char *fn);
static PRBool xmlSecNssAppAscii2UCS2Conv                        (PRBool toUnicode,
                                                                 unsigned char *inBuf,
                                                                 unsigned int   inBufLen,
                                                                 unsigned char *outBuf,
                                                                 unsigned int   maxOutBufLen,
                                                                 unsigned int  *outBufLen,
                                                                 PRBool         swapBytes);
static xmlSecKeyPtr     xmlSecNssAppDerKeyLoadSECItem           (SECItem* secItem);


#ifndef XMLSEC_NO_X509
static SECItem *xmlSecNssAppNicknameCollisionCallback           (SECItem *old_nick,
                                                                 PRBool *cancel,
                                                                 void *wincx);
#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecNssAppInit:
 * @config:             the path to NSS database files.
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before
 * @xmlSecInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppInit(const char* config) {
    SECStatus rv;

    if(config) {
        rv = NSS_InitReadWrite(config);
        if(rv != SECSuccess) {
            xmlSecNssError2("NSS_InitReadWrite", NULL,
                            "config=%s",
                            xmlSecErrorsSafeString(config));
            return(-1);
        }
    } else {
        rv = NSS_NoDB_Init(NULL);
        if(rv != SECSuccess) {
            xmlSecNssError("NSS_NoDB_Init", NULL);
            return(-1);
        }
    }

    /* configure PKCS11 */
    PK11_ConfigurePKCS11("manufacturesID", "libraryDescription",
                         "tokenDescription", "privateTokenDescription",
                         "slotDescription", "privateSlotDescription",
                         "fipsSlotDescription", "fipsPrivateSlotDescription",
                         0, 0);

    /* setup for PKCS12 */
    PORT_SetUCS2_ASCIIConversionFunction(xmlSecNssAppAscii2UCS2Conv);
    SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
    SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
    SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
    SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
    SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);

    return(0);
}

/**
 * xmlSecNssAppShutdown:
 *
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after
 * @xmlSecShutdown function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppShutdown(void) {
    SECStatus rv;
/*
    SSL_ClearSessionCache();
*/
    PK11_LogoutAll();
    rv = NSS_Shutdown();
    if(rv != SECSuccess) {
        xmlSecNssError("NSS_Shutdown", NULL);
        return(-1);
    }
    return(0);
}


static int
xmlSecNssAppCreateSECItem(SECItem *contents, const xmlSecByte* data, xmlSecSize dataSize) {
    unsigned int dataLen;

    xmlSecAssert2(contents != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    contents->data = 0;
    XMLSEC_SAFE_CAST_SIZE_TO_UINT(dataSize, dataLen, return(-1), NULL);
    if (!SECITEM_AllocItem(NULL, contents, dataLen)) {
        xmlSecNssError("SECITEM_AllocItem", NULL);
        return(-1);
    }

    if(dataLen > 0) {
        xmlSecAssert2(contents->data != NULL, -1);
        memcpy(contents->data, data, dataLen);
    }

    return (0);
}

static int
xmlSecNssAppReadSECItem(SECItem *contents, const char *fn) {
    PRFileInfo info;
    PRFileDesc *file = NULL;
    PRInt32 numBytes;
    PRStatus prStatus;
    unsigned int ulen;
    int ret = -1;

    xmlSecAssert2(contents != NULL, -1);
    xmlSecAssert2(fn != NULL, -1);

    file = PR_Open(fn, PR_RDONLY, 00660);
    if (file == NULL) {
        xmlSecNssError2("PR_Open", NULL,
                        "filename=%s", xmlSecErrorsSafeString(fn));
        goto done;
    }

    prStatus = PR_GetOpenFileInfo(file, &info);
    if (prStatus != PR_SUCCESS) {
        xmlSecNssError2("PR_GetOpenFileInfo", NULL,
                        "filename=%s", xmlSecErrorsSafeString(fn));
        goto done;
    }
    XMLSEC_SAFE_CAST_INT_TO_UINT(info.size, ulen, goto done, NULL);

    contents->data = 0;
    if (!SECITEM_AllocItem(NULL, contents, ulen)) {
        xmlSecNssError("SECITEM_AllocItem", NULL);
        goto done;
    }

    numBytes = PR_Read(file, contents->data, info.size);
    if (numBytes != info.size) {
        SECITEM_FreeItem(contents, PR_FALSE);
        goto done;
    }

    ret = 0;
done:
    if (file) {
        PR_Close(file);
    }

    return (ret);
}

static PRBool
xmlSecNssAppAscii2UCS2Conv(PRBool toUnicode,
                           unsigned char *inBuf,
                           unsigned int   inBufLen,
                           unsigned char *outBuf,
                           unsigned int   maxOutBufLen,
                           unsigned int  *outBufLen,
                           PRBool         swapBytes ATTRIBUTE_UNUSED)
{
    SECItem it = { siBuffer, NULL, 0 };

    if (toUnicode == PR_FALSE) {
        return (PR_FALSE);
    }

    memset(&it, 0, sizeof(it));
    it.data = inBuf;
    it.len = inBufLen;

    return(PORT_UCS2_UTF8Conversion(toUnicode, it.data, it.len,
                                    outBuf, maxOutBufLen, outBufLen));
}

#ifndef XMLSEC_NO_X509
/* rename certificate if needed */
static SECItem *
xmlSecNssAppNicknameCollisionCallback(SECItem *old_nick ATTRIBUTE_UNUSED,
    PRBool *cancel, void *wincx ATTRIBUTE_UNUSED
) {
    CERTCertificate *cert = (CERTCertificate *)wincx;
    char *nick = NULL;
    SECItem *ret_nick = NULL;

    if((cancel  == NULL) || (cert == NULL)) {
        xmlSecNssError("cert is missing", NULL);
        return(NULL);
    }

    nick = CERT_MakeCANickname(cert);
    if (!nick) {
        xmlSecNssError("CERT_MakeCANickname", NULL);
        return(NULL);
    }

    ret_nick = PORT_ZNew(SECItem);
    if (ret_nick == NULL) {
        xmlSecNssError("PORT_ZNew", NULL);
        PORT_Free(nick);
        return NULL;
    }

    /* done */
    ret_nick->data = (unsigned char *)nick;
    ret_nick->len = (unsigned int)PORT_Strlen(nick);
    return ret_nick;
}
#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecNssAppKeyLoadEx:
 * @filename:           the key filename.
 * @type:               the key type (public / private).
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from a file
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyLoadEx(const char *filename, xmlSecKeyDataType type ATTRIBUTE_UNUSED, xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx
) {
    SECItem secItem = { siBuffer, NULL, 0 };
    xmlSecKeyPtr res;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    UNREFERENCED_PARAMETER(type);

    /* read the file contents */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppReadSECItem(&secItem, filename);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppReadSECItem", NULL);
        return(NULL);
    }

    res = xmlSecNssAppKeyLoadSECItem(&secItem, format, pwd, pwdCallback, pwdCallbackCtx);
    if(res == NULL) {
        xmlSecInternalError("xmlSecNssAppKeyLoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(NULL);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(res);
}

/**
 * xmlSecNssAppKeyLoadMemory:
 * @data:               the key binary data.
 * @dataSize:           the key binary data size.
 * @format:             the key data format.
 * @pwd:                the key data2 password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from a binary @data.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format,
                    const char *pwd, void* pwdCallback, void* pwdCallbackCtx) {
    SECItem secItem = { siBuffer, NULL, 0 };
    xmlSecKeyPtr res;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppCreateSECItem(&secItem, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppCreateSECItem", NULL);
        return(NULL);
    }

    res = xmlSecNssAppKeyLoadSECItem(&secItem, format, pwd, pwdCallback, pwdCallbackCtx);
    if(res == NULL) {
        xmlSecInternalError("xmlSecNssAppKeyLoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(NULL);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(res);
}

/**
 * xmlSecNssAppKeyLoadSECItem:
 * @secItem:            the pointer to sec item.
 * @format:             the key format.
 * @pwd:                the key password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from a file
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyLoadSECItem(SECItem* secItem, xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx
) {
    xmlSecKeyPtr key = NULL;

    xmlSecAssert2(secItem != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
#ifndef XMLSEC_NO_X509
    case xmlSecKeyDataFormatPkcs12:
        key = xmlSecNssAppPkcs12LoadSECItem(secItem, pwd, pwdCallback, pwdCallbackCtx);
        if(key == NULL) {
            xmlSecInternalError("xmlSecNssAppPkcs12LoadSECItem", NULL);
            return(NULL);
        }
        break;
    case xmlSecKeyDataFormatCertDer:
    case xmlSecKeyDataFormatCertPem:
        key = xmlSecNssAppKeyFromCertLoadSECItem(secItem, format);
        if(key == NULL) {
            xmlSecInternalError("xmlSecNssAppKeyFromCertLoadSECItem", NULL);
            return(NULL);
        }
        break;
#endif /* XMLSEC_NO_X509 */
    case xmlSecKeyDataFormatDer:
        key = xmlSecNssAppDerKeyLoadSECItem(secItem);
        if(key == NULL) {
            xmlSecInternalError("xmlSecNssAppDerKeyLoadSECItem", NULL);
            return(NULL);
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        return(NULL);
    }

    return(key);
}

static xmlSecKeyPtr
xmlSecNssAppDerKeyLoadSECItem(SECItem* secItem) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr retval = NULL;
    xmlSecKeyDataPtr data = NULL;
    int ret;
    SECKEYPublicKey *pubkey = NULL;
    SECKEYPrivateKey *privkey = NULL;
    CERTSubjectPublicKeyInfo *spki = NULL;
    SECItem nickname = { siBuffer, NULL, 0 };
    PK11SlotInfo *slot = NULL;
    SECStatus status;

    xmlSecAssert2(secItem != NULL, NULL);

    /* we're importing a key about which we know nothing yet, just use the
     * internal slot
     */
    slot = xmlSecNssGetInternalKeySlot();
    if (slot == NULL) {
        xmlSecInternalError("xmlSecNssGetInternalKeySlot", NULL);
        goto done;
    }

    nickname.len = 0;
    nickname.data = NULL;


    /* TRY PRIVATE KEY FIRST
     * Note: This expects the key to be in PrivateKeyInfo format. The
     * DER files created from PEM via nss utilities aren't in that
     * format
     */
    status = PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, secItem,
                            &nickname, NULL, PR_FALSE,
                            PR_TRUE, KU_ALL, &privkey, NULL);
    if (status != SECSuccess) {
        /* TRY PUBLIC KEY */
        spki = SECKEY_DecodeDERSubjectPublicKeyInfo(secItem);
        if (spki == NULL) {
            xmlSecNssError("SECKEY_DecodeDERSubjectPublicKeyInfo", NULL);
            goto done;
        }

        pubkey = SECKEY_ExtractPublicKey(spki);
        if (pubkey == NULL) {
            xmlSecNssError("SECKEY_ExtractPublicKey", NULL);
            goto done;
        }
    }

    data = xmlSecNssPKIAdoptKey(privkey, pubkey);
    if(data == NULL) {
        xmlSecInternalError("xmlSecNssPKIAdoptKey", NULL);
        goto done;
    }
    privkey = NULL;
    pubkey = NULL;

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }

    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue",
                            xmlSecKeyDataGetName(data));
        goto done;
    }
    retval = key;
    key = NULL;
    data = NULL;


done:
    if(slot != NULL) {
        PK11_FreeSlot(slot);
    }
    if(privkey != NULL) {
        SECKEY_DestroyPrivateKey(privkey);
    }
    if(pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    if(data != NULL) {
        xmlSecKeyDataDestroy(data);
    }
    if(spki != NULL) {
        SECKEY_DestroySubjectPublicKeyInfo(spki);
    }
    return (retval);
}

/* returns 1 if matches, 0 if not, or a negative value on error */
static int
xmlSecNssAppCheckCertMatchesKey(xmlSecKeyPtr key,  CERTCertificate * cert) {
    xmlSecKeyDataPtr keyData = NULL;
    SECKEYPublicKey* pubkey = NULL;
    SECKEYPublicKey* cert_pubkey = NULL;
    SECItem * der_pubkey = NULL;
    SECItem * der_cert_pubkey = NULL;
    int res = -1;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(cert != NULL, -1);

    /* get key's pubkey and its der encoding */
    keyData = xmlSecKeyGetValue(key);
    if(keyData == NULL) {
        res = 0; /* no key -> no match */
        goto done;
    }
    pubkey = xmlSecNssPKIKeyDataGetPubKey(keyData);
    if(pubkey == NULL) {
        xmlSecInternalError("xmlSecNssPKIKeyDataGetPubKey", NULL);
        goto done;
    }
    der_pubkey = SECKEY_EncodeDERSubjectPublicKeyInfo(pubkey);
    if (der_pubkey == NULL) {
        xmlSecNssError("SECKEY_EncodeDERSubjectPublicKeyInfo", NULL);
        goto done;
    }

    /* get certs's pubkey and its der encoding */
    cert_pubkey = CERT_ExtractPublicKey(cert);
    if (cert_pubkey == NULL) {
        xmlSecNssError("CERT_ExtractPublicKey", NULL);
        goto done;
    }
    der_cert_pubkey = SECKEY_EncodeDERSubjectPublicKeyInfo(cert_pubkey);
    if (der_cert_pubkey == NULL) {
        xmlSecNssError("SECKEY_EncodeDERSubjectPublicKeyInfo", NULL);
        goto done;
    }

    /* compare */
    if(SECEqual == SECITEM_CompareItem(der_pubkey, der_cert_pubkey)) {
        /* match */
        res = 1;
    } else {
        /* no match */
        res = 0;
    }

done:
    if(pubkey != NULL) {
        SECKEY_DestroyPublicKey(pubkey);
    }
    if (cert_pubkey) {
        SECKEY_DestroyPublicKey(cert_pubkey);
    }
    if(der_pubkey != NULL) {
        SECITEM_FreeItem(der_pubkey, PR_TRUE);
    }
    if(der_cert_pubkey != NULL) {
        SECITEM_FreeItem(der_cert_pubkey, PR_TRUE);
    }
    return(res);
}

#ifndef XMLSEC_NO_X509
/**
 * xmlSecNssAppKeyCertLoad:
 * @key:                the pointer to key.
 * @filename:           the certificate filename.
 * @format:             the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeyCertLoad(xmlSecKeyPtr key, const char* filename, xmlSecKeyDataFormat format) {
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* read the file contents */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppReadSECItem(&secItem, filename);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppReadSECItem", NULL);
        return(-1);
    }

    ret = xmlSecNssAppKeyCertLoadSECItem(key, &secItem, format);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppKeyCertLoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(-1);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(0);
}

/**
 * xmlSecNssAppKeyCertLoadMemory:
 * @key:                the pointer to key.
 * @data:               the key binary data.
 * @dataSize:           the key binary data size.
 * @format:             the certificate format.
 *
 * Reads the certificate from @data and adds it to key
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format) {
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* read the file contents */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppCreateSECItem(&secItem, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppCreateSECItem", NULL);
        return(-1);
    }

    ret = xmlSecNssAppKeyCertLoadSECItem(key, &secItem, format);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppKeyCertLoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(-1);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(0);
}

/**
 * xmlSecNssAppKeyCertLoadSECItem:
 * @key:                the pointer to key.
 * @secItem:            the pointer to SECItem.
 * @format:             the certificate format.
 *
 * Reads the certificate from @secItem and adds it to key
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeyCertLoadSECItem(xmlSecKeyPtr key, SECItem* secItem, xmlSecKeyDataFormat format) {
    CERTCertificate *cert = NULL;
    xmlSecKeyDataPtr x509Data;
    int isKeyCert = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(secItem != NULL, -1);
    xmlSecAssert2(secItem->type == siBuffer, -1);
    xmlSecAssert2(secItem->data != NULL, -1);
    xmlSecAssert2(secItem->len > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* read cert */
    switch(format) {
    case xmlSecKeyDataFormatPkcs8Der:
    case xmlSecKeyDataFormatDer:
        cert = xmlSecNssX509CertDerRead(CERT_GetDefaultCertDB(), secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            goto done;
        }
        break;
    case xmlSecKeyDataFormatCertPem:
        cert = xmlSecNssX509CertPemRead(CERT_GetDefaultCertDB(), secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertPemRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            goto done;
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        goto done;
    }
    xmlSecAssert2(cert != NULL, -1);

    /* add cert to the key */
    x509Data = xmlSecKeyEnsureData(key, xmlSecNssKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData(xmlSecNssKeyDataX509Id)", NULL);
        goto done;
    }

    /* do we want to add this cert as a key cert? */
    if(xmlSecNssKeyDataX509GetKeyCert(x509Data) == NULL) {
        ret = xmlSecNssAppCheckCertMatchesKey(key, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssAppCheckCertMatchesKey", NULL);
            goto done;
        }
        if(ret == 1) {
            isKeyCert = 1;
        }
    }
    if(isKeyCert != 0) {
        ret = xmlSecNssKeyDataX509AdoptKeyCert(x509Data, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssKeyDataX509AdoptKeyCert", NULL);
            goto done;
        }
    } else {
        ret = xmlSecNssKeyDataX509AdoptCert(x509Data, cert);
        if(ret < 0) {
            xmlSecInternalError("xmlSecNssKeyDataX509AdoptCert", NULL);
            goto done;
        }
    }
    cert = NULL; /* owned by x509Data now */

    /* success */
    res = 0;

done:
    if(cert != NULL) {
        CERT_DestroyCertificate(cert);
    }
    return(res);
}

/**
 * xmlSecNssAppPkcs12Load:
 * @filename:           the PKCS12 key filename.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file.
 * For uniformity, call @xmlSecNssAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppPkcs12Load(const char *filename, const char *pwd,
                       void *pwdCallback ATTRIBUTE_UNUSED,
                       void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    SECItem secItem = { siBuffer, NULL, 0 };
    xmlSecKeyPtr res;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);

    /* read the file contents */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppReadSECItem(&secItem, filename);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppReadSECItem", NULL);
        return(NULL);
    }

    res = xmlSecNssAppPkcs12LoadSECItem(&secItem, pwd, pwdCallback, pwdCallbackCtx);
    if(res == NULL) {
        xmlSecInternalError("xmlSecNssAppPkcs12LoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(NULL);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(res);
}

/**
 * xmlSecNssAppPkcs12LoadMemory:
 * @data:               the key binary data.
 * @dataSize:           the key binary data size.
 * @pwd:                the PKCS12 password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 binary data.
 * For uniformity, call @xmlSecNssAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize, const char *pwd,
                       void *pwdCallback ATTRIBUTE_UNUSED,
                       void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    SECItem secItem = { siBuffer, NULL, 0 };
    xmlSecKeyPtr res;
    int ret;

    xmlSecAssert2(data != NULL, NULL);

    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppCreateSECItem(&secItem, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppCreateSECItem", NULL);
        return(NULL);
    }

    res = xmlSecNssAppPkcs12LoadSECItem(&secItem, pwd, pwdCallback, pwdCallbackCtx);
    if(res == NULL) {
        xmlSecInternalError("xmlSecNssAppPkcs12LoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(NULL);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(res);
}


/**
 * xmlSecNssAppPkcs12LoadSECItem:
 * @secItem:            the @SECItem object.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 SECItem.
 * For uniformity, call @xmlSecNssAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppPkcs12LoadSECItem(SECItem* secItem, const char *pwd,
                       void *pwdCallback ATTRIBUTE_UNUSED,
                       void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr keyValueData = NULL;
    xmlSecKeyDataPtr x509Data = NULL;
    int ret;
    PK11SlotInfo *slot = NULL;
    SECItem pwditem = { siBuffer, NULL, 0 };
    SECItem uc2_pwditem = { siBuffer, NULL, 0 };
    SECStatus rv;
    SECKEYPrivateKey *privkey = NULL;
    SECKEYPublicKey *pubkey = NULL;
    CERTCertList *certlist = NULL;
    CERTCertListNode *head = NULL;
    CERTCertificate *cert = NULL;
    CERTCertificate *tmpcert = NULL;
    SEC_PKCS12DecoderContext *p12ctx = NULL;
    const SEC_PKCS12DecoderItem *dip;
    size_t pwdSize;
    xmlSecKeyPtr res = NULL;

    xmlSecAssert2((secItem != NULL), NULL);

    if (pwd == NULL) {
        pwd = "";
    }
    memset(&uc2_pwditem, 0, sizeof(uc2_pwditem));

    /* we're importing a key about which we know nothing yet, just use the
     * internal slot. We have no criteria to choose a slot.
     */
    slot = xmlSecNssGetInternalKeySlot();
    if (slot == NULL) {
        xmlSecInternalError("xmlSecNssGetInternalKeySlot", NULL);
        goto done;
    }

    pwditem.data = (unsigned char *)pwd;
    pwdSize = strlen(pwd) + 1;
    XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(pwdSize, pwditem.len, goto done, NULL);

    if (!SECITEM_AllocItem(NULL, &uc2_pwditem, 2*pwditem.len)) {
        xmlSecNssError("SECITEM_AllocItem", NULL);
        goto done;
    }

    if (PORT_UCS2_ASCIIConversion(PR_TRUE, pwditem.data, pwditem.len,
                              uc2_pwditem.data, 2*pwditem.len,
                              &(uc2_pwditem.len), 0) == PR_FALSE) {
        xmlSecNssError("PORT_UCS2_ASCIIConversion", NULL);
        goto done;
    }

    p12ctx = SEC_PKCS12DecoderStart(&uc2_pwditem, slot, NULL,
                                    NULL, NULL, NULL, NULL, NULL);
    if (p12ctx == NULL) {
        xmlSecNssError("SEC_PKCS12DecoderStart", NULL);
        goto done;
    }

    rv = SEC_PKCS12DecoderUpdate(p12ctx, secItem->data, secItem->len);
    if (rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12DecoderUpdate", NULL);
        goto done;
    }

    rv = SEC_PKCS12DecoderVerify(p12ctx);
    if (rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12DecoderVerify", NULL);
        goto done;
    }

    rv = SEC_PKCS12DecoderValidateBags(p12ctx, xmlSecNssAppNicknameCollisionCallback);
    if (rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12DecoderValidateBags", NULL);
        goto done;
    }

    rv = SEC_PKCS12DecoderImportBags(p12ctx);
    if (rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12DecoderImportBags", NULL);
        goto done;
    }

    certlist = SEC_PKCS12DecoderGetCerts(p12ctx);
    if (certlist == NULL) {
        xmlSecNssError("SEC_PKCS12DecoderGetCerts", NULL);
        goto done;
    }

    x509Data = xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id);
    if(x509Data == NULL) {
        xmlSecInternalError("xmlSecKeyDataCreate(xmlSecNssKeyDataX509Id)", NULL);
        goto done;
    }

    for (head = CERT_LIST_HEAD(certlist); !CERT_LIST_END(head, certlist); head = CERT_LIST_NEXT(head)) {
        cert = head->cert;
        privkey = PK11_FindKeyByAnyCert(cert, NULL);

        if (privkey != NULL) {
            if (keyValueData != NULL) {
                /* we already found a private key.
                 * assume the first private key we find is THE ONE
                 */
                SECKEY_DestroyPrivateKey(privkey);
                privkey = NULL;
                continue;
            }

            pubkey = CERT_ExtractPublicKey(cert);
            if (pubkey == NULL) {
                xmlSecNssError("CERT_ExtractPublicKey", NULL);
                goto done;
            }
            keyValueData = xmlSecNssPKIAdoptKey(privkey, pubkey);
            if(keyValueData == NULL) {
                xmlSecInternalError("xmlSecNssPKIAdoptKey", NULL);
                goto done;
            }

            pubkey = NULL;
            privkey = NULL;

            tmpcert = CERT_DupCertificate(cert);
            if(tmpcert == NULL) {
                xmlSecNssError("CERT_DupCertificate", NULL);
                goto done;
            }

            ret = xmlSecNssKeyDataX509AdoptKeyCert(x509Data, tmpcert);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssKeyDataX509AdoptKeyCert", NULL);
                goto done;
            }
            tmpcert = NULL; /* owned by x509Data now */
        } else {
            tmpcert = CERT_DupCertificate(cert);
            if(tmpcert == NULL) {
                xmlSecNssError("CERT_DupCertificate", NULL);
                goto done;
            }
            ret = xmlSecNssKeyDataX509AdoptCert(x509Data, tmpcert);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssKeyDataX509AdoptCert", NULL);
                goto done;
            }
            tmpcert = NULL; /* owned by x509Data now */
        }
    } /* end for loop */

    if (keyValueData == NULL) {
        /* private key not found in PKCS12 file */
        xmlSecInternalError("xmlSecNssAppPkcs12Load(private key)", NULL);
        goto done;
     }

    /* create key and set key value and x509 data into it */
    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }
    ret = xmlSecKeySetValue(key, keyValueData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        goto done;
    }
    keyValueData = NULL; /* owned by key now */

    ret = xmlSecKeyAdoptData(key, x509Data);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeyAdoptData", NULL);
        goto done;
    }
    x509Data = NULL; /* owned by key now */

    /* try to find key name */
    rv = SEC_PKCS12DecoderIterateInit(p12ctx);
    if (rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12DecoderIterateInit", NULL);
        goto done;
    }
    /* read pkcs12 bags */
    while (SEC_PKCS12DecoderIterateNext(p12ctx, &dip) == SECSuccess) {
         if((dip->friendlyName != NULL) && (dip->friendlyName->data != NULL) && (dip->friendlyName->len > 0) ) {
            ret = xmlSecKeySetNameEx(key, dip->friendlyName->data, dip->friendlyName->len);
            if(ret < 0) {
                xmlSecInternalError("xmlSecKeySetNameEx", NULL);
                goto done;
            }
            /* use the first one */
            break;
         }
    }


    /* success */
    res = key;
    key = NULL;

done:
    if(tmpcert != NULL) {
        CERT_DestroyCertificate(tmpcert);
    }
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    if (p12ctx) {
        SEC_PKCS12DecoderFinish(p12ctx);
    }
    SECITEM_FreeItem(&uc2_pwditem, PR_FALSE);
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (certlist) {
        CERT_DestroyCertList(certlist);
    }
    if(x509Data != NULL) {
        xmlSecKeyDataDestroy(x509Data);
    }
    if(keyValueData != NULL) {
        xmlSecKeyDataDestroy(keyValueData);
    }
    if (privkey) {
        SECKEY_DestroyPrivateKey(privkey);
    }
    if (pubkey) {
        SECKEY_DestroyPublicKey(pubkey);
    }

    return(res);
}

/**
 * xmlSecNssAppKeyFromCertLoadSECItem:
 * @secItem:            the @SECItem object.
 * @format:             the cert format.
 *
 * Loads public key from cert.
 *
 * Returns: pointer to key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyFromCertLoadSECItem(SECItem* secItem, xmlSecKeyDataFormat format) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr keyData = NULL;
    xmlSecKeyDataPtr certData;
    CERTCertificate *cert = NULL;
    int ret;
    xmlSecKeyPtr res = NULL;

    xmlSecAssert2(secItem != NULL, NULL);
    xmlSecAssert2(secItem->type == siBuffer, NULL);
    xmlSecAssert2(secItem->data != NULL, NULL);
    xmlSecAssert2(secItem->len > 0, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    /* load cert */
    switch(format) {
    case xmlSecKeyDataFormatCertDer:
        cert = xmlSecNssX509CertDerRead(CERT_GetDefaultCertDB(), secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            goto done;
        }
        break;
    case xmlSecKeyDataFormatCertPem:
        cert = xmlSecNssX509CertPemRead(CERT_GetDefaultCertDB(), secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertPemRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            goto done;
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        goto done;
    }

    /* get key value */
    keyData = xmlSecNssX509CertGetKey(cert);
    if(keyData == NULL) {
        xmlSecInternalError("xmlSecNssX509CertGetKey", NULL);
        goto done;
    }

    /* create key set key value */
    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecInternalError("xmlSecKeyCreate", NULL);
        goto done;
    }
    ret = xmlSecKeySetValue(key, keyData);
    if(ret < 0) {
        xmlSecInternalError("xmlSecKeySetValue", NULL);
        goto done;
    }
    keyData = NULL; /* owned by key now */

    /* create cert data put key's cert into it */
    certData = xmlSecKeyEnsureData(key, xmlSecNssKeyDataX509Id);
    if(certData == NULL) {
        xmlSecInternalError("xmlSecKeyEnsureData", NULL);
        goto done;
    }
    ret = xmlSecNssKeyDataX509AdoptKeyCert(certData, cert);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKeyDataX509AdoptKeyCert", NULL);
        goto done;
    }
    cert = NULL; /* owned by data now */

    /* success */
    res = key;
    key = NULL;

done:
    if(key != NULL) {
        xmlSecKeyDestroy(key);
    }
    if(keyData != NULL) {
        xmlSecKeyDataDestroy(keyData);
    }
    if(cert != NULL) {
        CERT_DestroyCertificate(cert);
    }
    return(res);
}

/**
 * xmlSecNssAppKeysMngrCertLoad:
 * @mngr:               the pointer to keys manager.
 * @filename:           the certificate file.
 * @format:             the certificate file format (PEM or DER).
 * @type:               the certificate type (trusted/untrusted).
 *
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, const char *filename,
                             xmlSecKeyDataFormat format,
                             xmlSecKeyDataType type) {
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* read the file contents */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppReadSECItem(&secItem, filename);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppReadSECItem", NULL);
        return(-1);
    }

    ret = xmlSecNssAppKeysMngrCertLoadSECItem(mngr, &secItem, format, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppKeysMngrCertLoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(-1);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(0);
}

/**
 * xmlSecNssAppKeysMngrCertLoadMemory:
 * @mngr:               the pointer to keys manager.
 * @data:               the certificatedata.
 * @dataSize:           the certificate data size.
 * @format:             the certificate format (PEM or DER).
 * @type:               the certificate type (trusted/untrusted).
 *
 * Reads cert from @data and adds to the list of trusted or known
 * untrusted certs in @store
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data,
                             xmlSecSize dataSize, xmlSecKeyDataFormat format,
                             xmlSecKeyDataType type) {
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppCreateSECItem(&secItem, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppCreateSECItem", NULL);
        return(-1);
    }

    ret = xmlSecNssAppKeysMngrCertLoadSECItem(mngr, &secItem, format, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppKeysMngrCertLoadSECItem", NULL);
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(-1);
    }

    SECITEM_FreeItem(&secItem, PR_FALSE);
    return(0);
}

/**
 * xmlSecNssAppKeysMngrCertLoadSECItem:
 * @mngr:               the pointer to keys manager.
 * @secItem:            the pointer to SECItem.
 * @format:             the certificate format (PEM or DER).
 * @type:               the certificate type (trusted/untrusted).
 *
 * Reads cert from @secItem and adds to the list of trusted or known
 * untrusted certs in @store
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCertLoadSECItem(xmlSecKeysMngrPtr mngr, SECItem* secItem,
                             xmlSecKeyDataFormat format,
                             xmlSecKeyDataType type) {
    xmlSecKeyDataStorePtr x509Store;
    CERTCertificate* cert;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(secItem != NULL, -1);
    xmlSecAssert2(secItem->type == siBuffer, -1);
    xmlSecAssert2(secItem->data != NULL, -1);
    xmlSecAssert2(secItem->len > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecNssX509StoreId)", NULL);
        return(-1);
    }

    switch(format) {
    case xmlSecKeyDataFormatDer:
        cert = xmlSecNssX509CertDerRead(CERT_GetDefaultCertDB(), secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            return(-1);
        }
        break;
    case xmlSecKeyDataFormatCertPem:
        cert = xmlSecNssX509CertPemRead(CERT_GetDefaultCertDB(), secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertPemRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            return(-1);
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        return(-1);
    }

    ret = xmlSecNssX509StoreAdoptCert(x509Store, cert, type);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509StoreAdoptCert", NULL);
        CERT_DestroyCertificate(cert);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecNssAppKeysMngrCrlLoad:
 * @mngr:               the pointer to keys manager.
 * @filename:           the CRL file.
 * @format:             the CRL file format (PEM or DER).
 *
 * Reads crl from @filename and adds to the list of crls in @store
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCrlLoad(xmlSecKeysMngrPtr mngr, const char *filename, xmlSecKeyDataFormat format) {
    xmlSecKeyDataStorePtr x509Store;
    CERTSignedCrl* crl;
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecNssX509StoreId)", NULL);
        return(-1);
    }

    /* read the file contents */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppReadSECItem(&secItem, filename);
    if((ret < 0) || (secItem.type != siBuffer) ||(secItem.data == NULL) || (secItem.len <= 0)) {
        xmlSecInternalError("xmlSecNssAppReadSECItem", NULL);
        return(-1);
    }

    /* read CRL */
    switch(format) {
    case xmlSecKeyDataFormatDer:
        crl = xmlSecNssX509CrlDerRead(secItem.data, secItem.len, XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecNssX509CrlDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            SECITEM_FreeItem(&secItem, PR_FALSE);
            return(-1);
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(-1);
    }
    SECITEM_FreeItem(&secItem, PR_FALSE);

    /* Add CRL to the store */
    ret = xmlSecNssX509StoreAdoptCrl(x509Store, crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509StoreAdoptCrl", NULL);
        SEC_DestroyCrl(crl);
        return(-1);
    }
    crl = NULL; /* owned by x509data now */

    /* done */
    return(0);
}

/**
 * xmlSecNssAppKeysMngrCrlLoadMemory:
 * @mngr:               the pointer to keys manager.
 * @data:               the CRL data.
 * @dataSize:           the CRL data size.
 * @format:             the CRL format (PEM or DER).
 *
 * Reads crl from @data and adds to the list of crls in @store
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCrlLoadMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format) {
    xmlSecKeyDataStorePtr x509Store;
    CERTSignedCrl* crl;
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecNssX509StoreId)", NULL);
        return(-1);
    }

    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppCreateSECItem(&secItem, data, dataSize);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssAppCreateSECItem", NULL);
        return(-1);
    }

    /* read CRL */
    switch(format) {
    case xmlSecKeyDataFormatDer:
        crl = xmlSecNssX509CrlDerRead(secItem.data, secItem.len, XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecNssX509CrlDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            SECITEM_FreeItem(&secItem, PR_FALSE);
            return(-1);
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        SECITEM_FreeItem(&secItem, PR_FALSE);
        return(-1);
    }
    SECITEM_FreeItem(&secItem, PR_FALSE);

    /* Add CRL to the store */
    ret = xmlSecNssX509StoreAdoptCrl(x509Store, crl);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssX509StoreAdoptCrl", NULL);
        SEC_DestroyCrl(crl);
        return(-1);
    }
    crl = NULL; /* owned by x509data now */

    /* done */
    return(0);
}


#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecNssAppDefaultKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with NSS keys store #xmlSecNssKeysStoreId
 * and a default NSS crypto key data stores.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create NSS keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecNssKeysStoreId);
        if(keysStore == NULL) {
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecNssX509StoreId)", NULL);
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeysMngrAdoptKeysStore", NULL);
            xmlSecKeyStoreDestroy(keysStore);
            return(-1);
        }
    }

    ret = xmlSecNssKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKeysMngrInit", NULL);
        return(-1);
    }

    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecNssAppDefaultKeysMngrAdoptKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecNssAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecNssKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecInternalError("xmlSecNssKeysStoreAdoptKey", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecNssAppDefaultKeysMngrVerifyKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 * @keyInfoCtx:         the key info context for verification.
 *
 * Verifies @key with the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @key to the keys manager @mngr created with #xmlSecCryptoAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
 */
int
xmlSecNssAppDefaultKeysMngrVerifyKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
#ifndef XMLSEC_NO_X509
    xmlSecKeyDataStorePtr x509Store;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecNssX509StoreId)", NULL);
        return(-1);
    }

    return(xmlSecNssX509StoreVerifyKey(x509Store, key, keyInfoCtx));

#else  /* XMLSEC_NO_X509 */

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    xmlSecNotImplementedError("X509 support is disabled");
    return(-1);

#endif /* XMLSEC_NO_X509 */
}

/**
 * xmlSecNssAppDefaultKeysMngrLoad:
 * @mngr:               the pointer to keys manager.
 * @uri:                the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created
 * with #xmlSecNssAppDefaultKeysMngrInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecNssKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecNssKeysStoreLoad", NULL,
                             "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecNssAppDefaultKeysMngrSave:
 * @mngr:               the pointer to keys manager.
 * @filename:           the destination filename.
 * @type:               the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetKeysStore", NULL);
        return(-1);
    }

    ret = xmlSecNssKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecNssKeysStoreSave", NULL,
                             "filename%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecNssAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns: default password callback.
 */
void*
xmlSecNssAppGetDefaultPwdCallback(void) {
    return(NULL);
}
