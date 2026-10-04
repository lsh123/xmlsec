/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
/**
 * @addtogroup xmlsec_nss_app
 * @brief Application support functions for NSS.
 * @details Common functions for the xmlsec1 command-line utility for NSS.
 */
#include "globals.h"

#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <cert.h>
#include <certdb.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <pkcs12.h>
#include <p12plcy.h>

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
static xmlSecKeyPtr     xmlSecNssAppDerKeyLoadSECItem           (SECItem* secItem,
                                                                  const char *pwd,
                                                                  void* pwdCallback,
                                                                  void* pwdCallbackCtx);


#ifndef XMLSEC_NO_X509
static SECItem *xmlSecNssAppNicknameCollisionCallback           (SECItem *old_nick,
                                                                 PRBool *cancel,
                                                                 void *wincx);
#endif /* XMLSEC_NO_X509 */

/* SEC_ASN1_MKSUB() is a no-op on non-Windows platforms, but it is needed
 * when NSS is linked as a DLL (Windows) */
SEC_ASN1_MKSUB(SECOID_AlgorithmIDTemplate)

/*
 * The password callback used by the key and PKCS12 loading functions below.
 * For compatibility with the other backends it has the same signature
 * as the OpenSSL pem_password_cb (a function type, so a pointer to it
 * is a function pointer).
 */
typedef int xmlSecNssAppPwdCallback(char *buf, int bufSize, int verify, void *userdata);

XMLSEC_PTR_TO_FUNC_IMPL(xmlSecNssAppPwdCallback)

/**
 * Resolves the password for the key loading functions. If @p pwd is not
 * NULL, it is used as is (an explicit password wins, even if it is empty).
 * Otherwise, if @p pwdCallback is not NULL, it is called with @p verify set
 * to 0 and the password is expected to be written to @p buf (up to @p bufSize
 * - 1 characters). If neither @p pwd nor @p pwdCallback is given, the empty
 * password "" is used.
 *
 * @param pwd the explicit password or NULL.
 * @param pwdCallback the password callback or NULL; expected to have the
 * type #xmlSecNssAppPwdCallback.
 * @param pwdCallbackCtx the user context for the password callback.
 * @param buf the caller-provided buffer for the callback result.
 * @param bufSize the size of @p buf.
 *
 * @return pointer to the resolved password (either @p pwd itself or @p buf)
 * or NULL if the callback failed.
 */
static const char*
xmlSecNssAppPwdCallbackResolve(const char* pwd, void* pwdCallback,
    void* pwdCallbackCtx, char* buf, int bufSize) {
    xmlSecNssAppPwdCallback *callback = NULL;
    int ret;

    xmlSecAssert2(buf != NULL, NULL);
    xmlSecAssert2(bufSize > 0, NULL);

    if(pwd != NULL) {
        /* an explicit password wins */
        return(pwd);
    }
    if(pwdCallback == NULL) {
        /* no password and no callback */
        buf[0] = '\0';
        return(buf);
    }

    callback = XMLSEC_PTR_TO_FUNC(xmlSecNssAppPwdCallback, pwdCallback);
    ret = callback(buf, bufSize, 0, pwdCallbackCtx);
    if((ret < 0) || (ret >= bufSize)) {
        xmlSecNssError3("pwdCallback", NULL, "ret=%d; bufSize=%d", ret, bufSize);
        return(NULL);
    }
    buf[ret] = '\0';
    return(buf);
}

/*
 * Templates for parsing the PKCS#8 structures used by the encrypted
 * private key import below:
 *
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *      version                   INTEGER { v1(0) } (v1) -- optional,
 *      decryptionAlgorithm       AlgorithmIdentifier,
 *      encryptedData             OCTET STRING
 * }
 *
 * Some encoders (e.g. OpenSSL) omit the "version" field, which has a
 * default value of 0, so it is marked as optional here.
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *      version                   Version,
 *      privateKeyAlgorithm       AlgorithmIdentifier,
 *      privateKey                OCTET STRING
 * }
 */
typedef struct _xmlSecNssEpkiInfo {
    SECItem version;
    SECAlgorithmID algorithm;
    SECItem encryptedData;
} xmlSecNssEpkiInfo;

typedef struct _xmlSecNssPkcs8OuterInfo {
    SECItem version;
    SECAlgorithmID privateKeyAlgorithm;
    SECItem privateKey;
} xmlSecNssPkcs8OuterInfo;

static const SEC_ASN1Template xmlSecNssEpkiTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(xmlSecNssEpkiInfo) },
    { SEC_ASN1_INTEGER | SEC_ASN1_OPTIONAL, offsetof(xmlSecNssEpkiInfo, version), NULL, 0 },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN, offsetof(xmlSecNssEpkiInfo, algorithm),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate), 0 },
    { SEC_ASN1_OCTET_STRING, offsetof(xmlSecNssEpkiInfo, encryptedData), NULL, 0 },
    { 0 }
};

static const SEC_ASN1Template xmlSecNssPkcs8OuterTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(xmlSecNssPkcs8OuterInfo) },
    { SEC_ASN1_INTEGER, offsetof(xmlSecNssPkcs8OuterInfo, version), NULL, 0 },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN, offsetof(xmlSecNssPkcs8OuterInfo, privateKeyAlgorithm),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate), 0 },
    { SEC_ASN1_OCTET_STRING, offsetof(xmlSecNssPkcs8OuterInfo, privateKey), NULL, 0 },
    { 0 }
};

/*
 * Imports the encrypted PKCS#8 private key described by @p epki into @p slot
 * using the non-NUL-terminated password @p pwditem. The key type cannot be
 * determined from the EncryptedPrivateKeyInfo structure, so the encrypted
 * data is first decrypted with the password-derived PBE key into an opaque
 * generic secret key; the resulting PKCS#8 DER is then imported with
 * PK11_ImportDERPrivateKeyInfoAndReturnKey, which derives the key type from
 * the inner PKCS#8 algorithm OID.
 *
 * The PK11_ImportEncryptedPrivateKeyInfoAndReturnKey() API is not used here:
 * it relies on PK11_UnwrapPrivKey, which (on NSS 3.120 and earlier) rejects
 * a NULL public value, and a PKCS#8 container does not contain the public
 * key.
 *
 * Returns 0 on success (with @p privkey set) or -1 on failure (the failing
 * NSS call is reported).
 */
static int
xmlSecNssAppImportEpkiKey(PK11SlotInfo* slot, SECKEYEncryptedPrivateKeyInfo* epki,
    SECItem* pwditem, SECKEYPrivateKey** privkey) {
    PK11SymKey* pbeKey = NULL;
    PK11SymKey* symKey = NULL;
    SECItem* param = NULL;
    SECItem nickname = { siBuffer, NULL, 0 };
    SECItem derPKI;
    SECItem* keyData;
    CK_MECHANISM_TYPE mech;
    SECStatus rv;
    int res = -1;

    xmlSecAssert2(slot != NULL, -1);
    xmlSecAssert2(epki != NULL, -1);
    xmlSecAssert2(pwditem != NULL, -1);
    xmlSecAssert2(privkey != NULL, -1);
    xmlSecAssert2(*privkey == NULL, -1);

    /* derive the PBE symmetric key from the password */
    pbeKey = PK11_PBEKeyGen(slot, &epki->algorithm, pwditem, PR_FALSE, NULL);
    if(pbeKey == NULL) {
        xmlSecNssError("PK11_PBEKeyGen", NULL);
        return(-1);
    }

    /* get the cipher mechanism and its parameters (e.g. the IV) for the
     * PBE scheme */
    mech = PK11_GetPBECryptoMechanism(&epki->algorithm, &param, pwditem);
    if((mech == CKM_INVALID_MECHANISM) || (param == NULL)) {
        xmlSecNssError("PK11_GetPBECryptoMechanism", NULL);
        goto done;
    }
    mech = PK11_GetPadMechanism(mech);

    /* decrypt the encrypted data into an opaque generic secret key; the
     * key size is not known up front, so let NSS use the actual
     * (decrypted) length */
    symKey = PK11_UnwrapSymKey(pbeKey, mech, param, &epki->encryptedData,
        CKM_GENERIC_SECRET_KEY_GEN, CKA_DECRYPT, 0);
    if(symKey == NULL) {
        xmlSecNssError("PK11_UnwrapSymKey", NULL);
        goto done;
    }

    rv = PK11_ExtractKeyValue(symKey);
    if(rv != SECSuccess) {
        xmlSecNssError("PK11_ExtractKeyValue", NULL);
        goto done;
    }
    keyData = PK11_GetKeyData(symKey);
    if((keyData == NULL) || (keyData->data == NULL) || (keyData->len == 0)) {
        xmlSecInternalError("PK11_GetKeyData", NULL);
        goto done;
    }
    derPKI.data = keyData->data;
    derPKI.len = keyData->len;

    rv = PK11_ImportDERPrivateKeyInfoAndReturnKey(slot, &derPKI, &nickname,
        NULL, PR_FALSE, PR_TRUE, KU_ALL, privkey, NULL);
    if(rv != SECSuccess) {
        /* the decrypted data is not a valid PKCS#8 container (a wrong
         * password usually fails earlier, in PK11_UnwrapSymKey) */
        xmlSecNssError("PK11_ImportDERPrivateKeyInfoAndReturnKey", NULL);
        goto done;
    }

    res = 0;

done:
    if(symKey != NULL) {
        PK11_FreeSymKey(symKey);
    }
    if(param != NULL) {
        SECITEM_FreeItem(param, PR_TRUE);
    }
    if(pbeKey != NULL) {
        PK11_FreeSymKey(pbeKey);
    }
    return(res);
}

/* Imports an encrypted PKCS#8 private key from @p derItem into @p slot.
 * @p derItem may be either a bare EncryptedPrivateKeyInfo (the layout
 * produced by "openssl pkcs8 -topk8 -v2 <algorithm>") or a PrivateKeyInfo
 * container with the inner EncryptedPrivateKeyInfo stored in the
 * "privateKey" OCTET STRING. The container layout is detected first: its
 * version field is mandatory, whereas the version field of the
 * EncryptedPrivateKeyInfo template is optional, so the bare-EPKI template
 * would otherwise also match the container and the import would fail with
 * the (non-PBE) container algorithm. Returns 0 if the key was imported
 * (and @p privkey was set), 1 if @p derItem is not a PKCS#8 container (the
 * caller may try the SubjectPublicKeyInfo path), and -1 if @p derItem is a
 * PKCS#8 container but the import failed (e.g. wrong password or an
 * unsupported algorithm). */
static int
xmlSecNssAppImportEncryptedPkcs8Key(PK11SlotInfo* slot, SECItem* derItem,
    const char* resolvedPwd, SECKEYPrivateKey** privkey) {
    xmlSecNssEpkiInfo epkiInfo;
    xmlSecNssPkcs8OuterInfo outer;
    SECKEYEncryptedPrivateKeyInfo epki;
    PLArenaPool* arena = NULL;
    SECItem pwditem = { siBuffer, NULL, 0 };
    SECStatus rv;
    size_t pwdSize;
    int res = -1;

    xmlSecAssert2(slot != NULL, -1);
    xmlSecAssert2(derItem != NULL, -1);
    xmlSecAssert2(resolvedPwd != NULL, -1);
    xmlSecAssert2(privkey != NULL, -1);
    xmlSecAssert2(*privkey == NULL, -1);

    /* the password item passed to NSS must NOT be NUL-terminated */
    pwdSize = strlen(resolvedPwd);
    XMLSEC_SAFE_CAST_SIZE_T_TO_UINT(pwdSize, pwditem.len, goto done, NULL);
    pwditem.data = (unsigned char*)resolvedPwd;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if(arena == NULL) {
        xmlSecNssError("PORT_NewArena", NULL);
        goto done;
    }

    /* try to parse the item as a PrivateKeyInfo container with the inner
     * EncryptedPrivateKeyInfo stored in the "privateKey" OCTET STRING. The
     * container template has a mandatory version field, so a bare
     * EncryptedPrivateKeyInfo without a version field can never match it.
     * A versioned bare EncryptedPrivateKeyInfo does match it structurally,
     * but in that case the "privateKey" content is not a valid
     * EncryptedPrivateKeyInfo and the fall-through below handles it */
    memset(&outer, 0, sizeof(outer));
    rv = SEC_QuickDERDecodeItem(arena, &outer, xmlSecNssPkcs8OuterTemplate, derItem);
    if(rv == SECSuccess) {
        memset(&epkiInfo, 0, sizeof(epkiInfo));
        rv = SEC_QuickDERDecodeItem(arena, &epkiInfo, xmlSecNssEpkiTemplate,
            &outer.privateKey);
        if(rv == SECSuccess) {
            goto import;
        }
        /* the "privateKey" content is not an EncryptedPrivateKeyInfo; the
         * whole item itself might still be one, so fall through */
    }

    /* try to parse the whole item as an EncryptedPrivateKeyInfo */
    memset(&epkiInfo, 0, sizeof(epkiInfo));
    rv = SEC_QuickDERDecodeItem(arena, &epkiInfo, xmlSecNssEpkiTemplate, derItem);
    if(rv == SECSuccess) {
        goto import;
    }

    /* not a PKCS#8 container; the caller may try the SubjectPublicKeyInfo
     * path */
    res = 1;
    goto done;

import:
    memset(&epki, 0, sizeof(epki));
    epki.algorithm = epkiInfo.algorithm;
    epki.encryptedData = epkiInfo.encryptedData;
    res = xmlSecNssAppImportEpkiKey(slot, &epki, &pwditem, privkey);
    if(res != 0) {
        xmlSecNssError2("xmlSecNssAppImportEncryptedPkcs8Key", NULL,
            "failed to import encrypted PKCS#8 private key: %s",
            "wrong password, bad data, or unsupported encryption algorithm");
        goto done;
    }

done:
    if(arena != NULL) {
        PORT_FreeArena(arena, PR_TRUE);
    }
    return(res);
}

/**
 * @brief Initializes the NSS crypto engine.
 * @details General crypto engine initialization. This function is used
 * by the XMLSec command-line utility and is called before the
 * #xmlSecInit function.
 *
 * @param config the path to NSS database files.
 * @return 0 on success or a negative value otherwise.
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

    /* setup for PKCS12, only 3DES is explicitly enabled for compatibility with older
     * PKCS#12 files; report errors but do not fail since the cipher might have been
     * disabled by NSS policy */
    PORT_SetUCS2_ASCIIConversionFunction(xmlSecNssAppAscii2UCS2Conv);
    rv = SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
    if(rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168)", NULL);
    }
    rv = SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);
    if(rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168)", NULL);
    }
    rv = SEC_PKCS12SetPreferredCipher(PKCS12_AES_CBC_128, 1);
    if(rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12SetPreferredCipher(PKCS12_AES_CBC_128)", NULL);
    }
    rv = SEC_PKCS12SetPreferredCipher(PKCS12_AES_CBC_192, 1);
    if(rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12SetPreferredCipher(PKCS12_AES_CBC_192)", NULL);
    }
    rv = SEC_PKCS12SetPreferredCipher(PKCS12_AES_CBC_256, 1);
    if(rv != SECSuccess) {
        xmlSecNssError("SEC_PKCS12SetPreferredCipher(PKCS12_AES_CBC_256)", NULL);
    }

    /* done */
    return(0);
}

/**
 * @brief Shuts down the NSS crypto engine.
 * @details General crypto engine shutdown. This function is used
 * by the XMLSec command-line utility and is called after the
 * #xmlSecShutdown function.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppShutdown(void) {
    SECStatus rv;
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
    /*
     * info.size is PROffset32 (int) in this NSPR; check that it fits into
     * unsigned int (the limit for a single PR_Read call and for the
     * SECItem.len field).
     */
    XMLSEC_SAFE_CAST_INT_TO_UINT(info.size, ulen, goto done, NULL);

    contents->data = 0;
    if (!SECITEM_AllocItem(NULL, contents, ulen)) {
        xmlSecNssError("SECITEM_AllocItem", NULL);
        goto done;
    }

    numBytes = PR_Read(file, contents->data, (PRInt32)ulen);
    if (numBytes != (PRInt32)ulen) {
        xmlSecNssError2("PR_Read", NULL,
                        "filename=%s", xmlSecErrorsSafeString(fn));
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
                           PRBool         swapBytes XMLSEC_ATTRIBUTE_UNUSED)
{
    SECItem it = { siBuffer, NULL, 0 };

    if (toUnicode == PR_FALSE) {
        return (PR_FALSE);
    }

    it.data = inBuf;
    it.len = inBufLen;

    return(PORT_UCS2_UTF8Conversion(toUnicode, it.data, it.len,
                                    outBuf, maxOutBufLen, outBufLen));
}

#ifndef XMLSEC_NO_X509
/* rename certificate if needed */
static SECItem *
xmlSecNssAppNicknameCollisionCallback(SECItem *old_nick XMLSEC_ATTRIBUTE_UNUSED,
    PRBool *cancel, void *wincx
) {
    CERTCertificate *cert = (CERTCertificate *)wincx;
    char *nick = NULL;
    SECItem *ret_nick = NULL;

    if((cancel == NULL) || (cert == NULL)) {
        xmlSecNssError("cert is missing", NULL);
        return(NULL);
    }

    /*
     * NSS's sec_pkcs12_validate_cert_nickname() (lib/pkcs12/p12d.c) loops
     * until the nickname returned by this callback no longer collides with
     * an existing certificate nickname. This callback is safe with respect
     * to that loop: CERT_MakeCANickname() (lib/certdb/certdb.c) itself
     * appends a " #N" suffix until the nickname is free in the certificate
     * database, and NSS checks for collisions against the same default
     * certificate database (sec_pkcs12_certs_for_nickname_exist() calls
     * PK11_TraverseCertsForNicknameInSlot() on the internal slot, see
     * lib/pk11wrap/pk11cert.c). Hence the returned nickname never collides
     * and the loop always terminates; even if a certificate with the same
     * nickname were added concurrently, the callback would simply be
     * invoked again and produce a new, collision-free nickname.
     */
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
 * @brief Reads a key from a file.
 * @param filename the key filename.
 * @param type the key type (public / private).
 * @param format the key file format.
 * @param pwd the key file password, or NULL to use the password callback.
 * @param pwdCallback the key password callback (used only when @p pwd is NULL)
 * or NULL; expected to have the signature
 * int (*callback)(char* buf, int bufSize, int verify, void* userdata), called
 * with verify set to 0.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyLoadEx(const char *filename, xmlSecKeyDataType type XMLSEC_ATTRIBUTE_UNUSED, xmlSecKeyDataFormat format,
    const char *pwd, void* pwdCallback, void* pwdCallbackCtx
) {
    SECItem secItem = { siBuffer, NULL, 0 };
    xmlSecKeyPtr res;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);
    XMLSEC_UNREFERENCED(type);

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
 * @brief Reads a key from the binary @p data.
 * @param data the key binary data.
 * @param dataSize the key binary data size.
 * @param format the key data format.
 * @param pwd the key data password, or NULL to use the password callback.
 * @param pwdCallback the key password callback (used only when @p pwd is NULL)
 * or NULL; expected to have the signature
 * int (*callback)(char* buf, int bufSize, int verify, void* userdata), called
 * with verify set to 0.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
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
 * @brief Reads a key from a SECItem.
 * @param secItem the pointer to sec item.
 * @param format the key format.
 * @param pwd the key password, or NULL to use the password callback.
 * @param pwdCallback the key password callback (used only when @p pwd is NULL)
 * or NULL; expected to have the signature
 * int (*callback)(char* buf, int bufSize, int verify, void* userdata), called
 * with verify set to 0.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
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
    case xmlSecKeyDataFormatPkcs8Der:
        key = xmlSecNssAppDerKeyLoadSECItem(secItem, pwd, pwdCallback, pwdCallbackCtx);
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
xmlSecNssAppDerKeyLoadSECItem(SECItem* secItem, const char *pwd,
    void* pwdCallback, void* pwdCallbackCtx) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyPtr retval = NULL;
    xmlSecKeyDataPtr data = NULL;
    const char* resolvedPwd = NULL;
    char pwdBuf[2048];
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

    resolvedPwd = xmlSecNssAppPwdCallbackResolve(pwd, pwdCallback, pwdCallbackCtx,
        pwdBuf, (int)sizeof(pwdBuf));
    if(resolvedPwd == NULL) {
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
        /* the data is not a plain (unencrypted) PKCS#8 private key;
         * if a password is available, try to import an encrypted
         * PKCS#8 private key */
        ret = xmlSecNssAppImportEncryptedPkcs8Key(slot, secItem, resolvedPwd, &privkey);
        if(ret < 0) {
            /* the data is a PKCS#8 container and the import failed; the
             * error was reported by the helper, so do not try the
             * public key path */
            goto done;
        }

        if(ret != 0) {
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

#ifndef XMLSEC_NO_X509
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

    /* get cert's pubkey and its der encoding */
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

/**
 * @brief Reads the certificate from a file and adds to key.
 * @details Reads the certificate from @p filename and adds it to key.
 *
 * @param key the pointer to key.
 * @param filename the certificate filename.
 * @param format the certificate file format.
 * @return 0 on success or a negative value otherwise.
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
 * @brief Reads the certificate from memory and adds to key.
 * @details Reads the certificate from @p data and adds it to key.
 *
 * @param key the pointer to key.
 * @param data the key binary data.
 * @param dataSize the key binary data size.
 * @param format the certificate format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeyCertLoadMemory(xmlSecKeyPtr key, const xmlSecByte* data, xmlSecSize dataSize, xmlSecKeyDataFormat format) {
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;

    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* build the SECItem from the in-memory data */
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
 * @brief Reads a certificate from SECItem and adds to key.
 * @details Reads the certificate from @p secItem and adds it to key.
 *
 * @param key the pointer to key.
 * @param secItem the pointer to SECItem.
 * @param format the certificate format.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeyCertLoadSECItem(xmlSecKeyPtr key, SECItem* secItem, xmlSecKeyDataFormat format) {
    CERTCertDBHandle *certDb;
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

    certDb = CERT_GetDefaultCertDB();
    if(certDb == NULL) {
        xmlSecNssError("CERT_GetDefaultCertDB", NULL);
        goto done;
    }

    /* read cert */
    switch(format) {
    case xmlSecKeyDataFormatDer:
    case xmlSecKeyDataFormatCertDer:
        cert = xmlSecNssX509CertDerRead(certDb, secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            goto done;
        }
        break;
    case xmlSecKeyDataFormatPem:
    case xmlSecKeyDataFormatCertPem:
        cert = xmlSecNssX509CertPemRead(certDb, secItem->data, secItem->len);
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
 * @brief Reads key and certificates from PKCS12 file.
 * @details Reads a key and all associated certificates from the PKCS12 file.
 * For uniformity, call #xmlSecNssAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * @param filename the PKCS12 key filename.
 * @param pwd the PKCS12 file password, or NULL to use the password callback.
 * @param pwdCallback the password callback (used only when @p pwd is NULL)
 * or NULL; expected to have the signature
 * int (*callback)(char* buf, int bufSize, int verify, void* userdata), called
 * with verify set to 0.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppPkcs12Load(const char *filename, const char *pwd,
                       void *pwdCallback,
                       void* pwdCallbackCtx) {
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
 * @brief Reads key and certs from PKCS12 binary data.
 * @details Reads a key and all associated certificates from the PKCS12 binary data.
 * For uniformity, call #xmlSecNssAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * @param data the key binary data.
 * @param dataSize the key binary data size.
 * @param pwd the PKCS12 password, or NULL to use the password callback.
 * @param pwdCallback the password callback (used only when @p pwd is NULL)
 * or NULL; expected to have the signature
 * int (*callback)(char* buf, int bufSize, int verify, void* userdata), called
 * with verify set to 0.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize, const char *pwd,
                       void *pwdCallback,
                       void* pwdCallbackCtx) {
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
 * @brief Reads key and certs from PKCS12 SECItem.
 * @details Reads a key and all associated certificates from the PKCS12 SECItem.
 * For uniformity, call #xmlSecNssAppKeyLoadEx instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * @param secItem the SECItem object.
 * @param pwd the PKCS12 file password, or NULL to use the password callback.
 * @param pwdCallback the password callback (used only when @p pwd is NULL)
 * or NULL; expected to have the signature
 * int (*callback)(char* buf, int bufSize, int verify, void* userdata), called
 * with verify set to 0.
 * @param pwdCallbackCtx the user context for password callback.
 * @return pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppPkcs12LoadSECItem(SECItem* secItem, const char *pwd,
                       void *pwdCallback,
                       void* pwdCallbackCtx) {
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
    const char* resolvedPwd = NULL;
    char pwdBuf[2048];
    xmlSecKeyPtr res = NULL;

    xmlSecAssert2((secItem != NULL), NULL);

    resolvedPwd = xmlSecNssAppPwdCallbackResolve(pwd, pwdCallback, pwdCallbackCtx,
        pwdBuf, (int)sizeof(pwdBuf));
    if(resolvedPwd == NULL) {
        goto done;
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

    pwditem.data = (unsigned char *)resolvedPwd;
    pwdSize = strlen(resolvedPwd) + 1;
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

    /*
     * NOTE: from this point on, the private key and the certificates from
     * the PKCS12 file have been persisted into the NSS token and
     * certificate database. NSS installs them permanently:
     * sec_pkcs12_add_key() calls PK11_ImportPrivateKeyInfo() /
     * PK11_ImportEncryptedPrivateKeyInfo() with isPerm=PR_TRUE, and
     * sec_pkcs12_add_cert() calls PK11_ImportCertForKeyToSlot() /
     * CERT_ImportCerts() with isPerm=PR_TRUE (see lib/pkcs12/p12d.c in the
     * NSS source), and SEC_PKCS12DecoderFinish() only frees the decoder's
     * internal memory; it does not remove the imported objects.
     *
     * If any step below fails, this function returns NULL but the imported
     * key material remains in the NSS database. No rollback is performed
     * because the imported objects cannot be identified unambiguously
     * without a pre-import snapshot of the token/cert database: when the
     * same file is imported a second time, PK11_ImportCert() rejects the
     * already present certificate with SEC_ERROR_REUSED_ISSUER_AND_SERIAL
     * while CERT_ImportCerts() silently ignores that failure (see
     * lib/certdb/certdb.c and lib/certdb/stanpcertdb.c in the NSS source),
     * and PK11_FindKeyByAnyCert() may return a pre-existing key with the
     * same public key. Deleting such pre-existing objects would destroy the
     * user's existing key material, which is worse than leaving the
     * orphaned import behind. This matches NSS's non-transactional PKCS12
     * import design.
     */

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

        if((privkey != NULL) && (keyValueData == NULL)) {
            /* we found THE private key: the first private key we find is THE ONE */
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
            if(privkey != NULL) {
                /* we already found a private key.
                 * assume the first private key we find is THE ONE
                 */
                SECKEY_DestroyPrivateKey(privkey);
                privkey = NULL;
            }

            /* add the cert to the x509 data as a regular cert: either this
             * cert has no private key, or its private key was not used
             * because the first private key already won; in both cases the
             * cert itself is still kept so that no cert from the file is
             * dropped
             */
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
    SECITEM_ZfreeItem(&uc2_pwditem, PR_FALSE);
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
 * @brief Loads public key from cert.
 * @param secItem the SECItem object.
 * @param format the cert format.
 * @return pointer to key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecNssAppKeyFromCertLoadSECItem(SECItem* secItem, xmlSecKeyDataFormat format) {
    CERTCertDBHandle *certDb;
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

    certDb = CERT_GetDefaultCertDB();
    if(certDb == NULL) {
        xmlSecNssError("CERT_GetDefaultCertDB", NULL);
        goto done;
    }

    /* load cert */
    switch(format) {
    case xmlSecKeyDataFormatCertDer:
        cert = xmlSecNssX509CertDerRead(certDb, secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            goto done;
        }
        break;
    case xmlSecKeyDataFormatCertPem:
        cert = xmlSecNssX509CertPemRead(certDb, secItem->data, secItem->len);
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
 * @brief Reads a cert from a file and adds to the key store.
 * @details Reads cert from @p filename and adds to the list of trusted or known
 * untrusted certs in @p store.
 *
 * @param mngr the pointer to keys manager.
 * @param filename the certificate file.
 * @param format the certificate file format (PEM or DER).
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value otherwise.
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
 * @brief Reads cert from buffer and adds to the key store.
 * @details Reads cert from @p data and adds to the list of trusted or known
 * untrusted certs in @p store.
 *
 * @param mngr the pointer to keys manager.
 * @param data the certificate data.
 * @param dataSize the certificate data size.
 * @param format the certificate format (PEM or DER).
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value otherwise.
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
 * @brief Reads cert from SECItem and adds to the key store.
 * @details Reads cert from @p secItem and adds to the list of trusted or known
 * untrusted certs in @p store.
 *
 * @param mngr the pointer to keys manager.
 * @param secItem the pointer to SECItem.
 * @param format the certificate format (PEM or DER).
 * @param type the certificate type (trusted/untrusted).
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCertLoadSECItem(
    xmlSecKeysMngrPtr mngr,
    SECItem* secItem,
    xmlSecKeyDataFormat format,
    xmlSecKeyDataType type
) {
    CERTCertDBHandle *certDb;
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

    certDb = CERT_GetDefaultCertDB();
    if(certDb == NULL) {
        xmlSecNssError("CERT_GetDefaultCertDB", NULL);
        return(-1);
    }

    switch(format) {
    case xmlSecKeyDataFormatDer:
    case xmlSecKeyDataFormatCertDer:
        cert = xmlSecNssX509CertDerRead(certDb, secItem->data, secItem->len);
        if(cert == NULL) {
            xmlSecInternalError2("xmlSecNssX509CertDerRead", NULL,
                "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
            return(-1);
        }
        break;
    case xmlSecKeyDataFormatPem:
    case xmlSecKeyDataFormatCertPem:
        cert = xmlSecNssX509CertPemRead(certDb, secItem->data, secItem->len);
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
 * @brief Reads CRLs from a file and adds to the store.
 * @details Reads crl from @p filename and adds to the list of crls in @p store.
 *
 * @param mngr the pointer to keys manager.
 * @param filename the CRL file.
 * @param format the CRL file format (DER; NSS has no API to decode PEM CRLs).
 * @return 0 on success or a negative value otherwise.
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
    if((ret < 0) || (secItem.type != siBuffer) || (secItem.data == NULL) || (secItem.len <= 0)) {
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
    crl = NULL; /* owned by x509Store now */

    /* done */
    return(0);
}

/**
 * @brief Loads and verifies a CRL from a file.
 * @details Atomically loads and verifies a CRL from @p filename.
 *
 * @param mngr the keys manager.
 * @param filename the CRL filename.
 * @param format the CRL format (DER; NSS has no API to decode PEM CRLs).
 * @param keyInfoCtx the key info context for verification parameters.
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecNssAppKeysMngrCrlLoadAndVerify(xmlSecKeysMngrPtr mngr, const char *filename,
    xmlSecKeyDataFormat format, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyDataStorePtr x509Store;
    CERTSignedCrl* crl = NULL;
    SECItem secItem = { siBuffer, NULL, 0 };
    int ret;
    int res = -1;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* Get X509 store from keys manager */
    x509Store = xmlSecKeysMngrGetDataStore(mngr, xmlSecNssX509StoreId);
    if(x509Store == NULL) {
        xmlSecInternalError("xmlSecKeysMngrGetDataStore(xmlSecNssX509StoreId)", NULL);
        return(-1);
    }

    /* Load CRL from file ONCE */
    memset(&secItem, 0, sizeof(secItem));
    ret = xmlSecNssAppReadSECItem(&secItem, filename);
    if((ret < 0) || (secItem.type != siBuffer) || (secItem.data == NULL) || (secItem.len <= 0)) {
        xmlSecInternalError2("xmlSecNssAppReadSECItem", NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        goto done;
    }

    /* Read CRL from memory. Strict import-time checks are skipped on purpose because
     * the CRL is verified explicitly below via xmlSecNssX509StoreVerifyCrl. */
    switch(format) {
    case xmlSecKeyDataFormatDer:
        crl = xmlSecNssX509CrlDerRead(secItem.data, secItem.len, XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS);
        if(crl == NULL) {
            xmlSecInternalError2("xmlSecNssX509CrlDerRead", NULL,
                "filename=%s", xmlSecErrorsSafeString(filename));
            goto done;
        }
        break;
    default:
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_FORMAT, NULL,
            "format=" XMLSEC_ENUM_FMT, XMLSEC_ENUM_CAST(format));
        goto done;
    }

    /* Verify the in-memory CRL */
    ret = xmlSecNssX509StoreVerifyCrl(x509Store, crl, keyInfoCtx);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecNssX509StoreVerifyCrl", NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        goto done;
    } else if(ret != 1) {
        /* Verification failed - treat as error */
        xmlSecOtherError2(XMLSEC_ERRORS_R_INVALID_DATA, NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        goto done;
    }

    /* Adopt the verified in-memory CRL */
    ret = xmlSecNssX509StoreAdoptCrl(x509Store, crl);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecNssX509StoreAdoptCrl", NULL,
            "filename=%s", xmlSecErrorsSafeString(filename));
        goto done;
    }

    /* Success - CRL is now owned by store, don't free it */
    crl = NULL;
    res = 0;

done:
    SECITEM_FreeItem(&secItem, PR_FALSE);
    if(crl != NULL) {
        SEC_DestroyCrl(crl);
    }
    return(res);
}

/**
 * @brief Reads CRLs from memory and adds to the store.
 * @details Reads crl from @p data and adds to the list of crls in @p store.
 *
 * @param mngr the pointer to keys manager.
 * @param data the CRL data.
 * @param dataSize the CRL data size.
 * @param format the CRL format (DER; NSS has no API to decode PEM CRLs).
 * @return 0 on success or a negative value otherwise.
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
    crl = NULL; /* owned by x509Store now */

    /* done */
    return(0);
}


#endif /* XMLSEC_NO_X509 */

/**
 * @brief Initializes the default key manager for NSS.
 * @details Initializes @p mngr with NSS keys store #xmlSecNssKeysStoreId
 * and a default NSS crypto key data stores.
 *
 * @param mngr the pointer to keys manager.
 * @return 0 on success or a negative value otherwise.
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
            xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecNssKeysStoreId)", NULL);
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
 * @brief Adds @p key to the keys manager.
 * @details Adds @p key to the keys manager @p mngr created with #xmlSecNssAppDefaultKeysMngrInit
 * function.
 *
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @return 0 on success or a negative value otherwise.
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
 * @brief Verifies @p key using the keys manager.
 * @details Verifies @p key with the keys manager @p mngr created with #xmlSecNssAppDefaultKeysMngrInit
 * function:
 * - Checks that key certificate is present
 * - Checks that key certificate is valid
 *
 * Adds @p key to the keys manager @p mngr created with #xmlSecNssAppDefaultKeysMngrInit
 * function.
 *
 * @param mngr the pointer to keys manager.
 * @param key the pointer to key.
 * @param keyInfoCtx the key info context for verification.
 * @return 1 if key is verified, 0 otherwise, or a negative value if an error occurs.
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

    xmlSecNotImplementedError("X509 support is disabled during compilation");
    return(-1);

#endif /* XMLSEC_NO_X509 */
}

/**
 * @brief Loads the XML keys file into the keys manager.
 * @details Loads XML keys file from @p uri to the keys manager @p mngr created
 * with #xmlSecNssAppDefaultKeysMngrInit function.
 *
 * @param mngr the pointer to keys manager.
 * @param uri the uri.
 * @return 0 on success or a negative value otherwise.
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
 * @brief Saves keys from @p mngr to XML keys file.
 * @param mngr the pointer to keys manager.
 * @param filename the destination filename.
 * @param type the type of keys to save (public/private/symmetric).
 * @return 0 on success or a negative value otherwise.
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
                             "filename=%s", xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * @brief Gets default password callback.
 *
 * @return default password callback.
 */
void*
xmlSecNssAppGetDefaultPwdCallback(void) {
    /* the key loading functions (e.g. xmlSecNssAppKeyLoadEx) accept a
     * password callback; the NSS backend does not provide a default
     * callback, so callers must supply their own
     */
    return(NULL);
}
