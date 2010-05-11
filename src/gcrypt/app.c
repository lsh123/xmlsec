/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gcrypt/app.h>
#include <xmlsec/gcrypt/crypto.h>

/**************************************************************************
 *
 * ASN.1 parser is taken from GCrypt tests
 *
 *************************************************************************/

/* ASN.1 classes.  */
enum
{
  UNIVERSAL = 0,
  APPLICATION = 1,
  ASNCONTEXT = 2,
  PRIVATE = 3
};


/* ASN.1 tags.  */
enum
{
  TAG_NONE = 0,
  TAG_BOOLEAN = 1,
  TAG_INTEGER = 2,
  TAG_BIT_STRING = 3,
  TAG_OCTET_STRING = 4,
  TAG_NULL = 5,
  TAG_OBJECT_ID = 6,
  TAG_OBJECT_DESCRIPTOR = 7,
  TAG_EXTERNAL = 8,
  TAG_REAL = 9,
  TAG_ENUMERATED = 10,
  TAG_EMBEDDED_PDV = 11,
  TAG_UTF8_STRING = 12,
  TAG_REALTIVE_OID = 13,
  TAG_SEQUENCE = 16,
  TAG_SET = 17,
  TAG_NUMERIC_STRING = 18,
  TAG_PRINTABLE_STRING = 19,
  TAG_TELETEX_STRING = 20,
  TAG_VIDEOTEX_STRING = 21,
  TAG_IA5_STRING = 22,
  TAG_UTC_TIME = 23,
  TAG_GENERALIZED_TIME = 24,
  TAG_GRAPHIC_STRING = 25,
  TAG_VISIBLE_STRING = 26,
  TAG_GENERAL_STRING = 27,
  TAG_UNIVERSAL_STRING = 28,
  TAG_CHARACTER_STRING = 29,
  TAG_BMP_STRING = 30
};

/* ASN.1 Parser object.  */
struct tag_info
{
  int class;             /* Object class.  */
  unsigned long tag;     /* The tag of the object.  */
  unsigned long length;  /* Length of the values.  */
  int nhdr;              /* Length of the header (TL).  */
  unsigned int ndef:1;   /* The object has an indefinite length.  */
  unsigned int cons:1;   /* This is a constructed object.  */
};

/* Parse the buffer at the address BUFFER which consists of the number
   of octets as stored at BUFLEN.  Return the tag and the length part
   from the TLV triplet.  Update BUFFER and BUFLEN on success.  Checks
   that the encoded length does not exhaust the length of the provided
   buffer. */
static int
parse_tag (xmlSecByte const **buffer, xmlSecSize *buflen, struct tag_info *ti)
{
  int c;
  unsigned long tag;
  const xmlSecByte *buf = *buffer;
  xmlSecSize length = *buflen;

  xmlSecAssert2(buffer != NULL, -1);
  xmlSecAssert2((*buffer) != NULL, -1);
  xmlSecAssert2(buflen != NULL, -1);
  xmlSecAssert2(ti != NULL, -1);

  ti->length = 0;
  ti->ndef = 0;
  ti->nhdr = 0;

  /* Get the tag */
  if (length <= 0) {
    return(-1); /* Premature EOF.  */
  }
  c = *buf++; 
  length--;
  ti->nhdr++;

  ti->class = (c & 0xc0) >> 6;
  ti->cons  = !!(c & 0x20);
  tag       = (c & 0x1f);

  if (tag == 0x1f) {
      tag = 0;
      do {
          tag <<= 7;
          if (length <= 0) {
            return(-1); /* Premature EOF.  */
          }
          c = *buf++; 
          length--;
          ti->nhdr++;
          tag |= (c & 0x7f);
      } while ( (c & 0x80) );
  }
  ti->tag = tag;

  /* Get the length */
  if(length <= 0) {
    return -1; /* Premature EOF. */
  }
  c = *buf++; 
  length--;
  ti->nhdr++;

  if ( !(c & 0x80) ) {
    ti->length = c;
  } else if (c == 0x80) {
    ti->ndef = 1;
  } else if (c == 0xff) {
    return -1; /* Forbidden length value.  */
  } else {
      xmlSecSize len = 0;
      int count = c & 0x7f;

      for (; count; count--) {
          len <<= 8;
          if (length <= 0) {
            return -1; /* Premature EOF.  */
          }
          c = *buf++; length--;
          ti->nhdr++;
          len |= (c & 0xff);
      }
      ti->length = len;
    }

  if (ti->class == UNIVERSAL && !ti->tag) {
    ti->length = 0;\
  }

  if (ti->length > length) {
    return(-1); /* Data larger than buffer.  */
  }

  *buffer = buf;
  *buflen = length;
  return(0);
}

static xmlSecKeyDataPtr
read_private_key_file (const xmlSecByte * der, xmlSecSize derlen) {
  xmlSecKeyDataPtr key_data = NULL;
  gcry_sexp_t s_key = NULL;
  gcry_error_t err;
  struct tag_info ti;
  gcry_mpi_t keyparms[8] = {
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL
  } ;
  int n_keyparms = 8;
  int idx;
  int ret;

  /* Parse the ASN.1 structure.  */
  if(parse_tag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
  {
    printf("ERROR - TODO: invalid ASN.1 structure\n");
    goto done;
  }

  if (parse_tag (&der, &derlen, &ti)
       || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef)
  {
    printf("ERROR - TODO: invalid ASN.1 structure\n");
    goto done;
  }

  if (ti.length != 1 || *der) {
    /* The value of the first integer is no 0. */
    printf("ERROR - TODO: invalid ASN.1 structure\n");
    goto done;
  }
  der += ti.length; derlen -= ti.length;

  for (idx=0; idx < n_keyparms; idx++) {
      if ( parse_tag (&der, &derlen, &ti)
           || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef)
      {
        printf("ERROR - TODO: invalid ASN.1 structure\n");
        goto done;
      }

      err = gcry_mpi_scan (keyparms+idx, GCRYMPI_FMT_USG, der, ti.length,NULL);
      if (err) {
        printf("ERROR - TODO\n");
        goto done;
      }
      der += ti.length;
      derlen -= ti.length;
  }
  if (idx != n_keyparms) {
    /* die ("not enough RSA key parameters\n"); */
    printf("ERROR - TODO\n");
    goto done;
  }

  /* Convert from OpenSSL parameter ordering to the OpenPGP order. */
  /* First check that p < q; if not swap p and q and recompute u.  */ 
  if (gcry_mpi_cmp (keyparms[3], keyparms[4]) > 0) {
      gcry_mpi_swap (keyparms[3], keyparms[4]);
      gcry_mpi_invm (keyparms[7], keyparms[3], keyparms[4]);
  }

  /* Build the S-expression.  */
  err = gcry_sexp_build (&s_key, NULL,
                         "(key-data"
                         "(public-key(rsa(n%m)(e%m)))"
                         "(private-key(rsa(n%m)(e%m)"
                         /**/            "(d%m)(p%m)(q%m)(u%m)))"
                         ")",
                         keyparms[0], keyparms[1],
                         keyparms[0], keyparms[1],
                         keyparms[2], keyparms[3], keyparms[4], keyparms[7]
  );
  if (err) {
    /* die ("error building S-expression: %s\n", gpg_strerror (err)); */
    printf("ERROR - TODO\n");
    goto done;
  }

  key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataRsaId);
  if(key_data == NULL) {
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecKeyDataCreate",
                XMLSEC_ERRORS_R_XMLSEC_FAILED,
                "xmlSecGCryptKeyDataRsaId");
    goto done;
  }

  ret = xmlSecGCryptKeyDataRsaAdoptKey(key_data, s_key);
  if(ret < 0) {
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptKeyDataRsaAdoptKey",
                XMLSEC_ERRORS_R_XMLSEC_FAILED,
                "xmlSecGCryptKeyDataRsaId");
    xmlSecKeyDataDestroy(key_data);
    key_data = NULL;
    goto done;
  }
  s_key = NULL; /* owned by key_data now */

done:
  if(s_key != NULL) {
    gcry_sexp_release(s_key);
  }
  
  for (idx=0; idx < n_keyparms; idx++) {
    if(keyparms[idx] != NULL) {
        gcry_mpi_release (keyparms[idx]);
    }
  }

  return(key_data);
}

#if 0
/* Read the file FNAME assuming it is a PEM encoded public key file
   and return an S-expression.  With SHOW set, the key parameters are
   printed.  */
static gcry_sexp_t
read_public_key_file (const char *fname, int show)
{
  gcry_error_t err;
  FILE *fp;
  char *buffer;
  size_t buflen;
  const unsigned char *der;
  size_t derlen;
  struct tag_info ti;
  gcry_mpi_t keyparms[2];
  int n_keyparms = 2;
  int idx;
  gcry_sexp_t s_key;

  fp = fopen (fname, binary_input?"rb":"r");
  if (!fp)
    die ("can't open `%s': %s\n", fname, strerror (errno));
  buffer = read_file (fp, 0, &buflen);
  if (!buffer)
    die ("error reading `%s'\n", fname);
  fclose (fp);

  buflen = base64_decode (buffer, buflen);
  
  /* Parse the ASN.1 structure.  */
  der = (const unsigned char*)buffer;
  derlen = buflen;
  if ( parse_tag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    goto bad_asn1;
  if ( parse_tag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    goto bad_asn1;
  /* We skip the description of the key parameters and assume it is RSA.  */
  der += ti.length; derlen -= ti.length;
  
  if ( parse_tag (&der, &derlen, &ti)
       || ti.tag != TAG_BIT_STRING || ti.class || ti.cons || ti.ndef)
    goto bad_asn1;
  if (ti.length < 1 || *der)
    goto bad_asn1;  /* The number of unused bits needs to be 0. */
  der += 1; derlen -= 1;

  /* Parse the BIT string.  */
  if ( parse_tag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    goto bad_asn1;

  for (idx=0; idx < n_keyparms; idx++)
    {
      if ( parse_tag (&der, &derlen, &ti)
           || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef)
        goto bad_asn1;
      if (show)
        {
          char prefix[2];

          prefix[0] = idx < 2? "ne"[idx] : '?';
          prefix[1] = 0;
          showhex (prefix, der, ti.length);
        }
      err = gcry_mpi_scan (keyparms+idx, GCRYMPI_FMT_USG, der, ti.length,NULL);
      if (err)
        die ("error scanning RSA parameter %d: %s\n", idx, gpg_strerror (err));
      der += ti.length; derlen -= ti.length;
    }
  if (idx != n_keyparms)
    die ("not enough RSA key parameters\n");

  gcry_free (buffer);

  /* Build the S-expression.  */
  err = gcry_sexp_build (&s_key, NULL,
                         "(public-key(rsa(n%m)(e%m)))",
                         keyparms[0], keyparms[1] );
  if (err)
    die ("error building S-expression: %s\n", gpg_strerror (err));
  
  for (idx=0; idx < n_keyparms; idx++)
    gcry_mpi_release (keyparms[idx]);
  
  return s_key;
  
 bad_asn1:
  die ("invalid ASN.1 structure in `%s'\n", fname);
  return NULL; /*NOTREACHED*/
}
#endif /* 0 */

/**
 * xmlSecGCryptAppInit:
 * @config:             the path to GCrypt configuration (unused).
 *
 * General crypto engine initialization. This function is used
 * by XMLSec command line utility and called before
 * @xmlSecInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppInit(const char* config ATTRIBUTE_UNUSED) {
    /* TODO - do we need to initialize? */
    return(0);
}

/**
 * xmlSecGCryptAppShutdown:
 *
 * General crypto engine shutdown. This function is used
 * by XMLSec command line utility and called after
 * @xmlSecShutdown function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppShutdown(void) {
    /* TODO - do we need to shutdown? */
    return(0);
}

/**
 * xmlSecGCryptAppKeyLoad:
 * @filename:           the key filename.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the a file (not implemented yet).
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppKeyLoad(const char *filename, xmlSecKeyDataFormat format,
                        const char *pwd,
                        void* pwdCallback,
                        void* pwdCallbackCtx) {
    xmlSecKeyPtr key;
    xmlSecBuffer buffer;
    int ret;

    xmlSecAssert2(filename != NULL, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    ret = xmlSecBufferInitialize(&buffer, 4*1024);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferInitialize",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(NULL);
    }

    ret = xmlSecBufferReadFile(&buffer, filename);
    if((ret < 0) || (xmlSecBufferGetData(&buffer) == NULL) || (xmlSecBufferGetSize(&buffer) <= 0)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecBufferReadFile",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "filename=%s", 
                    xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    key = xmlSecGCryptAppKeyLoadMemory(xmlSecBufferGetData(&buffer),
                    xmlSecBufferGetSize(&buffer),
                    format, pwd, pwdCallback, pwdCallbackCtx);
    if(key == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAppKeyLoadMemory",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "filename=%s",
                    xmlSecErrorsSafeString(filename));
        xmlSecBufferFinalize(&buffer);
        return(NULL);
    }

    /* cleanup */
    xmlSecBufferFinalize(&buffer);
    return(key);
}

/**
 * xmlSecGCryptAppKeyLoadMemory:
 * @data:               the binary key data.
 * @dataSize:           the size of binary key.
 * @format:             the key file format.
 * @pwd:                the key file password.
 * @pwdCallback:        the key password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key from the memory buffer (not implemented yet).
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppKeyLoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                        xmlSecKeyDataFormat format, const char *pwd,
                        void* pwdCallback, void* pwdCallbackCtx) {
    xmlSecKeyPtr key = NULL;
    xmlSecKeyDataPtr key_data = NULL;
    int ret;

    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, NULL);

    switch(format) {
    case xmlSecKeyDataFormatPem:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAppKeyLoadMemory",
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return (NULL);
    case xmlSecKeyDataFormatDer:
        key_data = read_private_key_file(data, dataSize);
        break;
#ifndef XMLSEC_NO_X509
    case xmlSecKeyDataFormatPkcs12:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAppKeyLoadMemory",
                    XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return (NULL);
#endif /* XMLSEC_NO_X509 */
    default:
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_FORMAT,
                    "format=%d", format);
        return(NULL);
    }

    key = xmlSecKeyCreate();
    if(key == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyCreate",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecKeyDataDestroy(key_data);
        return(NULL);
    }

    ret = xmlSecKeySetValue(key, key_data);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeySetValue",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "data=%s",
                    xmlSecErrorsSafeString(xmlSecKeyDataGetName(key_data)));
        xmlSecKeyDestroy(key);
        xmlSecKeyDataDestroy(key_data);
        return(NULL);
    }
    return(key);
}

#ifndef XMLSEC_NO_X509
/**
 * xmlSecGCryptAppKeyCertLoad:
 * @key:                the pointer to key.
 * @filename:           the certificate filename.
 * @format:             the certificate file format.
 *
 * Reads the certificate from $@filename and adds it to key
 * (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeyCertLoad(xmlSecKeyPtr key, const char* filename,
                          xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptAppKeyCertLoad",
                XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecGCryptAppKeyCertLoadMemory:
 * @key:                the pointer to key.
 * @data:               the certificate binary data.
 * @dataSize:           the certificate binary data size.
 * @format:             the certificate file format.
 *
 * Reads the certificate from memory buffer and adds it to key (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeyCertLoadMemory(xmlSecKeyPtr key,
                                 const xmlSecByte* data,
                                 xmlSecSize dataSize,
                                 xmlSecKeyDataFormat format) {
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptAppKeyCertLoadMemory",
                XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecGCryptAppPkcs12Load:
 * @filename:           the PKCS12 key filename.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 file
 * (not implemented yet).
 * For uniformity, call xmlSecGCryptAppKeyLoad instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12.
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppPkcs12Load(const char *filename,
                          const char *pwd ATTRIBUTE_UNUSED,
                          void* pwdCallback ATTRIBUTE_UNUSED,
                          void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(filename != NULL, NULL);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptAppPkcs12Load",
                XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL);
}

/**
 * xmlSecGCryptAppPkcs12LoadMemory:
 * @data:               the PKCS12 binary data.
 * @dataSize:           the PKCS12 binary data size.
 * @pwd:                the PKCS12 file password.
 * @pwdCallback:        the password callback.
 * @pwdCallbackCtx:     the user context for password callback.
 *
 * Reads key and all associated certificates from the PKCS12 data in memory buffer.
 * For uniformity, call xmlSecGCryptAppKeyLoadMemory instead of this function. Pass
 * in format=xmlSecKeyDataFormatPkcs12 (not implemented yet).
 *
 * Returns: pointer to the key or NULL if an error occurs.
 */
xmlSecKeyPtr
xmlSecGCryptAppPkcs12LoadMemory(const xmlSecByte* data, xmlSecSize dataSize,
                           const char *pwd ATTRIBUTE_UNUSED,
                           void* pwdCallback ATTRIBUTE_UNUSED,
                           void* pwdCallbackCtx ATTRIBUTE_UNUSED) {
    xmlSecAssert2(data != NULL, NULL);
    xmlSecAssert2(dataSize > 0, NULL);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptAppPkcs12LoadMemory",
                XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                XMLSEC_ERRORS_NO_MESSAGE);
    return(NULL);
}

/**
 * xmlSecGCryptAppKeysMngrCertLoad:
 * @mngr:               the keys manager.
 * @filename:           the certificate file.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate in @filename
 *                      trusted or not.
 *
 * Reads cert from @filename and adds to the list of trusted or known
 * untrusted certs in @store (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeysMngrCertLoad(xmlSecKeysMngrPtr mngr, 
                                const char *filename,
                                xmlSecKeyDataFormat format,
                                xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptAppKeysMngrCertLoad",
                XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

/**
 * xmlSecGCryptAppKeysMngrCertLoadMemory:
 * @mngr:               the keys manager.
 * @data:               the certificate binary data.
 * @dataSize:           the certificate binary data size.
 * @format:             the certificate file format.
 * @type:               the flag that indicates is the certificate trusted or not.
 *
 * Reads cert from binary buffer @data and adds to the list of trusted or known
 * untrusted certs in @store (not implemented yet).
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppKeysMngrCertLoadMemory(xmlSecKeysMngrPtr mngr,
                                      const xmlSecByte* data,
                                      xmlSecSize dataSize,
                                      xmlSecKeyDataFormat format,
                                      xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(data != NULL, -1);
    xmlSecAssert2(dataSize > 0, -1);
    xmlSecAssert2(format != xmlSecKeyDataFormatUnknown, -1);

    /* TODO */
    xmlSecError(XMLSEC_ERRORS_HERE,
                NULL,
                "xmlSecGCryptAppKeysMngrCertLoadMemory",
                XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
                XMLSEC_ERRORS_NO_MESSAGE);
    return(-1);
}

#endif /* XMLSEC_NO_X509 */

/**
 * xmlSecGCryptAppDefaultKeysMngrInit:
 * @mngr:               the pointer to keys manager.
 *
 * Initializes @mngr with simple keys store #xmlSecSimpleKeysStoreId
 * and a default GCrypt crypto key data stores.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    int ret;

    xmlSecAssert2(mngr != NULL, -1);

    /* create simple keys store if needed */
    if(xmlSecKeysMngrGetKeysStore(mngr) == NULL) {
        xmlSecKeyStorePtr keysStore;

        keysStore = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId);
        if(keysStore == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeyStoreCreate",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "xmlSecSimpleKeysStoreId");
            return(-1);
        }

        ret = xmlSecKeysMngrAdoptKeysStore(mngr, keysStore);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecKeysMngrAdoptKeysStore",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            xmlSecKeyStoreDestroy(keysStore);
            return(-1);
        }
    }

    ret = xmlSecGCryptKeysMngrInit(mngr);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptKeysMngrInit",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* TODO */
    mngr->getKey = xmlSecKeysMngrGetKey;
    return(0);
}

/**
 * xmlSecGCryptAppDefaultKeysMngrAdoptKey:
 * @mngr:               the pointer to keys manager.
 * @key:                the pointer to key.
 *
 * Adds @key to the keys manager @mngr created with #xmlSecGCryptAppDefaultKeysMngrInit
 * function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrAdoptKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeysMngrGetKeysStore",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecSimpleKeysStoreAdoptKey",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGCryptAppDefaultKeysMngrLoad:
 * @mngr:               the pointer to keys manager.
 * @uri:                the uri.
 *
 * Loads XML keys file from @uri to the keys manager @mngr created
 * with #xmlSecGCryptAppDefaultKeysMngrInit function.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrLoad(xmlSecKeysMngrPtr mngr, const char* uri) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(uri != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeysMngrGetKeysStore",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreLoad(store, uri, mngr);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecSimpleKeysStoreLoad",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGCryptAppDefaultKeysMngrSave:
 * @mngr:               the pointer to keys manager.
 * @filename:           the destination filename.
 * @type:               the type of keys to save (public/private/symmetric).
 *
 * Saves keys from @mngr to  XML keys file.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecGCryptAppDefaultKeysMngrSave(xmlSecKeysMngrPtr mngr, const char* filename, xmlSecKeyDataType type) {
    xmlSecKeyStorePtr store;
    int ret;

    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(filename != NULL, -1);

    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeysMngrGetKeysStore",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ret = xmlSecSimpleKeysStoreSave(store, filename, type);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecSimpleKeysStoreSave",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "filename=%s",
                    xmlSecErrorsSafeString(filename));
        return(-1);
    }

    return(0);
}

/**
 * xmlSecGCryptAppGetDefaultPwdCallback:
 *
 * Gets default password callback.
 *
 * Returns: default password callback.
 */
void*
xmlSecGCryptAppGetDefaultPwdCallback(void) {
    return(NULL);
}

