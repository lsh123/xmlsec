/** 
 * XML Security standards test: XMLDSig
 * 
 * See Copyright for the status of this software.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/extensions.h> 
#include <libxslt/xsltInternals.h>
#include <libxslt/xsltutils.h>
#include <libexslt/exslt.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/xkms.h>
#include <xmlsec/parser.h>
#include <xmlsec/templates.h>
#include <xmlsec/errors.h>

#include "crypto.h"
#include "cmdline.h"

static const char copyright[] =
    "Written by Aleksey Sanin <aleksey@aleksey.com>.\n\n"
    "Copyright (C) 2002-2003 Aleksey Sanin.\n"
    "This is free software: see the source for copying information.\n";

static const char bugs[] = 
    "Report bugs to http://www.aleksey.com/xmlsec/bugs.html\n";

static const char helpCommands1[] =     
    "Usage: xmlsec <command> [<options>] [<file>]\n"
    "\n"
    "xmlsec is a command line tool for signing, verifying, encrypting and\n"
    "decrypting XML documents. The allowed <command> values are:\n"
    "  --help      "	"\tdisplay this help information and exit\n"
    "  --help-all  "	"\tdisplay help information for all commands/options and exit\n"
    "  --help-<cmd>"	"\tdisplay help information for command <cmd> and exit\n"
    "  --version   "	"\tprint version information and exit\n"
    "  --keys      "	"\tkeys XML file manipulation\n";

static const char helpCommands2[] =     
#ifndef XMLSEC_NO_XMLDSIG
    "  --sign      "	"\tsign data and output XML document\n"
    "  --verify    "	"\tverify signed document\n"
#ifndef XMLSEC_NO_TMPL_TEST
    "  --sign-tmpl "	"\tcreate and sign dynamicaly generated signature template\n"
#endif /* XMLSEC_NO_TMPL_TEST */
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
    "  --encrypt   "	"\tencrypt data and output XML document\n"
    "  --decrypt   "	"\tdecrypt data from XML document\n"
#endif /* XMLSEC_NO_XMLENC */
#ifndef XMLSEC_NO_XKMS
    "  --xkis-server-locate  " "\tprocess data as XKMS/XKISS Locate request\n"
    "  --xkis-server-validate" "\tprocess data as XKMS/XKISS Validate request\n"
#endif /* XMLSEC_NO_XKMS */
    ;

static const char helpVersion[] = 
    "Usage: xmlsec version\n"
    "Prints version information and exits\n";

static const char helpKeys[] =     
    "Usage: xmlsec keys [<options>] <file>\n"
    "Creates a new XML keys file <file>\n";
    
static const char helpSign[] =     
    "Usage: xmlsec sign [<options>] <file>\n"
    "Calculates XML Digital Signature using template file <file>\n";
    
static const char helpVerify[] =     
    "Usage: xmlsec verify [<options>] <file>\n"
    "Verifies XML Digital Signature in the <file>\n";

static const char helpSignTmpl[] =     
    "Usage: xmlsec sign-tmpl [<options>]\n"
    "Creates a simple dynamic template and calculates XML Digital Signature\n"
    "(for testing only).\n";

static const char helpEncrypt[] =     
    "Usage: xmlsec encrypt [<options>] <file>\n"
    "Encrypts data and creates XML Encryption using template file <file>\n";

static const char helpEncryptTmpl[] =     
    "Usage: xmlsec encrypt [<options>]\n"
    "Creates a simple dynamic template and calculates XML Encryption\n";

static const char helpDecrypt[] =     
    "Usage: xmlsec decrypt [<options>] <file>\n"
    "Decrypts XML Encryption data in the <file>\n";

static const char helpXkissServerLocate[] =  
    "Usage: xmlsec xkiss-server-locate [<options>] <file>\n"
    "Processes the <file> as XKMS/XKISS Locate request and outputs the response\n";

static const char helpXkissServerValidate[] =  
    "Usage: xmlsec xkms-server-validate [<options>] <file>\n"
    "Processes the <file> as XKMS/XKISS Validate request and outputs the response\n";

static const char helpListKeyData[] =     
    "Usage: xmlsec list-key-data\n"
    "Prints the list of known key data klasses\n";

static const char helpListTransforms[] =     
    "Usage: xmlsec list-transforms\n"
    "Prints the list of known transform klasses\n";

#define xmlSecAppCmdLineTopicGeneral		0x0001
#define xmlSecAppCmdLineTopicDSigCommon		0x0002
#define xmlSecAppCmdLineTopicDSigSign		0x0004
#define xmlSecAppCmdLineTopicDSigVerify		0x0008
#define xmlSecAppCmdLineTopicEncCommon		0x0010
#define xmlSecAppCmdLineTopicEncEncrypt		0x0020
#define xmlSecAppCmdLineTopicEncDecrypt		0x0040
#define xmlSecAppCmdLineTopicXkmsCommon		0x0080
#define xmlSecAppCmdLineTopicKeysMngr		0x1000
#define xmlSecAppCmdLineTopicX509Certs		0x2000
#define xmlSecAppCmdLineTopicVersion		0x4000
#define xmlSecAppCmdLineTopicAll		0xFFFF

/****************************************************************
 *
 * General configuration params
 *
 ***************************************************************/
static xmlSecAppCmdLineParam helpParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--help",
    "-h",
    "--help"
    "\n\tprint help information about the command",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

#if !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
static xmlSecAppCmdLineParam cryptoParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--crypto",
    NULL,
    "--crypto <name>"
    "\n\tthe name of the crypto engine to use (if not specified, the default"
    "\n\tcrypto engine is used)",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    
#endif /* !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

static xmlSecAppCmdLineParam cryptoConfigParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--crypto-config",
    NULL,
    "--crypto-config <path>"
    "\n\tpath to crypto engine configuration",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    


static xmlSecAppCmdLineParam repeatParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--repeat",
    "-r",
    "--repeat <number>"
    "\n\trepeat the operation <number> times",
    xmlSecAppCmdLineParamTypeNumber,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    


static xmlSecAppCmdLineParam disableErrorMsgsParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--disable-error-msgs",
    NULL,
    "--disable-error-msgs"
    "\n\tdo not print xmlsec error messages",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam printCryptoErrorMsgsParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--print-crypto-error-msgs",
    NULL,
    "--print-crypto-error-msgs"
    "\n\tprint errors stack at the end",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

/****************************************************************
 *
 * Keys Manager params
 *
 ***************************************************************/
static xmlSecAppCmdLineParam genKeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--gen-key",
    "-g",
    "--gen-key[:<name>] <keyKlass>-<keySize>"
    "\n\tgenerate new <keyKlass> key of <keySize> bits size,"
    "\n\tset the key name to <name> and add the result to keys"
    "\n\tmanager (for example, \"--gen:mykey rsa-1024\" generates"
    "\n\ta new 1024 bits RSA key and sets it's name to \"mykey\")",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam keysFileParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--keys-file",
    "-k",
    "--keys-file <file>"
    "\n\tload keys from XML file",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam privkeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--privkey-pem",
    "--privkey",
    "--privkey-pem[:<name>] <file>[,<cafile>[,<cafile>[...]]]"
    "\n\tload private key from PEM file and certificates"
    "\n\tthat verify this key",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam privkeyDerParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--privkey-der",
    NULL,
    "--privkey-der[:<name>] <file>[,<cafile>[,<cafile>[...]]]"
    "\n\tload private key from DER file and certificates"
    "\n\tthat verify this key",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam pkcs8PemParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pkcs8-pem",
    "--privkey-p8-pem",
    "--pkcs-pem[:<name>] <file>[,<cafile>[,<cafile>[...]]]"
    "\n\tload private key from PKCS8 PEM file and PEM certificates"
    "\n\tthat verify this key",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam pkcs8DerParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pkcs8-der",
    "--privkey-p8-der",
    "--pkcs8-der[:<name>] <file>[,<cafile>[,<cafile>[...]]]"
    "\n\tload private key from PKCS8 DER file and DER certificates"
    "\n\tthat verify this key",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam pubkeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pubkey-pem",
    "--pubkey",
    "--pubkey-pem[:<name>] <file>"
    "\n\tload public key from PEM file",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam pubkeyDerParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pubkey-der",
    NULL,
    "--pubkey-der[:<name>] <file>"
    "\n\tload public key from DER file",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

#ifndef XMLSEC_NO_AES    
static xmlSecAppCmdLineParam aeskeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--aeskey",
    NULL,
    "--aeskey[:<name>] <file>"
    "\n\tload AES key from binary file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES   
static xmlSecAppCmdLineParam deskeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--deskey",
    NULL,
    "--deskey[:<name>] <file>"
    "\n\tload DES key from binary file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC    
static xmlSecAppCmdLineParam hmackeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--hmackey",
    NULL,
    "--hmackey[:<name>] <file>"
    "\n\tload HMAC key from binary file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};
#endif /* XMLSEC_NO_HMAC */

static xmlSecAppCmdLineParam pwdParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pwd",
    NULL,
    "--pwd <password>"
    "\n\tthe password to use for reading keys and certs",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam enabledKeyDataParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--enabled-key-data",
    NULL,
    "--enabled-key-data <list>"
    "\n\tcomma separated list of enabled key data (list of "
    "\n\tregistered key data klasses is available with \"--list-key-data\""
    "\n\tcommand); by default, all registered key data are enabled",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam enabledRetrievalMethodUrisParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--enabled-retrieval-method-uris",
    NULL,
    "--enabled-retrieval-uris <list>"
    "\n\tcomma separated list of of the following values:"
    "\n\t\"empty\", \"same-doc\", \"local\",\"remote\" to restrict possible URI"
    "\n\tattribute values for the <dsig:RetrievalMethod> element.",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

/****************************************************************
 *
 * Common params
 *
 ***************************************************************/
static xmlSecAppCmdLineParam sessionKeyParam = { 
    xmlSecAppCmdLineTopicDSigSign | xmlSecAppCmdLineTopicEncEncrypt,
    "--session-key",
    NULL,
    "--session-key <keyKlass>-<keySize>"
    "\n\tgenerate new session <keyKlass> key of <keySize> bits size"
    "\n\t(for example, \"--session des-192\" generates a new 192 bits"
    "\n\tDES key for DES3 encryption)",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam outputParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--output",
    "-o",
    "--output <filename>"
    "\n\twrite result document to file <filename>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam nodeIdParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--node-id",
    NULL,
    "--node-id <id>"
    "\n\tset the operation start point to the node with given <id>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam nodeNameParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--node-name",
    NULL,   
    "--node-name [<namespace-uri>:]<name>"
    "\n\tset the operation start point to the first node"
    "\n\twith given <name> and <namespace> URI",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    
    
static xmlSecAppCmdLineParam nodeXPathParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--node-xpath",
    NULL,   
    "--node-xpath <expr>"
    "\n\tset the operation start point to the first node"
    "\n\tselected by the specified XPath expression",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam dtdFileParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--dtd-file",
    NULL,   
    "--dtd-file <file>"
    "\n\tload the specified file as the DTD",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam printDebugParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--print-debug",
    NULL,   
    "--print-debug"
    "\n\tprint debug information to stdout",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam printXmlDebugParam = { 
    xmlSecAppCmdLineTopicDSigCommon | 
    xmlSecAppCmdLineTopicEncCommon | 
    xmlSecAppCmdLineTopicXkmsCommon,
    "--print-xml-debug",
    NULL,   
    "--print-xml-debug"
    "\n\tprint debug information to stdout in xml format",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

/****************************************************************
 *
 * Common dsig params
 *
 ***************************************************************/
#ifndef XMLSEC_NO_XMLDSIG
static xmlSecAppCmdLineParam ignoreManifestsParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--ignore-manifests",
    NULL,
    "--ignore-manifests"
    "\n\tdo not process <dsig:Manifest> elements",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam storeReferencesParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--store-references",
    NULL,
    "--store-references"
    "\n\tstore and print the result of <dsig:Reference/> element processing"
    "\n\tjust before calculating digest",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam storeSignaturesParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--store-signatures",
    NULL,
    "--store-signatures"
    "\n\tstore and print the result of <dsig:Signature> processing"
    "\n\tjust before calculating signature",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};
static xmlSecAppCmdLineParam enabledRefUrisParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--enabled-reference-uris",
    NULL,
    "--enabled-reference-uris <list>"
    "\n\tcomma separated list of of the following values:"
    "\n\t\"empty\", \"same-doc\", \"local\",\"remote\" to restrict possible URI"
    "\n\tattribute values for the <dsig:Reference> element",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

#endif /* XMLSEC_NO_XMLDSIG */

/****************************************************************
 *
 * Enc params
 *
 ***************************************************************/
#ifndef XMLSEC_NO_XMLENC
static xmlSecAppCmdLineParam enabledCipherRefUrisParam = { 
    xmlSecAppCmdLineTopicEncCommon,
    "--enabled-cipher-reference-uris",
    NULL,
    "--enabled-cipher-reference-uris <list>"
    "\n\tcomma separated list of of the following values:"
    "\n\t\"empty\", \"same-doc\", \"local\",\"remote\" to restrict possible URI"
    "\n\tattribute values for the <enc:CipherReference> element",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam binaryDataParam = { 
    xmlSecAppCmdLineTopicEncEncrypt,
    "--binary-data",
    "--binary",
    "--binary-data <file>"
    "\n\tbinary <file> to encrypt",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam xmlDataParam = { 
    xmlSecAppCmdLineTopicEncEncrypt,
    "--xml-data",
    NULL,
    "--xml-data <file>"
    "\n\tXML <file> to encrypt",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};
#endif /* XMLSEC_NO_XMLENC */

/****************************************************************
 *
 * X509 params
 *
 ***************************************************************/
#ifndef XMLSEC_NO_X509    
static xmlSecAppCmdLineParam pkcs12Param = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pkcs12",
    NULL,
    "--pkcs12[:<name>] <file>"
    "\n\tload load private key from pkcs12 file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam trustedParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--trusted-pem",
    "--trusted",
    "--trusted-pem <file>"
    "\n\tload trusted (root) certificate from PEM file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam untrustedParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--untrusted-pem",
    "--untrusted",
    "--untrusted-pem <file>"
    "\n\tload untrusted certificate from PEM file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam trustedDerParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--trusted-der",
    NULL,
    "--trusted-der <file>"
    "\n\tload trusted (root) certificate from DER file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam untrustedDerParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--untrusted-der",
    NULL,
    "--untrusted-der <file>"
    "\n\tload untrusted certificate from DER file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam verificationTimeParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--verification-time",
    NULL,
    "--verification-time <time>"
    "\n\tthe local time in \"YYYY-MM-DD HH:MM:SS\" format"
    "\n\tused certificates verification",
    xmlSecAppCmdLineParamTypeTime,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam depthParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--depth",
    NULL,    
    "--depth <number>"
    "\n\tmaximum certificates chain depth",
    xmlSecAppCmdLineParamTypeTime,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam X509SkipStrictChecksParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--X509-skip-strict-checks",
    NULL,    
    "--X509-skip-strict-checks"
    "\n\tskip strict checking of X509 data",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};
#endif /* XMLSEC_NO_X509 */    

static xmlSecAppCmdLineParamPtr parameters[] = {
    /* common dsig params */
#ifndef XMLSEC_NO_XMLDSIG
    &ignoreManifestsParam,
    &storeReferencesParam,
    &storeSignaturesParam,
    &enabledRefUrisParam,
#endif /* XMLSEC_NO_XMLDSIG */

    /* enc params */
#ifndef XMLSEC_NO_XMLENC
    &binaryDataParam,
    &xmlDataParam,
    &enabledCipherRefUrisParam,
#endif /* XMLSEC_NO_XMLENC */
             
    /* common dsig and enc parameters */
    &sessionKeyParam,    
    &outputParam,
    &printDebugParam,
    &printXmlDebugParam,    
    &dtdFileParam,
    &nodeIdParam,
    &nodeNameParam,
    &nodeXPathParam,
    
    /* Keys Manager params */
    &enabledKeyDataParam,
    &enabledRetrievalMethodUrisParam,
    &genKeyParam,
    &keysFileParam,
    &privkeyParam,
    &privkeyDerParam,
    &pkcs8PemParam,
    &pkcs8DerParam,
    &pubkeyParam,
    &pubkeyDerParam,
#ifndef XMLSEC_NO_AES    
    &aeskeyParam,
#endif  /* XMLSEC_NO_AES */    
#ifndef XMLSEC_NO_DES
    &deskeyParam,
#endif  /* XMLSEC_NO_DES */    
#ifndef XMLSEC_NO_HMAC    
    &hmackeyParam,
#endif  /* XMLSEC_NO_HMAC */    
    &pwdParam,
#ifndef XMLSEC_NO_X509
    &pkcs12Param,
    &trustedParam,
    &untrustedParam,
    &trustedDerParam,
    &untrustedDerParam,
    &verificationTimeParam,
    &depthParam,    
    &X509SkipStrictChecksParam,    
#endif /* XMLSEC_NO_X509 */    
    
    /* General configuration params */
#if !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
    &cryptoParam,
#endif /* !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */
    &cryptoConfigParam,
    &repeatParam,
    &disableErrorMsgsParam,
    &printCryptoErrorMsgsParam,
    &helpParam,
        
    /* MUST be the last one */
    NULL
};

typedef enum {
    xmlSecAppCommandUnknown = 0,
    xmlSecAppCommandHelp,
    xmlSecAppCommandListKeyData,
    xmlSecAppCommandListTransforms,    
    xmlSecAppCommandVersion,
    xmlSecAppCommandKeys,
    xmlSecAppCommandSign,
    xmlSecAppCommandVerify,
    xmlSecAppCommandSignTmpl,
    xmlSecAppCommandEncrypt,
    xmlSecAppCommandDecrypt,
    xmlSecAppCommandEncryptTmpl,
    xmlSecAppCommandXkissServerLocate,
    xmlSecAppCommandXkissServerValidate
} xmlSecAppCommand;

typedef struct _xmlSecAppXmlData				xmlSecAppXmlData,
								*xmlSecAppXmlDataPtr;
struct _xmlSecAppXmlData {
    xmlDocPtr	doc;
    xmlDtdPtr	dtd;
    xmlNodePtr	startNode;
};

static xmlSecAppXmlDataPtr	xmlSecAppXmlDataCreate		(const char* filename,
								 const xmlChar* defStartNodeName,
								 const xmlChar* defStartNodeNs);
static void			xmlSecAppXmlDataDestroy		(xmlSecAppXmlDataPtr data);					


static xmlSecAppCommand 	xmlSecAppParseCommand		(const char* cmd, 
							         xmlSecAppCmdLineParamTopic* topics,
								 xmlSecAppCommand* subCommand);
static void 			xmlSecAppPrintHelp		(xmlSecAppCommand command, 
								 xmlSecAppCmdLineParamTopic topics);
#define				xmlSecAppPrintUsage()		xmlSecAppPrintHelp(xmlSecAppCommandUnknown, 0)
static int			xmlSecAppInit			(void);
static void			xmlSecAppShutdown		(void);
static int			xmlSecAppLoadKeys		(void);
static int			xmlSecAppPrepareKeyInfoReadCtx	(xmlSecKeyInfoCtxPtr ctx);

#ifndef XMLSEC_NO_XMLDSIG
static int			xmlSecAppSignFile		(const char* filename);
static int			xmlSecAppVerifyFile		(const char* filename);
#ifndef XMLSEC_NO_TMPL_TEST
static int			xmlSecAppSignTmpl		(void);
#endif /* XMLSEC_NO_TMPL_TEST */
static int			xmlSecAppPrepareDSigCtx		(xmlSecDSigCtxPtr dsigCtx);
static void			xmlSecAppPrintDSigCtx		(xmlSecDSigCtxPtr dsigCtx);
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
static int			xmlSecAppEncryptFile		(const char* filename);
static int			xmlSecAppDecryptFile		(const char* filename);
#ifndef XMLSEC_NO_TMPL_TEST
static int			xmlSecAppEncryptTmpl		(void);
#endif /* XMLSEC_NO_TMPL_TEST */
static int			xmlSecAppPrepareEncCtx		(xmlSecEncCtxPtr encCtx);
static void			xmlSecAppPrintEncCtx		(xmlSecEncCtxPtr encCtx);
#endif /* XMLSEC_NO_XMLENC */

#ifndef XMLSEC_NO_XKMS
static int			xmlSecAppXkissServerLocate	(const char* filename);
static int			xmlSecAppXkissServerValidate	(const char* filename);
static int			xmlSecAppPrepareXkissServerCtx	(xmlSecXkissServerCtxPtr xkissServerCtx);
static void			xmlSecAppPrintXkissServerCtx	(xmlSecXkissServerCtxPtr xkissServerCtx);
#endif /* XMLSEC_NO_XKMS */

static void			xmlSecAppListKeyData		(void);
static void			xmlSecAppListTransforms		(void);

static xmlSecTransformUriType	xmlSecAppGetUriType		(const char* string);
static FILE* 			xmlSecAppOpenFile		(const char* filename);
static void			xmlSecAppCloseFile		(FILE* file);
static int			xmlSecAppWriteResult		(xmlDocPtr doc,
								 xmlSecBufferPtr buffer);

xmlSecKeysMngrPtr gKeysMngr = NULL;
int repeats = 1;
int print_debug = 0;
clock_t total_time = 0;
const char* xmlsec_crypto = XMLSEC_CRYPTO;
const char* tmp = NULL;

int main(int argc, const char **argv) {
    xmlSecAppCmdLineParamTopic cmdLineTopics;
    xmlSecAppCommand command, subCommand;
    int pos, i;
    int res = 1;
            
    /* read the command (first argument) */
    if(argc < 2) {
	xmlSecAppPrintUsage();
	goto fail;
    }
    command = xmlSecAppParseCommand(argv[1], &cmdLineTopics, &subCommand);
    if(command == xmlSecAppCommandUnknown) {
	fprintf(stderr, "Error: unknown command \"%s\"\n", argv[1]);
	xmlSecAppPrintUsage();
	goto fail;
    }
    
    /* do as much as we can w/o initialization */
    if(command == xmlSecAppCommandHelp) {
	xmlSecAppPrintHelp(subCommand, cmdLineTopics);
	goto success;
    } else if(command == xmlSecAppCommandVersion) {
	fprintf(stdout, "%s %s (%s)\n", XMLSEC_PACKAGE, XMLSEC_VERSION, xmlsec_crypto);
	goto success;
    }
    
    /* parse command line */
    pos = xmlSecAppCmdLineParamsListParse(parameters, cmdLineTopics, argv, argc, 2);
    if(pos < 0) {
	fprintf(stderr, "Error: invalid parameters\n");
	xmlSecAppPrintUsage();
	goto fail;
    }
    
    /* is it a help request? */    
    if(xmlSecAppCmdLineParamIsSet(&helpParam)) {
	xmlSecAppPrintHelp(command, cmdLineTopics);
	goto success;
    }
    
    /* we need to have some files at the end */
    switch(command) {
	case xmlSecAppCommandKeys:
	case xmlSecAppCommandSign:
	case xmlSecAppCommandVerify:
	case xmlSecAppCommandEncrypt:
	case xmlSecAppCommandDecrypt:
	case xmlSecAppCommandXkissServerLocate:
	case xmlSecAppCommandXkissServerValidate:
	    if(pos >= argc) {
		fprintf(stderr, "Error: <file> parameter is requried for this command\n");
		xmlSecAppPrintUsage();
		goto fail;
	    }
	    break;
	default:
	    break;
    }
    
    /* now init the xmlsec and all other libs */
#if !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
    tmp = xmlSecAppCmdLineParamGetString(&cryptoParam);
    if((tmp != NULL) && (strcmp(tmp, "default") != 0)) {
	xmlsec_crypto = tmp;
    }
#endif /* !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */
    
    if(xmlSecAppInit() < 0) {
	fprintf(stderr, "Error: initialization failed\n");
	xmlSecAppPrintUsage();
	goto fail;
    }    
    
    /* load keys */
    if(xmlSecAppLoadKeys() < 0) {
	fprintf(stderr, "Error: keys manager creation failed\n");
	xmlSecAppPrintUsage();
	goto fail;
    }
    
    /* get the "repeats" number */
    if(xmlSecAppCmdLineParamIsSet(&repeatParam) && 
       (xmlSecAppCmdLineParamGetInt(&repeatParam, 1) > 0)) {
       
	repeats = xmlSecAppCmdLineParamGetInt(&repeatParam, 1);
    }

    /* execute requested number of times */
    for(; repeats > 0; --repeats) {
	switch(command) {
	case xmlSecAppCommandListKeyData:
	    xmlSecAppListKeyData();
	    break;
	case xmlSecAppCommandListTransforms:
	    xmlSecAppListTransforms();
	    break;	    
	case xmlSecAppCommandKeys:
	    for(i = pos; i < argc; ++i) {
    	    	if(xmlSecAppCryptoSimpleKeysMngrSave(gKeysMngr, argv[i], xmlSecKeyDataTypeAny) < 0) {
		    fprintf(stderr, "Error: failed to save keys to file \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
#ifndef XMLSEC_NO_XMLDSIG
	case xmlSecAppCommandSign:
	    for(i = pos; i < argc; ++i) {
    	        if(xmlSecAppSignFile(argv[i]) < 0) {
		    fprintf(stderr, "Error: failed to sign file \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
	case xmlSecAppCommandVerify:
	    for(i = pos; i < argc; ++i) {
    	        if(xmlSecAppVerifyFile(argv[i]) < 0) {
		    fprintf(stderr, "Error: failed to verify file \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
#ifndef XMLSEC_NO_TMPL_TEST
	case xmlSecAppCommandSignTmpl:
	    if(xmlSecAppSignTmpl() < 0) {
		fprintf(stderr, "Error: failed to create and sign template\n");
		goto fail;
	    }
	    break;
#endif /* XMLSEC_NO_TMPL_TEST */
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
	case xmlSecAppCommandEncrypt:
	    for(i = pos; i < argc; ++i) {
    	        if(xmlSecAppEncryptFile(argv[i]) < 0) {
		    fprintf(stderr, "Error: failed to encrypt file with template \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
	case xmlSecAppCommandDecrypt:
	    for(i = pos; i < argc; ++i) {
    	        if(xmlSecAppDecryptFile(argv[i]) < 0) {
		    fprintf(stderr, "Error: failed to decrypt file \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
#ifndef XMLSEC_NO_TMPL_TEST
	case xmlSecAppCommandEncryptTmpl:
	    if(xmlSecAppEncryptTmpl() < 0) {
		fprintf(stderr, "Error: failed to create and encrypt template\n");
		goto fail;
	    }
	    break;
#endif /* XMLSEC_NO_TMPL_TEST */
#endif /* XMLSEC_NO_XMLENC */

#ifndef XMLSEC_NO_XKMS
	case xmlSecAppCommandXkissServerLocate:
	    for(i = pos; i < argc; ++i) {
    	        if(xmlSecAppXkissServerLocate(argv[i]) < 0) {
		    fprintf(stderr, "Error: failed to process XKISS Locate request from file \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
	case xmlSecAppCommandXkissServerValidate:
	    for(i = pos; i < argc; ++i) {
    	        if(xmlSecAppXkissServerValidate(argv[i]) < 0) {
		    fprintf(stderr, "Error: failed to process XKISS Validate request from file \"%s\"\n", argv[i]);
		    goto fail;
		}
	    }
	    break;
#endif /* XMLSEC_NO_XKMS */
	default:
	    fprintf(stderr, "Error: invalid command %d\n", command);
	    xmlSecAppPrintUsage();
	    goto fail;
	}
    }

    /* print perf stats results */
    if(xmlSecAppCmdLineParamIsSet(&repeatParam) && 
       (xmlSecAppCmdLineParamGetInt(&repeatParam, 1) > 0)) {
       
	repeats = xmlSecAppCmdLineParamGetInt(&repeatParam, 1);
        fprintf(stderr, "Executed %d tests in %ld msec\n", repeats, total_time / (CLOCKS_PER_SEC / 1000));    
    }

    goto success;
success:
    res = 0;
fail:
    if(gKeysMngr != NULL) {
	xmlSecKeysMngrDestroy(gKeysMngr);
	gKeysMngr = NULL;
    }
    xmlSecAppShutdown();
    xmlSecAppCmdLineParamsListClean(parameters);
    return(res);
}


#ifndef XMLSEC_NO_XMLDSIG
static int 
xmlSecAppSignFile(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecDSigCtx dsigCtx;
    clock_t start_time;
    int res = -1;
    
    if(filename == NULL) {
	return(-1);
    }
    
    if(xmlSecDSigCtxInitialize(&dsigCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: dsig context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareDSigCtx(&dsigCtx) < 0) {
	fprintf(stderr, "Error: dsig context preparation failed\n");
	goto done;
    }
    
    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeSignature, xmlSecDSigNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	goto done;
    }

    /* sign */
    start_time = clock();
    if(xmlSecDSigCtxSign(&dsigCtx, data->startNode) < 0) {
        fprintf(stderr,"Error: signature failed \n");
	goto done;
    }
    total_time += clock() - start_time;    

    if(repeats <= 1) { 
	FILE* f;
        
	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&outputParam));
	if(f == NULL) {
	    fprintf(stderr,"Error: failed to open output file \"%s\"\n",
		    xmlSecAppCmdLineParamGetString(&outputParam));
	    goto done;
	}
	xmlDocDump(f, data->doc);
	xmlSecAppCloseFile(f);
    }

    res = 0;
done:
    /* print debug info if requested */
    if(repeats <= 1) {
    	xmlSecAppPrintDSigCtx(&dsigCtx);
    }
    xmlSecDSigCtxFinalize(&dsigCtx);
    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

static int 
xmlSecAppVerifyFile(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecDSigCtx dsigCtx;
    clock_t start_time;
    int res = -1;
    
    if(filename == NULL) {
	return(-1);
    }

    if(xmlSecDSigCtxInitialize(&dsigCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: dsig context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareDSigCtx(&dsigCtx) < 0) {
	fprintf(stderr, "Error: dsig context preparation failed\n");
	goto done;
    }
    
    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeSignature, xmlSecDSigNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	goto done;
    }

    /* sign */
    start_time = clock();
    if(xmlSecDSigCtxVerify(&dsigCtx, data->startNode) < 0) {
        fprintf(stderr,"Error: signature failed \n");
	goto done;
    }
    total_time += clock() - start_time;    

    if((repeats <= 1) && (dsigCtx.status != xmlSecDSigStatusSucceeded)){ 
	/* return an error if signature does not match */
	goto done;
    }

    res = 0;
done:
    /* print debug info if requested */
    if(repeats <= 1) {
	xmlSecDSigReferenceCtxPtr dsigRefCtx;
	xmlSecSize good, i, size;
	FILE* f;
        
	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&outputParam));
	if(f == NULL) {
	    fprintf(stderr,"Error: failed to open output file \"%s\"\n",
		    xmlSecAppCmdLineParamGetString(&outputParam));
	    goto done;
	}
	xmlSecAppCloseFile(f);

	switch(dsigCtx.status) {
	    case xmlSecDSigStatusUnknown:
		fprintf(stderr, "ERROR\n");
		break;
	    case xmlSecDSigStatusSucceeded:
		fprintf(stderr, "OK\n");
		break;
	    case xmlSecDSigStatusInvalid:
		fprintf(stderr, "FAIL\n");
		break;
	}    

	/* print stats about # of good/bad references/manifests */
	size = xmlSecPtrListGetSize(&(dsigCtx.signedInfoReferences));
	for(i = good = 0; i < size; ++i) {
	    dsigRefCtx = (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(dsigCtx.signedInfoReferences), i);
	    if(dsigRefCtx == NULL) {
		fprintf(stderr,"Error: reference ctx is null\n");
		goto done;
	    }
	    if(dsigRefCtx->status == xmlSecDSigStatusSucceeded) {
		++good;
	    }
	}
	fprintf(stderr, "SignedInfo References (ok/all): %d/%d\n", good, size);

	size = xmlSecPtrListGetSize(&(dsigCtx.manifestReferences));
	for(i = good = 0; i < size; ++i) {
	    dsigRefCtx = (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(dsigCtx.manifestReferences), i);
	    if(dsigRefCtx == NULL) {
		fprintf(stderr,"Error: reference ctx is null\n");
		goto done;
	    }
	    if(dsigRefCtx->status == xmlSecDSigStatusSucceeded) {
		++good;
	    }
	}
	fprintf(stderr, "Manifests References (ok/all): %d/%d\n", good, size);

    	xmlSecAppPrintDSigCtx(&dsigCtx);
    }
    xmlSecDSigCtxFinalize(&dsigCtx);
    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

#ifndef XMLSEC_NO_TMPL_TEST
static int 
xmlSecAppSignTmpl(void) {
    xmlDocPtr doc = NULL;
    xmlNodePtr cur;
    xmlSecDSigCtx dsigCtx;
    clock_t start_time;
    int res = -1;
        
    if(xmlSecDSigCtxInitialize(&dsigCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: dsig context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareDSigCtx(&dsigCtx) < 0) {
	fprintf(stderr, "Error: dsig context preparation failed\n");
	goto done;
    }
    
    /* prepare template */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
	fprintf(stderr, "Error: failed to create doc\n");
	goto done;
    }
    
    cur = xmlSecTmplSignatureCreate(doc, xmlSecTransformInclC14NId,
				    xmlSecTransformHmacSha1Id, NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to create Signature node\n");
	goto done;
    }
    xmlDocSetRootElement(doc, cur);

    /* set hmac signature length */
    cur = xmlSecTmplSignatureGetSignMethodNode(xmlDocGetRootElement(doc));
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to find SignatureMethod node\n");
	goto done;
    }
    if(xmlSecTmplTransformAddHmacOutputLength(cur, 93) < 0) {
	fprintf(stderr, "Error: failed to set hmac length\n");
	goto done;
    }
    
    cur = xmlSecTmplSignatureAddReference(xmlDocGetRootElement(doc), 
				    xmlSecTransformSha1Id, 
				    BAD_CAST "ref1", NULL, NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add Reference node\n");
	goto done;
    }
    
    cur = xmlSecTmplReferenceAddTransform(cur, xmlSecTransformXPath2Id);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add XPath transform\n");
	goto done;
    }
    
    if(xmlSecTmplTransformAddXPath2(cur, BAD_CAST "intersect", 
				    BAD_CAST "//*[@Id='object1']", NULL) < 0) {
	fprintf(stderr, "Error: failed to set XPath expression\n");
	goto done;    
    }
    
    cur = xmlSecTmplSignatureAddObject(xmlDocGetRootElement(doc), 
				    BAD_CAST "object1", NULL, NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add Object node\n");
	goto done;
    }
    xmlNodeSetContent(cur, BAD_CAST "This is signed data");

    /* add key information */
    cur = xmlSecTmplSignatureEnsureKeyInfo(xmlDocGetRootElement(doc), NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add KeyInfo node\n");
	goto done;	
    }
    if(xmlSecTmplKeyInfoAddKeyName(cur, NULL) == NULL) {
	fprintf(stderr, "Error: failed to add KeyName node\n");
	goto done;	
    }
    
    /* sign */
    start_time = clock();
    if(xmlSecDSigCtxSign(&dsigCtx, xmlDocGetRootElement(doc)) < 0) {
        fprintf(stderr,"Error: signature failed \n");
	goto done;
    }
    total_time += clock() - start_time;    

    if(repeats <= 1) { 
	FILE* f;
        
	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&outputParam));
	if(f == NULL) {
	    fprintf(stderr,"Error: failed to open output file \"%s\"\n",
		    xmlSecAppCmdLineParamGetString(&outputParam));
	    goto done;
	}
	xmlDocDump(f, doc);
	xmlSecAppCloseFile(f);
    }

    res = 0;
done:
    /* print debug info if requested */
    if(repeats <= 1) {
    	xmlSecAppPrintDSigCtx(&dsigCtx);
    }
    xmlSecDSigCtxFinalize(&dsigCtx);
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}
#endif /* XMLSEC_NO_TMPL_TEST */

static int
xmlSecAppPrepareDSigCtx(xmlSecDSigCtxPtr dsigCtx) {
    if(dsigCtx == NULL) {
	fprintf(stderr, "Error: dsig context is null\n");
	return(-1);
    }

    /* set key info params */
    if(xmlSecAppPrepareKeyInfoReadCtx(&(dsigCtx->keyInfoReadCtx)) < 0) {
	fprintf(stderr, "Error: failed to prepare key info context\n");
	return(-1);
    }

    if(xmlSecAppCmdLineParamGetString(&sessionKeyParam) != NULL) {
	dsigCtx->signKey = xmlSecAppCryptoKeyGenerate(xmlSecAppCmdLineParamGetString(&sessionKeyParam),
				NULL, xmlSecKeyDataTypeSession);
	if(dsigCtx->signKey == NULL) {
	    fprintf(stderr, "Error: failed to generate a session key \"%s\"\n",
		    xmlSecAppCmdLineParamGetString(&sessionKeyParam));
	    return(-1);
	}
    }

    /* set dsig params */
    if(xmlSecAppCmdLineParamIsSet(&ignoreManifestsParam)) {
	dsigCtx->flags |= XMLSEC_DSIG_FLAGS_IGNORE_MANIFESTS; 
    }
    if(xmlSecAppCmdLineParamIsSet(&storeReferencesParam)) {
	dsigCtx->flags |= XMLSEC_DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES |
			  XMLSEC_DSIG_FLAGS_STORE_MANIFEST_REFERENCES; 
	print_debug = 1;
    }
    if(xmlSecAppCmdLineParamIsSet(&storeSignaturesParam)) {
	dsigCtx->flags |= XMLSEC_DSIG_FLAGS_STORE_SIGNATURE; 
	print_debug = 1;
    }
    
    if(xmlSecAppCmdLineParamGetStringList(&enabledRefUrisParam) != NULL) {
	dsigCtx->enabledReferenceUris = xmlSecAppGetUriType(
		    xmlSecAppCmdLineParamGetStringList(&enabledRefUrisParam));
	if(dsigCtx->enabledReferenceUris == xmlSecTransformUriTypeNone) {
	    fprintf(stderr, "Error: failed to parse \"%s\"\n",
		    xmlSecAppCmdLineParamGetStringList(&enabledRefUrisParam));
	    return(-1);
	}
    }

    return(0);
}

static void
xmlSecAppPrintDSigCtx(xmlSecDSigCtxPtr dsigCtx) { 
    if(dsigCtx == NULL) {
	return;
    }

    if(xmlSecAppCmdLineParamIsSet(&printDebugParam) || xmlSecAppCmdLineParamIsSet(&printXmlDebugParam)) { 
	print_debug = 0;
    }
    
    /* print debug info if requested */
    if((print_debug != 0) || xmlSecAppCmdLineParamIsSet(&printDebugParam)) {
	xmlSecDSigCtxDebugDump(dsigCtx, stdout);
    }
    
    if(xmlSecAppCmdLineParamIsSet(&printXmlDebugParam)) {	   
	xmlSecDSigCtxDebugXmlDump(dsigCtx, stdout);
    }
}

#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
static int 
xmlSecAppEncryptFile(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecEncCtx encCtx;
    xmlDocPtr doc = NULL;
    xmlNodePtr startTmplNode;
    clock_t start_time;
    int res = -1;

    if(filename == NULL) {
	return(-1);
    }

    if(xmlSecEncCtxInitialize(&encCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: enc context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareEncCtx(&encCtx) < 0) {
	fprintf(stderr, "Error: enc context preparation failed\n");
	goto done;
    }

    /* parse doc and find template node */
    doc = xmlSecParseFile(filename);
    if(doc == NULL) {
	fprintf(stderr, "Error: failed to parse xml file \"%s\"\n", 
		filename);
	goto done;
    }
    startTmplNode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(startTmplNode == NULL) {
	fprintf(stderr, "Error: failed to find default node with name=\"%s\"\n", 
		xmlSecNodeEncryptedData);
	goto done;
    }

    if(xmlSecAppCmdLineParamGetString(&binaryDataParam) != NULL) {
	/* encrypt */
	start_time = clock();            
	if(xmlSecEncCtxUriEncrypt(&encCtx, startTmplNode, BAD_CAST xmlSecAppCmdLineParamGetString(&binaryDataParam)) < 0) {
	    fprintf(stderr, "Error: failed to encrypt file \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&binaryDataParam));
	    goto done;
	}
	total_time += clock() - start_time;    
    } else if(xmlSecAppCmdLineParamGetString(&xmlDataParam) != NULL) {
	/* parse file and select node for encryption */
        data = xmlSecAppXmlDataCreate(xmlSecAppCmdLineParamGetString(&xmlDataParam), NULL, NULL);
	if(data == NULL) {
	    fprintf(stderr, "Error: failed to load file \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&xmlDataParam));
	    goto done;
	}

	/* encrypt */
	start_time = clock();            
	if(xmlSecEncCtxXmlEncrypt(&encCtx, startTmplNode, data->startNode) < 0) {
	    fprintf(stderr, "Error: failed to encrypt xml file \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&xmlDataParam));
	    goto done;
	}
	total_time += clock() - start_time;    
    } else {
	fprintf(stderr, "Error: encryption data not specified (use \"--xml\" or \"--binary\" options)\n");
	goto done;
    }
    
    /* print out result only once per execution */
    if(repeats <= 1) {
	if(encCtx.resultReplaced) {
	    if(xmlSecAppWriteResult((data != NULL) ? data->doc : doc, NULL) < 0) {
		goto done;
	    }
	} else {
	    if(xmlSecAppWriteResult(NULL, encCtx.result) < 0) {
		goto done;
	    }
	}	
    }
    res = 0;    

done:
    /* print debug info if requested */
    if(repeats <= 1) {
    	xmlSecAppPrintEncCtx(&encCtx);
    }
    xmlSecEncCtxFinalize(&encCtx);

    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}

static int 
xmlSecAppDecryptFile(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecEncCtx encCtx;
    clock_t start_time;
    int res = -1;

    if(filename == NULL) {
	return(-1);
    }

    if(xmlSecEncCtxInitialize(&encCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: enc context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareEncCtx(&encCtx) < 0) {
	fprintf(stderr, "Error: enc context preparation failed\n");
	goto done;
    }

    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeEncryptedData, xmlSecEncNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	goto done;
    }

    start_time = clock();  
    if(xmlSecEncCtxDecrypt(&encCtx, data->startNode) < 0) {
	fprintf(stderr, "Error: failed to decrypt file\n");
	goto done;
    }
    total_time += clock() - start_time;    
    
    /* print out result only once per execution */
    if(repeats <= 1) {
	if(encCtx.resultReplaced) {
	    if(xmlSecAppWriteResult(data->doc, NULL) < 0) {
		goto done;
	    }
	} else {
	    if(xmlSecAppWriteResult(NULL, encCtx.result) < 0) {
		goto done;
	    }
	}	
    }
    res = 0;    

done:
    /* print debug info if requested */
    if(repeats <= 1) { 
        xmlSecAppPrintEncCtx(&encCtx);
    }
    xmlSecEncCtxFinalize(&encCtx);

    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

#ifndef XMLSEC_NO_TMPL_TEST
static int 
xmlSecAppEncryptTmpl(void) {
    const char* data = "Hello, World!";
    xmlSecEncCtx encCtx;
    xmlDocPtr doc = NULL;
    xmlNodePtr cur;
    clock_t start_time;
    int res = -1;

    if(xmlSecEncCtxInitialize(&encCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: enc context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareEncCtx(&encCtx) < 0) {
	fprintf(stderr, "Error: enc context preparation failed\n");
	goto done;
    }

    /* prepare template */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
	fprintf(stderr, "Error: failed to create doc\n");
	goto done;
    }

    cur = xmlSecTmplEncDataCreate(doc, xmlSecTransformDes3CbcId, 
				  NULL, NULL, NULL, NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to encryption template\n");
	goto done;	
    }
    xmlDocSetRootElement(doc, cur);

    if(xmlSecTmplEncDataEnsureCipherValue(xmlDocGetRootElement(doc)) == NULL) {
	fprintf(stderr, "Error: failed to add CipherValue node\n");
	goto done;	
    }

    /* add key information */
    cur = xmlSecTmplEncDataEnsureKeyInfo(xmlDocGetRootElement(doc), NULL);
    if(cur == NULL) {
	fprintf(stderr, "Error: failed to add KeyInfo node\n");
	goto done;	
    }
    if(xmlSecTmplKeyInfoAddKeyName(cur, NULL) == NULL) {
	fprintf(stderr, "Error: failed to add KeyName node\n");
	goto done;	
    }

    /* encrypt */
    start_time = clock();            
    if(xmlSecEncCtxBinaryEncrypt(&encCtx, xmlDocGetRootElement(doc), 
				(const xmlSecByte*)data, strlen(data)) < 0) {
	fprintf(stderr, "Error: failed to encrypt data\n");
	goto done;	
    }
    total_time += clock() - start_time;    
    
    /* print out result only once per execution */
    if(repeats <= 1) {
	if(encCtx.resultReplaced) {
	    if(xmlSecAppWriteResult(doc, NULL) < 0) {
		goto done;
	    }
	} else {
	    if(xmlSecAppWriteResult(NULL, encCtx.result) < 0) {
		goto done;
	    }
	}	
    }
    res = 0;    

done:
    /* print debug info if requested */
    if(repeats <= 1) {
    	xmlSecAppPrintEncCtx(&encCtx);
    }
    xmlSecEncCtxFinalize(&encCtx);
    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}
#endif /* XMLSEC_NO_TMPL_TEST */

static int
xmlSecAppPrepareEncCtx(xmlSecEncCtxPtr encCtx) {    
    if(encCtx == NULL) {
	fprintf(stderr, "Error: enc context is null\n");
	return(-1);
    }

    /* set key info params */
    if(xmlSecAppPrepareKeyInfoReadCtx(&(encCtx->keyInfoReadCtx)) < 0) {
	fprintf(stderr, "Error: failed to prepare key info context\n");
	return(-1);
    }

    if(xmlSecAppCmdLineParamGetString(&sessionKeyParam) != NULL) {
	encCtx->encKey = xmlSecAppCryptoKeyGenerate(xmlSecAppCmdLineParamGetString(&sessionKeyParam),
				NULL, xmlSecKeyDataTypeSession);
	if(encCtx->encKey == NULL) {
	    fprintf(stderr, "Error: failed to generate a session key \"%s\"\n",
		    xmlSecAppCmdLineParamGetString(&sessionKeyParam));
	    return(-1);
	}
    }

    if(xmlSecAppCmdLineParamGetStringList(&enabledCipherRefUrisParam) != NULL) {
	encCtx->transformCtx.enabledUris = xmlSecAppGetUriType(
		    xmlSecAppCmdLineParamGetStringList(&enabledCipherRefUrisParam));
	if(encCtx->transformCtx.enabledUris == xmlSecTransformUriTypeNone) {
	    fprintf(stderr, "Error: failed to parse \"%s\"\n",
		    xmlSecAppCmdLineParamGetStringList(&enabledCipherRefUrisParam));
	    return(-1);
	}
    }
    return(0);
}

static void 
xmlSecAppPrintEncCtx(xmlSecEncCtxPtr encCtx) {
    if(encCtx == NULL) {
	return;
    }
    
    /* print debug info if requested */
    if((print_debug != 0) || xmlSecAppCmdLineParamIsSet(&printDebugParam)) {
	xmlSecEncCtxDebugDump(encCtx, stdout);
    }
    
    if(xmlSecAppCmdLineParamIsSet(&printXmlDebugParam)) {	   
	xmlSecEncCtxDebugXmlDump(encCtx, stdout);
    }
}

#endif /* XMLSEC_NO_XMLENC */

#ifndef XMLSEC_NO_XKMS
static int 
xmlSecAppXkissServerLocate(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecXkissServerCtx xkissServerCtx;
    clock_t start_time;
    int res = -1;

    if(filename == NULL) {
	return(-1);
    }

    if(xmlSecXkissServerCtxInitialize(&xkissServerCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: XKISS server context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareXkissServerCtx(&xkissServerCtx) < 0) {
	fprintf(stderr, "Error: XKISS server context preparation failed\n");
	goto done;
    }

    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeLocateRequest, xmlSecXkmsNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	goto done;
    }

    start_time = clock();          
    if((xmlSecXkissServerCtxLocate(&xkissServerCtx, data->startNode) < 0) || (xkissServerCtx.result == NULL)) {
	fprintf(stderr, "Error: failed to process locate request\n");
	goto done;
    }
    total_time += clock() - start_time;    
    
    /* print out result only once per execution */
    if(repeats <= 1) {
	if(xmlSecAppWriteResult(xkissServerCtx.result, NULL) < 0) {
	    goto done;
	}
    }

    res = 0;    

done:
    /* print debug info if requested */
    if(repeats <= 1) { 
        xmlSecAppPrintXkissServerCtx(&xkissServerCtx);
    }
    xmlSecXkissServerCtxFinalize(&xkissServerCtx);

    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

static int 
xmlSecAppXkissServerValidate(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecXkissServerCtx xkissServerCtx;
    clock_t start_time;
    int res = -1;

    if(filename == NULL) {
	return(-1);
    }

    if(xmlSecXkissServerCtxInitialize(&xkissServerCtx, gKeysMngr) < 0) {
	fprintf(stderr, "Error: XKISS server context initialization failed\n");
	return(-1);
    }
    if(xmlSecAppPrepareXkissServerCtx(&xkissServerCtx) < 0) {
	fprintf(stderr, "Error: XKISS server context preparation failed\n");
	goto done;
    }

    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeValidateRequest, xmlSecXkmsNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	goto done;
    }

    start_time = clock();          
    if((xmlSecXkissServerCtxValidate(&xkissServerCtx, data->startNode) < 0) || (xkissServerCtx.result == NULL)) {
	fprintf(stderr, "Error: failed to process locate request\n");
	goto done;
    }
    total_time += clock() - start_time;    
    
    /* print out result only once per execution */
    if(repeats <= 1) {
	if(xmlSecAppWriteResult(xkissServerCtx.result, NULL) < 0) {
	    goto done;
	}
    }

    res = 0;    

done:
    /* print debug info if requested */
    if(repeats <= 1) { 
        xmlSecAppPrintXkissServerCtx(&xkissServerCtx);
    }
    xmlSecXkissServerCtxFinalize(&xkissServerCtx);

    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

static int
xmlSecAppPrepareXkissServerCtx(xmlSecXkissServerCtxPtr xkissServerCtx) {    
    if(xkissServerCtx == NULL) {
	fprintf(stderr, "Error: XKISS  context is null\n");
	return(-1);
    }

    /* set key info params */
    if(xmlSecAppPrepareKeyInfoReadCtx(&(xkissServerCtx->keyInfoReadCtx)) < 0) {
	fprintf(stderr, "Error: failed to prepare key info context\n");
	return(-1);
    }

    return(0);
}

static void 
xmlSecAppPrintXkissServerCtx(xmlSecXkissServerCtxPtr xkissServerCtx) {
    if(xkissServerCtx == NULL) {
	return;
    }
    
    /* print debug info if requested */
    if((print_debug != 0) || xmlSecAppCmdLineParamIsSet(&printDebugParam)) {
	xmlSecXkissServerCtxDebugDump(xkissServerCtx, stdout);
    }
    
    if(xmlSecAppCmdLineParamIsSet(&printXmlDebugParam)) {	   
	xmlSecXkissServerCtxDebugXmlDump(xkissServerCtx, stdout);
    }
}

#endif /* XMLSEC_NO_XKMS */

static void 
xmlSecAppListKeyData(void) {
    fprintf(stdout, "Registered key data klasses:\n");
    xmlSecKeyDataIdListDebugDump(xmlSecKeyDataIdsGet(), stdout);
}

static void 
xmlSecAppListTransforms(void) {
    fprintf(stdout, "Registered transform klasses:\n");
    xmlSecTransformIdListDebugDump(xmlSecTransformIdsGet(), stdout);
}

static int 
xmlSecAppPrepareKeyInfoReadCtx(xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAppCmdLineValuePtr value;
    int ret;
    
    if(keyInfoCtx == NULL) {
	fprintf(stderr, "Error: key info context is null\n");
	return(-1);
    }

#ifndef XMLSEC_NO_X509
    if(xmlSecAppCmdLineParamIsSet(&verificationTimeParam)) {
	keyInfoCtx->certsVerificationTime = xmlSecAppCmdLineParamGetTime(&verificationTimeParam, 0);
    }
    if(xmlSecAppCmdLineParamIsSet(&depthParam)) {
	keyInfoCtx->certsVerificationDepth = xmlSecAppCmdLineParamGetInt(&depthParam, 0);
    }
    if(xmlSecAppCmdLineParamIsSet(&X509SkipStrictChecksParam)) {
	keyInfoCtx->flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_SKIP_STRICT_CHECKS;
    }
#endif /* XMLSEC_NO_X509 */

    /* read enabled key data list */
    for(value = enabledKeyDataParam.value; value != NULL; value = value->next) {
	if(value->strListValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    enabledKeyDataParam.fullName);
	    return(-1);
	} else {
	    xmlSecKeyDataId dataId;
	    const char* p;
	    
	    for(p = value->strListValue; (p != NULL) && ((*p) != '\0'); p += strlen(p)) {
		dataId = xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGet(), BAD_CAST p, xmlSecKeyDataUsageAny);
		if(dataId == xmlSecKeyDataIdUnknown) {
		    fprintf(stderr, "Error: key data \"%s\" is unknown.\n", p);
		    return(-1);
		}
		ret = xmlSecPtrListAdd(&(keyInfoCtx->enabledKeyData), (const xmlSecPtr)dataId);
		if(ret < 0) {
		    fprintf(stderr, "Error: failed to enable key data \"%s\".\n", p);
		    return(-1);
		}
	    }
	}
    }

    /* read enabled RetrievalMethod uris */
    if(xmlSecAppCmdLineParamGetStringList(&enabledRetrievalMethodUrisParam) != NULL) {
	keyInfoCtx->retrievalMethodCtx.enabledUris = xmlSecAppGetUriType(
		    xmlSecAppCmdLineParamGetStringList(&enabledRetrievalMethodUrisParam));
	if(keyInfoCtx->retrievalMethodCtx.enabledUris == xmlSecTransformUriTypeNone) {
	    fprintf(stderr, "Error: failed to parse \"%s\"\n",
		    xmlSecAppCmdLineParamGetStringList(&enabledRetrievalMethodUrisParam));
	    return(-1);
	}
    }

    return(0);
}

static int 
xmlSecAppLoadKeys(void) {
    xmlSecAppCmdLineValuePtr value;
    
    if(gKeysMngr != NULL) {
	fprintf(stderr, "Error: keys manager already initialized.\n");
	return(-1);	
    }    

    /* create and initialize keys manager */
    gKeysMngr = xmlSecKeysMngrCreate();
    if(gKeysMngr == NULL) {
	fprintf(stderr, "Error: failed to create keys manager.\n");
	return(-1);
    }
    if(xmlSecAppCryptoSimpleKeysMngrInit(gKeysMngr) < 0) {
	fprintf(stderr, "Error: failed to initialize keys manager.\n");
	return(-1);
    }    

    /* generate new key file */
    for(value = genKeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", genKeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyGenerate(gKeysMngr, value->strValue, value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to generate key \"%s\".\n", value->strValue);
	    return(-1);
	}	
    }

    /* read all xml key files */
    for(value = keysFileParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", keysFileParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrLoad(gKeysMngr, value->strValue) < 0) {
	    fprintf(stderr, "Error: failed to load xml keys file \"%s\".\n", value->strValue);
	    return(-1);
	}	
    }

    /* read all private keys */
    for(value = privkeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    privkeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(gKeysMngr, 
		    value->strListValue, 
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue, 
		    xmlSecKeyDataFormatPem) < 0) {
	    fprintf(stderr, "Error: failed to load private key from \"%s\".\n", 
		    value->strListValue);
	    return(-1);
	}
    }

    for(value = privkeyDerParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    privkeyDerParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(gKeysMngr, 
		    value->strListValue, 
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue,
		    xmlSecKeyDataFormatDer) < 0) {
	    fprintf(stderr, "Error: failed to load private key from \"%s\".\n", 
		    value->strListValue);
	    return(-1);
	}
    }

    for(value = pkcs8PemParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    pkcs8PemParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(gKeysMngr, 
		    value->strListValue, 
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue,
		    xmlSecKeyDataFormatPkcs8Pem) < 0) {
	    fprintf(stderr, "Error: failed to load private key from \"%s\".\n", 
		    value->strListValue);
	    return(-1);
	}
    }

    for(value = pkcs8DerParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    pkcs8DerParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(gKeysMngr, 
		    value->strListValue, 
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue,
		    xmlSecKeyDataFormatPkcs8Der) < 0) {
	    fprintf(stderr, "Error: failed to load private key from \"%s\".\n", 
		    value->strListValue);
	    return(-1);
	}
    }

    /* read all public keys */
    for(value = pubkeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    pubkeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(gKeysMngr, 
		    value->strListValue, 
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue,
		    xmlSecKeyDataFormatPem) < 0) {
	    fprintf(stderr, "Error: failed to load public key from \"%s\".\n", 
		    value->strListValue);
	    return(-1);
	}
    }

    for(value = pubkeyDerParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    pubkeyDerParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrKeyAndCertsLoad(gKeysMngr, 
		    value->strListValue, 
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue,
		    xmlSecKeyDataFormatDer) < 0) {
	    fprintf(stderr, "Error: failed to load public key from \"%s\".\n", 
		    value->strListValue);
	    return(-1);
	}
    }

#ifndef XMLSEC_NO_AES    
    /* read all AES keys */
    for(value = aeskeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    aeskeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(gKeysMngr, 
		    "aes", value->strValue, value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load aes key from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }
#endif /* XMLSEC_NO_AES */ 

#ifndef XMLSEC_NO_DES    
    /* read all des keys */
    for(value = deskeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    deskeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(gKeysMngr, 
		    "des", value->strValue, value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load des key from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }
#endif /* XMLSEC_NO_DES */ 

#ifndef XMLSEC_NO_HMAC    
    /* read all hmac keys */
    for(value = hmackeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", 
		    hmackeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(gKeysMngr, 
		    "hmac", value->strValue, value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load hmac key from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }
#endif /* XMLSEC_NO_HMAC */ 

#ifndef XMLSEC_NO_X509
    /* read all pkcs12 files */
    for(value = pkcs12Param.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", pkcs12Param.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrPkcs12KeyLoad(gKeysMngr, 
		    value->strValue,
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load pkcs12 key from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }

    /* read all trusted certs */
    for(value = trustedParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", trustedParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrCertLoad(gKeysMngr, 
		    value->strValue, xmlSecKeyDataFormatPem,
		    xmlSecKeyDataTypeTrusted) < 0) {
	    fprintf(stderr, "Error: failed to load trusted cert from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }
    for(value = trustedDerParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", trustedDerParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrCertLoad(gKeysMngr, 
		    value->strValue, xmlSecKeyDataFormatDer,
		    xmlSecKeyDataTypeTrusted) < 0) {
	    fprintf(stderr, "Error: failed to load trusted cert from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }


    /* read all untrusted certs */
    for(value = untrustedParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", untrustedParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrCertLoad(gKeysMngr, 
		    value->strValue, xmlSecKeyDataFormatPem,
		    xmlSecKeyDataTypeNone) < 0) {
	    fprintf(stderr, "Error: failed to load untrusted cert from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }
    for(value = untrustedDerParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", untrustedDerParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrCertLoad(gKeysMngr, 
		    value->strValue, xmlSecKeyDataFormatDer,
		    xmlSecKeyDataTypeNone) < 0) {
	    fprintf(stderr, "Error: failed to load untrusted cert from \"%s\".\n",
		    value->strValue);
	    return(-1);
	}
    }

#endif /* XMLSEC_NO_X509 */    

    return(0);
}

static int intialized = 0;
static int
xmlSecAppInit(void) {
    if(intialized != 0) {
	return(0);
    }
    intialized = 1;
    
    /* Init libxml */     
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlTreeIndentString = "\t";
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */
        	
    /* Init xmlsec */
    if(xmlSecInit() < 0) {
	fprintf(stderr, "Error: xmlsec intialization failed.\n");
	return(-1);
    }

#if !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING)
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST xmlsec_crypto) < 0) {
	fprintf(stderr, "Error: unable to load xmlsec-%s library. Check shared libraries path or use \"--crypto\" option to specify different crypto engine.\n", xmlsec_crypto);
	return(-1);	
    }
#endif /* !defined(XMLSEC_NO_CRYPTO_DYNAMIC_LOADING) && defined(XMLSEC_CRYPTO_DYNAMIC_LOADING) */

    /* Init Crypto */
    if(xmlSecAppCryptoInit(xmlSecAppCmdLineParamGetString(&cryptoConfigParam)) < 0) {
	fprintf(stderr, "Error: xmlsec crypto intialization failed.\n");
	return(-1);
    }
    return(0);
}

static void
xmlSecAppShutdown(void) {
    if(intialized == 0) {
	return;
    }

    /* Shutdown Crypto */
    if(xmlSecAppCryptoShutdown() < 0) {
	fprintf(stderr, "Error: xmlsec crypto shutdown failed.\n");
    }
    
    /* Shutdown xmlsec */
    if(xmlSecShutdown() < 0) {
	fprintf(stderr, "Error: xmlsec shutdown failed.\n");
    }
    
    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
}

static xmlSecAppXmlDataPtr 
xmlSecAppXmlDataCreate(const char* filename, const xmlChar* defStartNodeName, const xmlChar* defStartNodeNs) {
    xmlSecAppXmlDataPtr data;
    xmlNodePtr cur = NULL;
        
    if(filename == NULL) {
	fprintf(stderr, "Error: xml filename is null\n");
	return(NULL);
    }
    
    /* create object */
    data = (xmlSecAppXmlDataPtr) xmlMalloc(sizeof(xmlSecAppXmlData));
    if(data == NULL) {
	fprintf(stderr, "Error: failed to create xml data\n");
	return(NULL);
    }
    memset(data, 0, sizeof(xmlSecAppXmlData));
    
    /* parse doc */
    data->doc = xmlSecParseFile(filename);
    if(data->doc == NULL) {
	fprintf(stderr, "Error: failed to parse xml file \"%s\"\n", 
		filename);
	xmlSecAppXmlDataDestroy(data);
	return(NULL);    
    }
    
    /* load dtd and set default attrs and ids */
    if(xmlSecAppCmdLineParamGetString(&dtdFileParam) != NULL) {
        xmlValidCtxt ctx;

        data->dtd = xmlParseDTD(NULL, BAD_CAST xmlSecAppCmdLineParamGetString(&dtdFileParam));
	if(data->dtd == NULL) {
	    fprintf(stderr, "Error: failed to parse dtd file \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&dtdFileParam));
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}

	memset(&ctx, 0, sizeof(ctx));    
	/* we don't care is doc actually valid or not */
	xmlValidateDtd(&ctx, data->doc, data->dtd);
    }
    
    /* now find the start node */
    if(xmlSecAppCmdLineParamGetString(&nodeIdParam) != NULL) {
	xmlAttrPtr attr;
	    
	attr = xmlGetID(data->doc, BAD_CAST xmlSecAppCmdLineParamGetString(&nodeIdParam));
	if(attr == NULL) {
	    fprintf(stderr, "Error: failed to find node with id=\"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&nodeIdParam));
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
	cur = attr->parent;
    } else if(xmlSecAppCmdLineParamGetString(&nodeNameParam) != NULL) {
	xmlChar* buf;
	xmlChar* name;
	xmlChar* ns;
	
	buf = xmlStrdup(BAD_CAST xmlSecAppCmdLineParamGetString(&nodeNameParam));
	if(buf == NULL) {
	    fprintf(stderr, "Error: failed to duplicate node \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&nodeNameParam));
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
	name = (xmlChar*)strrchr((char*)buf, ':');
	if(name != NULL) {
	    (*(name++)) = '\0';
	    ns = buf;
	} else {
	    name = buf;
	    ns = NULL;
	}
	
	cur = xmlSecFindNode(xmlDocGetRootElement(data->doc), name, ns);
	if(cur == NULL) {
	    fprintf(stderr, "Error: failed to find node with name=\"%s\"\n", 
		    name);
	    xmlFree(buf);
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
	xmlFree(buf);
    } else if(xmlSecAppCmdLineParamGetString(&nodeXPathParam) != NULL) {
	xmlXPathContextPtr ctx = NULL;
	xmlXPathObjectPtr obj = NULL;
	
	ctx = xmlXPathNewContext(data->doc);
	if(ctx == NULL) {
	    fprintf(stderr, "Error: failed to create xpath context\n");
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
	
	obj = xmlXPathEval(BAD_CAST xmlSecAppCmdLineParamGetString(&nodeXPathParam), ctx);
	if(obj == NULL) {
	    fprintf(stderr, "Error: failed to evaluate xpath expression\n");
	    xmlXPathFreeContext(ctx);
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}

	if((obj->nodesetval == NULL) || (obj->nodesetval->nodeNr != 1)) {
	    fprintf(stderr, "Error: xpath expression evaluation does not return a single node as expected\n");
	    xmlXPathFreeObject(obj);
	    xmlXPathFreeContext(ctx);
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
		
	cur = obj->nodesetval->nodeTab[0];
	xmlXPathFreeContext(ctx);
	xmlXPathFreeObject(obj);
	
    } else {
	cur = xmlDocGetRootElement(data->doc);
	if(cur == NULL) {
	    fprintf(stderr, "Error: failed to get root element\n"); 
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
    }
    
    if(defStartNodeName != NULL) {
	data->startNode = xmlSecFindNode(cur, defStartNodeName, defStartNodeNs);
	if(data->startNode == NULL) {
	    fprintf(stderr, "Error: failed to find default node with name=\"%s\"\n", 
		    defStartNodeName);
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
    } else {
	data->startNode = cur;
    }
    
    return(data);
}

static void 
xmlSecAppXmlDataDestroy(xmlSecAppXmlDataPtr data) {
    if(data == NULL) {
	fprintf(stderr, "Error: xml data is null\n");
	return;
    }
    if(data->dtd != NULL) {
	xmlFreeDtd(data->dtd);
    }
    if(data->doc != NULL) {
	xmlFreeDoc(data->doc);
    }
    memset(data, 0, sizeof(xmlSecAppXmlData));
    xmlFree(data);    
}

static xmlSecAppCommand 
xmlSecAppParseCommand(const char* cmd, xmlSecAppCmdLineParamTopic* cmdLineTopics, xmlSecAppCommand* subCommand) {
    if(subCommand != NULL) {
	(*subCommand) = xmlSecAppCommandUnknown;
    }

    if((cmd == NULL) || (cmdLineTopics == NULL)) {
	return(xmlSecAppCommandUnknown);
    } else 

    if((strcmp(cmd, "help") == 0) || (strcmp(cmd, "--help") == 0)) {
	(*cmdLineTopics) = 0;
	return(xmlSecAppCommandHelp);
    } else 

    if((strcmp(cmd, "help-all") == 0) || (strcmp(cmd, "--help-all") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicAll;
	return(xmlSecAppCommandHelp);
    } else 
    
    if((strncmp(cmd, "help-", 5) == 0) || (strncmp(cmd, "--help-", 7) == 0)) {	 
	cmd = (cmd[0] == '-') ? cmd + 7 : cmd + 5;
	if(subCommand) {
	    (*subCommand) = xmlSecAppParseCommand(cmd, cmdLineTopics, NULL);
	} else {
	    (*cmdLineTopics) = 0;
	}
	return(xmlSecAppCommandHelp);
    } else 

    if((strcmp(cmd, "version") == 0) || (strcmp(cmd, "--version") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicVersion;
	return(xmlSecAppCommandVersion);
    } else 

    if((strcmp(cmd, "list-key-data") == 0) || (strcmp(cmd, "--list-key-data") == 0)) {
	(*cmdLineTopics) = 0;
	return(xmlSecAppCommandListKeyData);
    } else 

    if((strcmp(cmd, "list-transforms") == 0) || (strcmp(cmd, "--list-transforms") == 0)) {
	(*cmdLineTopics) = 0;
	return(xmlSecAppCommandListTransforms);
    } else 
    
    if((strcmp(cmd, "keys") == 0) || (strcmp(cmd, "--keys") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral | 
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandKeys);
    } else 
    
#ifndef XMLSEC_NO_XMLDSIG
    if((strcmp(cmd, "sign") == 0) || (strcmp(cmd, "--sign") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicDSigCommon |
			xmlSecAppCmdLineTopicDSigSign |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandSign);
    } else 
    
    if((strcmp(cmd, "verify") == 0) || (strcmp(cmd, "--verify") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicDSigCommon |
			xmlSecAppCmdLineTopicDSigVerify |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandVerify);
    } else 
#ifndef XMLSEC_NO_TMPL_TEST
    if((strcmp(cmd, "sign-tmpl") == 0) || (strcmp(cmd, "--sign-tmpl") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicDSigCommon |
			xmlSecAppCmdLineTopicDSigSign |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandSignTmpl);
    } else 
#endif /* XMLSEC_NO_TMPL_TEST */
    
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
    if((strcmp(cmd, "encrypt") == 0) || (strcmp(cmd, "--encrypt") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicEncCommon |
			xmlSecAppCmdLineTopicEncEncrypt |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandEncrypt);
    } else 

    if((strcmp(cmd, "decrypt") == 0) || (strcmp(cmd, "--decrypt") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicEncCommon |
			xmlSecAppCmdLineTopicEncDecrypt |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandDecrypt);
    } else 

#ifndef XMLSEC_NO_TMPL_TEST
    if((strcmp(cmd, "encrypt-tmpl") == 0) || (strcmp(cmd, "--encrypt-tmpl") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicEncCommon |
			xmlSecAppCmdLineTopicEncEncrypt |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandEncryptTmpl);
    } else 
#endif /* XMLSEC_NO_TMPL_TEST */
#endif /* XMLSEC_NO_XMLENC */

#ifndef XMLSEC_NO_XKMS
    if((strcmp(cmd, "xkiss-server-locate") == 0) || (strcmp(cmd, "--xkiss-server-locate") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicXkmsCommon |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandXkissServerLocate);
    } else 
    if((strcmp(cmd, "xkiss-server-validate") == 0) || (strcmp(cmd, "--xkiss-server-validate") == 0)) {
	(*cmdLineTopics) = xmlSecAppCmdLineTopicGeneral |
			xmlSecAppCmdLineTopicXkmsCommon |
			xmlSecAppCmdLineTopicKeysMngr |
			xmlSecAppCmdLineTopicX509Certs;
	return(xmlSecAppCommandXkissServerValidate);
    } else
#endif /* XMLSEC_NO_XKMS */

    if(1) {
	(*cmdLineTopics) = 0;
	return(xmlSecAppCommandUnknown);
    }
}
	
static void 
xmlSecAppPrintHelp(xmlSecAppCommand command, xmlSecAppCmdLineParamTopic topics) {
    switch(command) {
    case xmlSecAppCommandUnknown:
    case xmlSecAppCommandHelp:
	fprintf(stdout, "%s%s\n", helpCommands1, helpCommands2);
        break;
    case xmlSecAppCommandVersion:
	fprintf(stdout, "%s\n", helpVersion);
        break;
    case xmlSecAppCommandListKeyData:
	fprintf(stdout, "%s\n", helpListKeyData);
        break;
    case xmlSecAppCommandListTransforms:
	fprintf(stdout, "%s\n", helpListTransforms);
        break;
    case xmlSecAppCommandKeys:
	fprintf(stdout, "%s\n", helpKeys);
        break;
    case xmlSecAppCommandSign:
	fprintf(stdout, "%s\n", helpSign);
        break;
    case xmlSecAppCommandVerify:
	fprintf(stdout, "%s\n", helpVerify);
        break;
    case xmlSecAppCommandEncrypt:
	fprintf(stdout, "%s\n", helpEncrypt);
        break;
    case xmlSecAppCommandDecrypt:
	fprintf(stdout, "%s\n", helpDecrypt);
        break;
    case xmlSecAppCommandSignTmpl:
	fprintf(stdout, "%s\n", helpSignTmpl);
        break;
    case xmlSecAppCommandEncryptTmpl:
	fprintf(stdout, "%s\n", helpEncryptTmpl);
        break;
    case xmlSecAppCommandXkissServerLocate:
	fprintf(stdout, "%s\n", helpXkissServerLocate);
        break;
    case xmlSecAppCommandXkissServerValidate:
	fprintf(stdout, "%s\n", helpXkissServerValidate);
        break;
    }
    if(topics != 0) {
	fprintf(stdout, "Options:\n");
	xmlSecAppCmdLineParamsListPrint(parameters, topics, stdout);
	fprintf(stdout, "\n");
    }
    fprintf(stdout, "\n%s\n", bugs);
    fprintf(stdout, "%s\n", copyright);
}

static xmlSecTransformUriType 
xmlSecAppGetUriType(const char* string) {
    xmlSecTransformUriType type = xmlSecTransformUriTypeNone;
    
    while((string != NULL) && (string[0] != '\0')) {
	if(strcmp(string, "empty") == 0) {
	    type |= xmlSecTransformUriTypeEmpty;
	} else if(strcmp(string, "same-doc") == 0) {
	    type |= xmlSecTransformUriTypeSameDocument;
	} else if(strcmp(string, "local") == 0) {
	    type |= xmlSecTransformUriTypeLocal;
	} else if(strcmp(string, "remote") == 0) {
	    type |= xmlSecTransformUriTypeRemote;
	} else {
	    fprintf(stderr, "Error: invalid uri type: \"%s\"\n", string);
	    return(xmlSecTransformUriTypeNone);
	}
	string += strlen(string) + 1;
    }
    return(type);
}

static FILE* 
xmlSecAppOpenFile(const char* filename) {
    FILE* file;
    
    if((filename == NULL) || (strcmp(filename, "-") == 0)) {
	return(stdout);
    }
    file = fopen(filename, "w");
    if(file == NULL) {
	fprintf(stderr, "Error: failed to open file \"%s\"\n", filename);
	return(NULL);
    }
    
    return(file);
}

static void 
xmlSecAppCloseFile(FILE* file) {
    if((file == NULL) || (file == stdout) || (file == stderr)) {
	return;
    }
    
    fclose(file);
}

static int 
xmlSecAppWriteResult(xmlDocPtr doc, xmlSecBufferPtr buffer) {
    FILE* f;

    f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&outputParam));
    if(f == NULL) {
	return(-1);
    }
    if(doc != NULL) {
	xmlDocDump(f, doc);    
    } else if((buffer != NULL) && (xmlSecBufferGetData(buffer) != NULL)) {
    	fwrite(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer), 1, f); 
    } else {
	fprintf(stderr, "Error: both result doc and result buffer are null\n");	
	xmlSecAppCloseFile(f);
	return(-1);
    }    
    xmlSecAppCloseFile(f);
    return(0);
}

