/** 
 * XML Security standards test: XMLDSig
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
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
#include <xmlsec/parser.h>
#include <xmlsec/debug.h>
#include <xmlsec/errors.h>

#include "crypto.h"
#include "cmdline.h"

static const char copyright[] =
    "Written by Aleksey Sanin <aleksey@aleksey.com>.\n"
    "Copyright (C) 2002-2003 Aleksey Sanin.\n"
    "This is free software: see the source for copying information.\n";

static const char bugs[] = 
    "To report bugs or get some help check XML Security Library home page:\n"
    "  http://www.aleksey.com/xmlsec\n";

static const char helpCommands[] =     
    "Usage: xmlsec <command> [<options>] [<file>]\n"
    "where <command> is one of the following:\n"
    "  help      "	"\tdisplay this help information and exit\n"
    "  help-<cmd>"	"\tdisplay help information for <cmd> and exit\n"
    "  version   "	"\tprint version information and exit\n"
    "  keys      "	"\tkeys XML file manipulation\n"
#ifndef XMLSEC_NO_XMLDSIG
    "  sign      "	"\tsign data and output XML document\n"
    "  verify    "	"\tverify signed document\n"
#endif /* XMLSEC_NO_XMLDSIG */
#ifndef XMLSEC_NO_XMLENC
    "  encrypt   "	"\tencrypt data and output XML document\n"
    "  decrypt   "	"\tdecrypt data from XML document\n"
#endif /* XMLSEC_NO_XMLENC */
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

static const char helpEncrypt[] =     
    "Usage: xmlsec encrypt [<options>] <file>\n"
    "Encrypts data and creates XML Encryption using template file <file>\n";

static const char helpDecrypt[] =     
    "Usage: xmlsec decrypt [<options>] <file>\n"
    "Decrypts XML Encryption data in the <file>\n";

#define xmlSecAppCmdLineTopicGeneral		0x0001
#define xmlSecAppCmdLineTopicDSigCommon		0x0002
#define xmlSecAppCmdLineTopicDSigSign		0x0004
#define xmlSecAppCmdLineTopicDSigVerify		0x0008
#define xmlSecAppCmdLineTopicEncCommon		0x0010
#define xmlSecAppCmdLineTopicEncEncrypt		0x0020
#define xmlSecAppCmdLineTopicEncDecrypt		0x0040
#define xmlSecAppCmdLineTopicKeysMngr		0x0080
#define xmlSecAppCmdLineTopicX509Certs		0x0100
#define xmlSecAppCmdLineTopicVersion		0x0200

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

static xmlSecAppCmdLineParam cryptoConfigParam = { 
    xmlSecAppCmdLineTopicGeneral,
    "--crypto-config",
    NULL,
    "--crypto-config"
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
    "\n\tprint openssl errors stack at the end",
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

static xmlSecAppCmdLineParam keysParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--keys",
    "-k",
    "--keys <file>"
    "\n\tload keys from XML file",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam privkeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--privkey",
    NULL,
    "--privkey[:<name>] <file>[,<cafile>[,<cafile>[...]]]"
    "\n\tload private key from PEM file and certificates"
    "\n\tthat verify this key",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam pubkeyParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--pubkey",
    NULL,
    "--pubkey[:<name>] <file>"
    "\n\tload public key from PEM file",
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

static xmlSecAppCmdLineParam allowedParam = { 
    xmlSecAppCmdLineTopicKeysMngr,
    "--allowed",
    NULL,
    "--allowed <list>"
    "\n\tcomma separated list of allowed key origins",
    xmlSecAppCmdLineParamTypeStringList,
    xmlSecAppCmdLineParamFlagParamNameValue | xmlSecAppCmdLineParamFlagMultipleValues,
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
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
    "--output",
    "-o",
    "--output <filename>"
    "\n\twrite result document to file <filename>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam nodeIdParam = { 
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
    "--node-id",
    NULL,
    "--node-id <id>"
    "\n\tset the operation start point to the node with given <id>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam nodeNameParam = { 
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
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
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
    "--node-xpath",
    NULL,   
    "--node-xpath <expr>"
    "\n\tset the operation start point to the first node"
    "\n\tselected by the specified XPath expression",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    
    
static xmlSecAppCmdLineParam dtdfileParam = { 
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
    "--dtdfile",
    NULL,   
    "--dtdfile <file>"
    "\n\tload the specified file as the DTD",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam printDebugParam = { 
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
    "--print-debug",
    NULL,   
    "--print-debug <file>"
    "\n\tprint debug information to <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

static xmlSecAppCmdLineParam printXmlDebugParam = { 
    xmlSecAppCmdLineTopicDSigCommon | xmlSecAppCmdLineTopicEncCommon,
    "--print-xml-debug",
    NULL,   
    "--print-xml-debug <file>"
    "\n\tprint debug information in xml format to <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

/****************************************************************
 *
 * Common dsig params
 *
 ***************************************************************/
#ifndef XMLSEC_NO_XMLDSIG
static xmlSecAppCmdLineParam fakeSignaturesParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--fake-signatures",
    NULL,
    "--fake-signatures"
    "\n\tdisable actual signature calculation for performance testing",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};    

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
    "\n\tstore and print the result of <dsig:Reference> processing"
    "\n\tjust before calculating digest",
    xmlSecAppCmdLineParamTypeFlag,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam storeManifestsParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--store-manifests",
    NULL,
    "--store-manifests"
    "\n\tstore and print the result of <dsig:Manifest> processing"
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

static xmlSecAppCmdLineParam storeAllParam = { 
    xmlSecAppCmdLineTopicDSigCommon,
    "--store-all",
    NULL,
    "--store-all"
    "\n\tcombination of all the \"--store-*\" options",
    xmlSecAppCmdLineParamTypeFlag,
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
static xmlSecAppCmdLineParam binaryParam = { 
    xmlSecAppCmdLineTopicEncEncrypt,
    "--binary",
    NULL,
    "--binary <file>"
    "\n\tbinary <file> to encrypt",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagNone,
    NULL
};

static xmlSecAppCmdLineParam xmlParam = { 
    xmlSecAppCmdLineTopicEncEncrypt,
    "--xml",
    NULL,
    "--xml <file>"
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
    "--trusted",
    NULL,
    "--trusted <file>"
    "\n\tload trusted (root) certificate from PEM file <file>",
    xmlSecAppCmdLineParamTypeString,
    xmlSecAppCmdLineParamFlagMultipleValues,
    NULL
};

static xmlSecAppCmdLineParam untrustedParam = { 
    xmlSecAppCmdLineTopicX509Certs,
    "--untrusted",
    NULL,
    "--untrusted <file>"
    "\n\tload untrusted certificate from PEM file <file>",
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
#endif /* XMLSEC_NO_X509 */    

static xmlSecAppCmdLineParamPtr parameters[] = {
    /* common dsig params */
#ifndef XMLSEC_NO_XMLDSIG
    &ignoreManifestsParam,
    &fakeSignaturesParam,
    &storeReferencesParam,
    &storeManifestsParam,
    &storeSignaturesParam,
    &storeAllParam,
#endif /* XMLSEC_NO_XMLDSIG */

    /* enc params */
#ifndef XMLSEC_NO_XMLENC
    &binaryParam,
    &xmlParam,
#endif /* XMLSEC_NO_XMLENC */
             
    /* common dsig and enc parameters */
    &sessionKeyParam,    
    &outputParam,
    &printDebugParam,
    &printXmlDebugParam,    
    &dtdfileParam,
    &nodeIdParam,
    &nodeNameParam,
    &nodeXPathParam,
    
    /* Keys Manager params */
    &allowedParam,
    &genKeyParam,
    &keysParam,
    &privkeyParam,
    &pubkeyParam,
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
    &verificationTimeParam,
    &depthParam,    
#endif /* XMLSEC_NO_X509 */    
    
    /* General configuration params */
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
    xmlSecAppCommandVersion,
    xmlSecAppCommandKeys,
    xmlSecAppCommandSign,
    xmlSecAppCommandVerify,
    xmlSecAppCommandEncrypt,
    xmlSecAppCommandDecrypt
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
static int			xmlSecAppPrepareKeyInfoCtx	(xmlSecKeyInfoCtxPtr ctx);

#ifndef XMLSEC_NO_XMLDSIG
static int			xmlSecAppSignFile		(const char* filename);
static int			xmlSecAppVerifyFile		(const char* filename);
static xmlSecDSigCtxPtr		xmlSecAppCreateDSigCtx		(void);
static void			xmlSecAppPrintDSigResult	(xmlSecDSigResultPtr result, 
								 const char* filename); 
static void			xmlSecAppPrintDSigXmlResult	(xmlSecDSigResultPtr result, 
								 const char* filename);
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
static int			xmlSecAppEncryptFile		(const char* filename);
static int			xmlSecAppDecryptFile		(const char* filename);
static xmlSecEncCtxPtr		xmlSecAppCreateEncCtx		(void);
static void			xmlSecAppPrintEncCtx		(xmlSecEncCtxPtr encCtx);
#endif /* XMLSEC_NO_XMLENC */


static FILE* 			xmlSecAppOpenFile		(const char* filename);
static void			xmlSecAppCloseFile		(FILE* file);

xmlSecKeysMngrPtr gKeysMngr = NULL;
int repeats = 1;
int print_debug = 0;
clock_t total_time = 0;

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
	fprintf(stdout, "Error: unknown command \"%s\"\n", argv[1]);
	xmlSecAppPrintUsage();
	goto fail;
    }
    
    /* do as much as we can w/o initialization */
    if(command == xmlSecAppCommandHelp) {
	xmlSecAppPrintHelp(subCommand, cmdLineTopics);
	goto success;
    } else if(command == xmlSecAppCommandHelp) {
	fprintf(stdout, "xmlsec %s-%s\n", XMLSEC_VERSION, XMLSEC_CRYPTO);
	fprintf(stderr, "\n");
	fprintf(stderr, "%s\n", bugs);
	fprintf(stderr, "%s\n", copyright);    
	goto success;
    }
    
    /* parse command line */
    pos = xmlSecAppCmdLineParamsListParse(parameters, cmdLineTopics, argv, argc, 2);
    if(pos < 0) {
	fprintf(stdout, "Error: invalid parameters\n");
	xmlSecAppPrintUsage();
	goto fail;
    }
    
    /* is it a help request? */    
    if(xmlSecAppCmdLineParamIsSet(&helpParam)) {
	xmlSecAppPrintHelp(command, cmdLineTopics);
	goto success;
    }
    
    /* we need to have some files at the end */
    if(pos >= argc) {
	fprintf(stdout, "Error: <file> parameter is requried for this command\n");
	xmlSecAppPrintUsage();
	goto fail;
    }
    
    /* now init the xmlsec and all other libs */
    if(xmlSecAppInit() < 0) {
	fprintf(stdout, "Error: initialization failed\n");
	xmlSecAppPrintUsage();
	goto fail;
    }    
    
    /* load keys */
    if(xmlSecAppLoadKeys() < 0) {
	fprintf(stdout, "Error: keys manager creation failed\n");
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
	for(i = pos; i < argc; ++i) {
	    /* process file */
	    switch(command) {
	    case xmlSecAppCommandKeys:
    	        if(xmlSecAppCryptoSimpleKeysMngrSave(gKeysMngr, argv[i], xmlSecKeyDataTypeAny) < 0) {
		    fprintf(stdout, "Error: failed to save keys to file \"%s\"\n", argv[i]);
		    goto fail;
		}
		break;
#ifndef XMLSEC_NO_XMLDSIG
	    case xmlSecAppCommandSign:
    	        if(xmlSecAppSignFile(argv[i]) < 0) {
		    fprintf(stdout, "Error: failed to sign file \"%s\"\n", argv[i]);
		    goto fail;
		}
		break;
	    case xmlSecAppCommandVerify:
    	        if(xmlSecAppVerifyFile(argv[i]) < 0) {
		    fprintf(stdout, "Error: failed to verify file \"%s\"\n", argv[i]);
		    goto fail;
		}
		break;
#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
	    case xmlSecAppCommandEncrypt:
    	        if(xmlSecAppEncryptFile(argv[i]) < 0) {
		    fprintf(stdout, "Error: failed to encrypt file \"%s\"\n", argv[i]);
		    goto fail;
		}
		break;
	    case xmlSecAppCommandDecrypt:
    	        if(xmlSecAppDecryptFile(argv[i]) < 0) {
		    fprintf(stdout, "Error: failed to decrypt file \"%s\"\n", argv[i]);
		    goto fail;
		}
		break;
#endif /* XMLSEC_NO_XMLENC */
	    default:
		fprintf(stdout, "Error: invalid command %d\n", command);
		xmlSecAppPrintUsage();
		goto fail;
	    }
	}
    }

    /* print perf stats results */
    if(xmlSecAppCmdLineParamIsSet(&repeatParam) && 
       (xmlSecAppCmdLineParamGetInt(&repeatParam, 1) > 0)) {
       
	repeats = xmlSecAppCmdLineParamGetInt(&repeatParam, 1);
        fprintf(stderr, "Executed %d tests in %ld msec\n", repeats, total_time / (CLOCKS_PER_SEC / 1000));    
	if(xmlSecTimerGet() > 0.0001) {
	    fprintf(stderr, "The debug timer is %f\n", xmlSecTimerGet());    
	}
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
    xmlSecAppXmlDataPtr data;
    xmlSecDSigCtxPtr dsigCtx;
    xmlSecDSigResultPtr result;
    clock_t start_time;

    if(filename == NULL) {
	return(-1);
    }
    
    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeSignature, xmlSecDSigNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	return(-1);
    }

    dsigCtx = xmlSecAppCreateDSigCtx();
    if(dsigCtx == NULL) {
	fprintf(stderr, "Error: failed create signature context\n");
	xmlSecAppXmlDataDestroy(data);
	return(-1);
    }
    
    /* sign */
    start_time = clock();
    /* TODO: session key */
    if(xmlSecDSigGenerate(dsigCtx, NULL, NULL, data->startNode, &result) < 0) {
        fprintf(stderr,"Error: xmlSecDSigGenerate() failed \n");
	xmlSecDSigCtxDestroy(dsigCtx);
	xmlSecAppXmlDataDestroy(data);
	return(-1);
    }
    total_time += clock() - start_time;    


    if(repeats <= 1) { 
	FILE* f;
        
	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&outputParam));
	if( f != NULL) {
	    xmlDocDump(f, data->doc);
	    xmlSecAppCloseFile(f);
	}
	
	/* print debug info if requested */
	if((print_debug != 0) || xmlSecAppCmdLineParamIsSet(&printDebugParam)) {
	   xmlSecAppPrintDSigResult(result, xmlSecAppCmdLineParamGetString(&printDebugParam));
	}
	if(xmlSecAppCmdLineParamIsSet(&printXmlDebugParam)) {	   
	   xmlSecAppPrintDSigXmlResult(result, xmlSecAppCmdLineParamGetString(&printXmlDebugParam));
	}
    }

    if(result != NULL) {
	xmlSecDSigResultDestroy(result);
    }
    xmlSecDSigCtxDestroy(dsigCtx);
    xmlSecAppXmlDataDestroy(data);
    return(0);
}

static int 
xmlSecAppVerifyFile(const char* filename) {
    xmlSecDSigCtxPtr dsigCtx;
    int res = -1;
    
    if(filename == NULL) {
	return(-1);
    }

    dsigCtx = xmlSecAppCreateDSigCtx();
    if(dsigCtx == NULL) {
	fprintf(stderr, "Error: failed create verification context\n");
	return(-1);
    }
    
    /* TODO */
    fprintf(stdout, "verify >> %s\n", filename);

    xmlSecDSigCtxDestroy(dsigCtx);
    return(res);
}

static xmlSecDSigCtxPtr	
xmlSecAppCreateDSigCtx(void) {
    xmlSecDSigCtxPtr dsigCtx;
    
    dsigCtx = xmlSecDSigCtxCreate(gKeysMngr);
    if(dsigCtx == NULL) {
	fprintf(stderr, "Error: failed to create dsig context\n");
	return(NULL);
    }

    /* set key info params */
    if(xmlSecAppPrepareKeyInfoCtx(&(dsigCtx->keyInfoCtx)) < 0) {
	fprintf(stderr, "Error: failed to prepare key info context\n");
	xmlSecDSigCtxDestroy(dsigCtx);
	return(NULL);
    }

    /* set dsig params */
    if(xmlSecAppCmdLineParamIsSet(&ignoreManifestsParam)) {
	dsigCtx->processManifests = 0; 
    }
    if(xmlSecAppCmdLineParamIsSet(&fakeSignaturesParam)) {
	dsigCtx->fakeSignatures = 1; 
    }
    if(xmlSecAppCmdLineParamIsSet(&storeReferencesParam)) {
	dsigCtx->storeReferences = 1; 
	print_debug = 1;
    }
    if(xmlSecAppCmdLineParamIsSet(&storeManifestsParam)) {
	dsigCtx->storeManifests = 1; 
	print_debug = 1;
    }
    if(xmlSecAppCmdLineParamIsSet(&storeSignaturesParam)) {
	dsigCtx->storeSignatures = 1; 
	print_debug = 1;
    }
    if(xmlSecAppCmdLineParamIsSet(&storeAllParam)) {
	dsigCtx->storeReferences = 1; 
	dsigCtx->storeManifests = 1; 
	dsigCtx->storeSignatures = 1; 
	print_debug = 1;
    }
    
    return(dsigCtx);
}

static void
xmlSecAppPrintDSigResult(xmlSecDSigResultPtr result, const char* filename) { 
    /* TODO */
}

static void
xmlSecAppPrintDSigXmlResult(xmlSecDSigResultPtr result, const char* filename) { 
    /* TODO */
}

#endif /* XMLSEC_NO_XMLDSIG */

#ifndef XMLSEC_NO_XMLENC
static int 
xmlSecAppEncryptFile(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    if(filename == NULL) {
	return(-1);
    }

    /* parse file and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeEncryptedData, xmlSecEncNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load file \"%s\"\n", filename);
	goto done;
    }

    encCtx = xmlSecAppCreateEncCtx();
    if(encCtx == NULL) {
	fprintf(stderr, "Error: failed create decryption context\n");
	goto done;
    }
    
    /* TODO */
    fprintf(stdout, "decrypt >> %s\n", filename);
    res = 0;    

done:
    if(encCtx != NULL) {
	/* print debug info if requested */
        xmlSecAppPrintEncCtx(encCtx);
        xmlSecEncCtxDestroy(encCtx);
    }
    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

static int 
xmlSecAppDecryptFile(const char* filename) {
    xmlSecAppXmlDataPtr data = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    clock_t start_time;
    int res = -1;

    if(filename == NULL) {
	return(-1);
    }

    /* parse template and select start node */
    data = xmlSecAppXmlDataCreate(filename, xmlSecNodeEncryptedData, xmlSecEncNs);
    if(data == NULL) {
	fprintf(stderr, "Error: failed to load template \"%s\"\n", filename);
	goto done;
    }

    /* decrypt */
    encCtx = xmlSecAppCreateEncCtx();
    if(encCtx == NULL) {
	fprintf(stderr, "Error: failed create decryption context\n");
	goto done;
    }
    
    start_time = clock();            
    if((xmlSecEncCtxDecrypt(encCtx, data->startNode) < 0) || (encCtx->encResult == NULL)) {
	fprintf(stderr, "Error: failed to decrypt file\n");
	goto done;
    }
    total_time += clock() - start_time;    
    
    /* print out result only once per execution */
    if(repeats <= 1) {
	FILE* f;

	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&outputParam));
	if(f != NULL) {
	    if(encCtx->replaced) {
		xmlDocDump(f, data->doc);    
    	    } else {
    		fwrite(xmlSecBufferGetData(encCtx->encResult), 
	    	    xmlSecBufferGetSize(encCtx->encResult), 1, f); 
	    }
	    xmlSecAppCloseFile(f);
	}    
    }
    res = 0;    

done:
    if(encCtx != NULL) {
	/* print debug info if requested */
	if(repeats <= 1) { 
    	    xmlSecAppPrintEncCtx(encCtx);
	}
        xmlSecEncCtxDestroy(encCtx);
    }
    if(data != NULL) {
	xmlSecAppXmlDataDestroy(data);
    }
    return(res);
}

static xmlSecEncCtxPtr	
xmlSecAppCreateEncCtx(void) {
    xmlSecEncCtxPtr encCtx;
    
    encCtx = xmlSecEncCtxCreate(gKeysMngr);
    if(encCtx == NULL) {
	fprintf(stderr, "Error: failed to create enc context\n");
	return(NULL);
    }

    /* set key info params */
    if(xmlSecAppPrepareKeyInfoCtx(&(encCtx->keyInfoCtx)) < 0) {
	fprintf(stderr, "Error: failed to prepare key info context\n");
	xmlSecEncCtxDestroy(encCtx);
	return(NULL);
    }

    if(xmlSecAppCmdLineParamGetString(&sessionKeyParam) != NULL) {
	encCtx->encKey = xmlSecAppCryptoKeyGenerate(xmlSecAppCmdLineParamGetString(&sessionKeyParam),
				NULL, xmlSecKeyDataTypeSession);
	if(encCtx->encKey == NULL) {
	    fprintf(stderr, "Error: failed to generate a session key \"%s\"\n",
		    xmlSecAppCmdLineParamGetString(&sessionKeyParam));
	    xmlSecEncCtxDestroy(encCtx);
	    return(NULL);
	}
    }
    

    return(encCtx);
}

static void 
xmlSecAppPrintEncCtx(xmlSecEncCtxPtr encCtx) {
    if(encCtx == NULL) {
	return;
    }
    
    /* print debug info if requested */
    if((print_debug != 0) || xmlSecAppCmdLineParamIsSet(&printDebugParam)) {
	FILE* f;
	
	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&printDebugParam));
	if(f != NULL) {
	    xmlSecEncCtxDebugDump(encCtx, f);
	    xmlSecAppCloseFile(f);
	}
    }
    
    if(xmlSecAppCmdLineParamIsSet(&printXmlDebugParam)) {	   
	FILE* f;
	
	f = xmlSecAppOpenFile(xmlSecAppCmdLineParamGetString(&printXmlDebugParam));
	if(f != NULL) {
	    xmlSecEncCtxDebugXmlDump(encCtx, f);
	    xmlSecAppCloseFile(f);
	}
    }
}

#endif /* XMLSEC_NO_XMLENC */

static int 
xmlSecAppPrepareKeyInfoCtx(xmlSecKeyInfoCtxPtr keyInfoCtx) {
    if(keyInfoCtx == NULL) {
	fprintf(stderr, "Error: key info context is null\n");
	return(-1);
    }

    if(xmlSecAppCmdLineParamIsSet(&verificationTimeParam)) {
	keyInfoCtx->certsVerificationTime = xmlSecAppCmdLineParamGetTime(&verificationTimeParam, 0);
    }
    if(xmlSecAppCmdLineParamIsSet(&depthParam)) {
	keyInfoCtx->certsVerificationDepth = xmlSecAppCmdLineParamGetInt(&depthParam, 0);
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
    for(value = keysParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", keysParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrLoad(gKeysMngr, value->strValue) < 0) {
	    fprintf(stderr, "Error: failed to load xml keys file \"%s\".\n", value->strValue);
	    return(-1);
	}	
    }

    /* read all private keys */
    for(value = privkeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", privkeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(gKeysMngr, 
		    xmlSecAppCmdLineParamGetStringList(&privkeyParam),
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue, 1) < 0) {
	    fprintf(stderr, "Error: failed to load private key.\n");
	    return(-1);
	}
    }

    /* read all public keys */
    for(value = pubkeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", pubkeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrPemKeyAndCertsLoad(gKeysMngr, 
		    xmlSecAppCmdLineParamGetStringList(&pubkeyParam),
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue, 0) < 0) {
	    fprintf(stderr, "Error: failed to load public key.\n");
	    return(-1);
	}
    }

#ifndef XMLSEC_NO_AES    
    /* read all AES keys */
    for(value = aeskeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", aeskeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(gKeysMngr, 
		    "aes",
		    xmlSecAppCmdLineParamGetString(&aeskeyParam),
		    value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load aes key.\n");
	    return(-1);
	}
    }
#endif /* XMLSEC_NO_AES */ 

#ifndef XMLSEC_NO_DES    
    /* read all des keys */
    for(value = deskeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", deskeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(gKeysMngr, 
		    "des",
		    xmlSecAppCmdLineParamGetString(&deskeyParam),
		    value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load des key.\n");
	    return(-1);
	}
    }
#endif /* XMLSEC_NO_DES */ 

#ifndef XMLSEC_NO_HMAC    
    /* read all hmac keys */
    for(value = hmackeyParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", hmackeyParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrBinaryKeyLoad(gKeysMngr, 
		    "hmac",
		    xmlSecAppCmdLineParamGetString(&hmackeyParam),
		    value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load hmac key.\n");
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
		    xmlSecAppCmdLineParamGetString(&pkcs12Param),
		    xmlSecAppCmdLineParamGetString(&pwdParam),
		    value->paramNameValue) < 0) {
	    fprintf(stderr, "Error: failed to load pkcs12 key.\n");
	    return(-1);
	}
    }

    /* read all trusted certs */
    for(value = trustedParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", trustedParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrPemCertLoad(gKeysMngr, 
		    xmlSecAppCmdLineParamGetString(&trustedParam),
		    1) < 0) {
	    fprintf(stderr, "Error: failed to load trusted cert.\n");
	    return(-1);
	}
    }

    /* read all untrusted certs */
    for(value = untrustedParam.value; value != NULL; value = value->next) {
	if(value->strValue == NULL) {
	    fprintf(stderr, "Error: invalid value for option \"%s\".\n", untrustedParam.fullName);
	    return(-1);
	} else if(xmlSecAppCryptoSimpleKeysMngrPemCertLoad(gKeysMngr, 
		    xmlSecAppCmdLineParamGetString(&untrustedParam),
		    0) < 0) {
	    fprintf(stderr, "Error: failed to load untrusted cert.\n");
	    return(-1);
	}
    }

#endif /* XMLSEC_NO_X509 */    

#if TODO
    &allowedParam,
    &verificationTimeParam,
    &depthParam,    
#endif /* TODO */

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
    if(xmlSecAppCmdLineParamGetString(&dtdfileParam) != NULL) {
        xmlValidCtxt ctx;

        data->dtd = xmlParseDTD(NULL, BAD_CAST xmlSecAppCmdLineParamGetString(&dtdfileParam));
	if(data->dtd == NULL) {
	    fprintf(stderr, "Error: failed to parse dtd file \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&dtdfileParam));
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
	data->startNode = attr->parent;
    } else if(xmlSecAppCmdLineParamGetString(&nodeNameParam) != NULL) {
	xmlChar* name;
	xmlChar* ns;
	
	name = xmlStrdup(BAD_CAST xmlSecAppCmdLineParamGetString(&nodeNameParam));
	if(name == NULL) {
	    fprintf(stderr, "Error: failed to duplicate node \"%s\"\n", 
		    xmlSecAppCmdLineParamGetString(&nodeNameParam));
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
	ns = (xmlChar*)strrchr((char*)name, ':');
	if(ns != NULL) {
	    (*(ns++)) = '\0';
	}
	
	data->startNode = xmlSecFindNode(xmlDocGetRootElement(data->doc), name, ns);
	if(data->startNode == NULL) {
	    fprintf(stderr, "Error: failed to find node with name=\"%s\"\n", 
		    name);
	    xmlFree(name);
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
	xmlFree(name);
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
		
	data->startNode = obj->nodesetval->nodeTab[0];
	xmlXPathFreeContext(ctx);
	xmlXPathFreeObject(obj);
	
    } else if(defStartNodeName != NULL) {
	data->startNode = xmlSecFindNode(xmlDocGetRootElement(data->doc), defStartNodeName, defStartNodeNs);
	if(data->startNode == NULL) {
	    fprintf(stderr, "Error: failed to find default node with name=\"%s\"\n", 
		    defStartNodeName);
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
    } else {
	data->startNode = xmlDocGetRootElement(data->doc);
	if(data->startNode == NULL) {
	    fprintf(stderr, "Error: failed to get root element\n"); 
	    xmlSecAppXmlDataDestroy(data);
	    return(NULL);    
	}
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
#endif /* XMLSEC_NO_XMLENC */

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
	fprintf(stdout, "%s\n", helpCommands);
        break;
    case xmlSecAppCommandVersion:
	fprintf(stdout, "%s\n", helpVersion);
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
    }
    if(topics != 0) {
	fprintf(stdout, "Options:\n");
	xmlSecAppCmdLineParamsListPrint(parameters, topics, stdout);
	fprintf(stdout, "\n");
    }
    fprintf(stdout, "%s\n", bugs);
    fprintf(stdout, "%s\n", copyright);
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

