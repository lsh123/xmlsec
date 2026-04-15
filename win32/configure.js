/* Configure script for xmlsec, specific for Windows with Scripting Host.
 *
 * This script will configure the libxmlsec build process and create necessary files.
 * Run it with an 'help', or an invalid option and it will tell you what options
 * it accepts.
 *
 * March 2002, Igor Zlatkovic <igor@stud.fh-frankfurt.de>
 *	Created for LibXML and LibXSLT
 * April 2002, Aleksey Sanin <aleksey@aleksey.com>
 *	Modified for XMLSec Libary
 */

/* The source directory, relative to the one where this file resides. */
var baseDir = "..";
var srcDir = baseDir + "\\src";
var srcDirApps = baseDir + "\\apps";
/* The directory where we put the binaries after compilation. */
var binDir = "binaries";
/* Base name of what we are building. */
var baseName = "libxmlsec";

/* Configure file which contains the version and the output file where
   we can store our build configuration. */
var configFile = baseDir + "\\configure.ac";
var versionFile = ".\\configure.txt";

/* This one will generate config.h for version / package info */
var optsFile = baseDir + "\\config.h";

/* Input and output files regarding the xmlsec version. */
var versionHeaderIn = baseDir + "\\include\\xmlsec\\version.h.in";
var versionHeader = baseDir + "\\include\\xmlsec\\version.h";

/* Version strings for the binary distribution. Will be filled later
   in the code. */
var verMajorXmlSec;
var verMinorXmlSec;
var verMicroXmlSec;

/* Libxmlsec features. */
var withCrypto = "mscng";
var withDefaultCrypto = "mscng";
var withOpenSSL = 0;
var withOpenSSLVersion = "";
var withNss = 0;
var withMSCrypto = 0;
var withMSCng = 1;
var withLibXSLT = 1;
var withIconv = 0;     /* disable iconv by default */
var withFTP = 0;       /* disable ftp by default */
var withHTTP = 0;      /* disable http by default */
var withGost = 0;
var withRsaPkcs15 = 1;
var withLegacyFeatures = 0;

/* Win32 build options. */
var buildUnicode = 1;
var buildDebug = 0;
var buildWithMemcheck = "no";
var buildPedantic = 1;
var buildCc = "cl.exe";
var buildCflags = "";
var buildStatic = 1;
var buildPrefix = ".";
var buildBinPrefix = "$(PREFIX)\\bin";
var buildIncPrefix = "$(PREFIX)\\include";
var buildLibPrefix = "$(PREFIX)\\lib";
var buildSoPrefix = "$(PREFIX)\\bin";
var buildInclude = ".";
var buildLib = ".";
var cruntime = "/MD";

/* Crypto options */
var withOpenSSL3Engines = 0;

/* Local stuff */
var error = 0;

/* Helper function, transforms the option variable into the 'Enabled'
   or 'Disabled' string. */
function boolToStr(opt)
{
	if (opt == false)
		return "Disabled";
	else if (opt == true)
		return "Enabled";
	error = 1;
	return "Undefined";
}

/* Helper function, transforms the argument string into the boolean
   value. */
function strToBool(opt)
{
	if (opt == "0" || opt == "no")
		return false;
	else if (opt == "1" || opt == "yes")
		return true;
	error = 1;
	return false;
}

/* Displays the details about how to use this script. */
function usage()
{
	var txt;
	txt = "Usage:\n";
	txt += "  cscript " + WScript.ScriptName + " <options>\n";
	txt += "  cscript " + WScript.ScriptName + " help\n\n";
	txt += "Options can be specified in the form <option>=<value>.\n\n";
	txt += "XmlSec Library options, default value given in parentheses:\n\n";
	txt += "  crypto:     Crypto engines list, first is default: \"openssl\",\n";
	txt += "              \"openssl=111\", \"openssl-111\", \"openssl=300\",\n";
	txt += "              \"openssl-300\", \"nss\", \"mscrypto\", \"mscng\"\n";
	txt += "              (\"" + withCrypto + "\");\n"
 	txt += "  xslt:       LibXSLT is used (" + (withLibXSLT? "yes" : "no")  + ")\n";
 	txt += "  iconv:      Use the iconv library (" + (withIconv? "yes" : "no")  + ")\n";
	txt += "  ftp:        Enable FTP support (" + (withFTP ? "yes" : "no") + ")\n";
	txt += "  http:       Enable HTTP support (" + (withHTTP ? "yes" : "no") + ")\n";
	txt += "  rsa-pkcs15: Enable RSA PKCS#1.5 key transport (" + (withRsaPkcs15 ? "yes" : "no") + ")\n";
	txt += "  gost:	      Enable GOST algorithms (" + (withGost ? "yes" : "no") + ")\n";
	txt += "  legacy-features: Enable legacy features and crypto algorithms (" + (withLegacyFeatures ? "yes" : "no") + ")\n";
	txt += "\nWin32 build options, default value given in parentheses:\n\n";
	txt += "  unicode:    Build Unicode version (" + (buildUnicode? "yes" : "no")  + ")\n";
	txt += "  debug:      Build unoptimised debug executables (" + (buildDebug? "yes" : "no")  + ")\n";
	txt += "  memcheck:   Build unoptimised debug executables with memcheck reporting (" + buildWithMemcheck + ")\n";
	txt += "              with possible options: 'yes' or 'leaks', 'asan', and 'no' (default)."
    txt += "  pedantic:   Build with more warnings enabled (" + (buildPedantic? "yes" : "no") + ")\n";
	txt += "  cc:         Build with the specified compiler(" + buildCc  + ")\n";
	txt += "  cflags:     Build with the specified compiler flags('" + buildCflags  + "')\n";
	txt += "  static:     Build static xmlsec libraries (" + (buildStatic? "yes" : "no")  + ")\n";
	txt += "  prefix:     Base directory for the installation (" + buildPrefix + ")\n";
	txt += "  bindir:     Directory where xmlsec and friends should be installed\n";
	txt += "              (" + buildBinPrefix + ")\n";
	txt += "  incdir:     Directory where headers should be installed\n";
	txt += "              (" + buildIncPrefix + ")\n";
	txt += "  libdir:     Directory where static and import libraries should be\n";
	txt += "              installed (" + buildLibPrefix + ")\n";
	txt += "  sodir:      Directory where shared libraries should be installed\n";
	txt += "              (" + buildSoPrefix + ")\n";
	txt += "  include:    Additional search path for the compiler, particularily\n";
	txt += "              where libxml headers can be found (" + buildInclude + ")\n";
	txt += "  lib:        Additional search path for the linker, particularily\n";
	txt += "              where libxml library can be found (" + buildLib + ")\n";
	txt += "\nCrypto options, default value given in parentheses:\n\n";
	txt += "  with-openssl3-engines:    Enable ENGINE interface support for OpenSSL (" + (withOpenSSL3Engines ? "yes" : "no") + ")\n";
	WScript.Echo(txt);
}

/* Parses AC_INIT([name],[version],[url]) and extracts version components.
   Returns an array [major, minor, subminor]. */
function parseAcInit(str)
{
	var match = str.match(/AC_INIT\(\[([^\]]*)\],\[(\d+)\.(\d+)\.(\d+)\],\[([^\]]*)\]\)/);
	if (match == null) {
		return null;
	}
	return [match[2], match[3], match[4]];
}

function parseConfigureAc(fso) {
	var cf, ln, s, ver;

	/* Parse version from AC_INIT */
	cf = fso.OpenTextFile(configFile, 1);
	while (cf.AtEndOfStream != true) {
		ln = cf.ReadLine();
		ver = parseAcInit(ln);
		if (ver != null) {
			break;
		}
	}
	cf.Close();

	/* done */
	return ver;
}

/* Discovers the version we are working with by reading the apropriate
   configuration file. Despite its name, this also writes the configuration
   file included by our makefile. */
function discoverVersion()
{
	var fso, cf, vf, ln, s;

	fso = new ActiveXObject("Scripting.FileSystemObject");

	/* get version from configure.ac AC_INIT */
	ver = parseConfigureAc(fso);
	if (ver == null) {
		error = 1;
		return;
	}
	verMajorXmlSec = ver[0];
	verMinorXmlSec = ver[1];
	verMicroXmlSec = ver[2];

	/* Write the configuration file for the Makefile. */
	vf = fso.CreateTextFile(versionFile, true);
	vf.WriteLine("# " + versionFile);
	vf.WriteLine("# This file is generated automatically by " + WScript.ScriptName + ".");
	vf.WriteBlankLines(1);
	vf.WriteLine("XMLSEC_VERSION_MAJOR=" + verMajorXmlSec);
	vf.WriteLine("XMLSEC_VERSION_MINOR=" + verMinorXmlSec);
	vf.WriteLine("XMLSEC_VERSION_SUBMINOR=" + verMicroXmlSec);
	vf.WriteLine("BASEDIR=" + baseDir);
	vf.WriteLine("XMLSEC_SRCDIR=" + srcDir);
	vf.WriteLine("APPS_SRCDIR=" + srcDirApps);
	vf.WriteLine("BINDIR=" + binDir);
	vf.WriteLine("WITH_CRYPTO=" + withCrypto);
	vf.WriteLine("WITH_DEFAULT_CRYPTO=" + withDefaultCrypto);
	vf.WriteLine("WITH_OPENSSL=" + withOpenSSL);
	vf.WriteLine("WITH_OPENSSL_VERSION=XMLSEC_OPENSSL_" + withOpenSSLVersion);
	vf.WriteLine("WITH_OPENSSL3_ENGINES=" + (withOpenSSL3Engines ? "1" : "0") );
	vf.WriteLine("WITH_NSS=" + withNss);
	vf.WriteLine("WITH_MSCRYPTO=" + withMSCrypto);
	vf.WriteLine("WITH_MSCNG=" + withMSCng);
	vf.WriteLine("WITH_LIBXSLT=" + (withLibXSLT ? "1" : "0"));
	vf.WriteLine("WITH_ICONV=" + (withIconv ? "1" : "0"));
	vf.WriteLine("WITH_FTP=" + (withFTP ? "1" : "0"));
	vf.WriteLine("WITH_HTTP=" + (withHTTP ? "1" : "0"));
	vf.WriteLine("WITH_GOST=" + (withGost ? "1" : "0"));
	vf.WriteLine("WITH_RSA_PKCS15=" + (withRsaPkcs15 ? "1" : "0"));
	vf.WriteLine("WITH_LEGACY_FEATURES=" + (withLegacyFeatures ? "1" : "0"));
	vf.WriteLine("UNICODE=" + (buildUnicode? "1" : "0"));
	vf.WriteLine("DEBUG=" + (buildDebug? "1" : "0"));
	vf.WriteLine("MEMCHECK=" + buildWithMemcheck);
	vf.WriteLine("PEDANTIC=" + (buildPedantic? "1" : "0"));
	vf.WriteLine("CC=" + buildCc);
	vf.WriteLine("CFLAGS=" + buildCflags);
	vf.WriteLine("STATIC=" + (buildStatic? "1" : "0"));
	vf.WriteLine("PREFIX=" + buildPrefix);
	vf.WriteLine("BINPREFIX=" + buildBinPrefix);
	vf.WriteLine("INCPREFIX=" + buildIncPrefix);
	vf.WriteLine("LIBPREFIX=" + buildLibPrefix);
	vf.WriteLine("SOPREFIX=" + buildSoPrefix);
	vf.WriteLine("INCLUDE=$(INCLUDE);" + buildInclude);
	vf.WriteLine("LIB=$(LIB);" + buildLib);
	vf.WriteLine("CRUNTIME=" + cruntime);
	vf.Close();
}

/* Configures xmlsec. This one will generate config.h for version / package info */
function configureXmlSec()
{
        var fso, of;
        var packageName = "xmlsec1";
        var fullVersion = verMajorXmlSec + "." + verMinorXmlSec + "." + verMicroXmlSec;

        fso = new ActiveXObject("Scripting.FileSystemObject");
        of = fso.CreateTextFile(optsFile, true);
        of.WriteLine("/* config.h. Generated by configure.js */");
        of.WriteLine("#define PACKAGE_NAME \"" + packageName + "\"");
        of.WriteLine("#define PACKAGE_VERSION \"" + fullVersion + "\"");
        of.WriteLine("#define PACKAGE_STRING  \"" + packageName + " " + fullVersion + "\"");
        of.WriteLine("#define VERSION \"" + fullVersion + "\"");
        of.Close();
}

/* This one will generate version.h from version.h.in. */
function configureXmlSecVersion()
{
	var fso, ofi, of, ln, s;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	if (fso.FileExists(versionHeader)) {
		// version.h is already generated, nothing to do.
		return;
	}

	ofi = fso.OpenTextFile(versionHeaderIn, 1);
	of = fso.CreateTextFile(versionHeader, true);
	while (ofi.AtEndOfStream != true) {
		ln = ofi.ReadLine();
		s = new String(ln);
		if (s.search(/\@XMLSEC_VERSION_MAJOR\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSEC_VERSION_MAJOR\@/,
				verMajorXmlSec));
		} else if (s.search(/\@XMLSEC_VERSION_MINOR\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSEC_VERSION_MINOR\@/,
				verMinorXmlSec));
		} else if (s.search(/\@XMLSEC_VERSION_SUBMINOR\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSEC_VERSION_SUBMINOR\@/,
				verMicroXmlSec));
		} else if (s.search(/\@XMLSEC_VERSION\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSEC_VERSION\@/,
				verMajorXmlSec + "." + verMinorXmlSec + "." + verMicroXmlSec));
		} else if (s.search(/\@XMLSEC_VERSION_INFO\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSEC_VERSION_INFO\@/,
				(parseInt(verMajorXmlSec) + parseInt(verMinorXmlSec)) + ":" + verMicroXmlSec + ":" + verMinorXmlSec));
		} else
			of.WriteLine(ln);
	}
	ofi.Close();
	of.Close();
}

function validateMemcheckOption(opt) {
	if (opt == "yes" || opt == "leaks") {
		return "leaks";
	} else if (opt == "asan") {
		return "asan";
	} else if (opt == "no") {
		return "no";
	} else {
		// error, caller will handle it
		return "";
	}
}

/*
 * main(),
 * Execution begins here.
 */

/* Parse the command-line arguments. */
var cruntimeSet = 0
for (i = 0; (i < WScript.Arguments.length) && (error == 0); i++) {
	var arg, opt;
	arg = WScript.Arguments(i);
	opt = arg.substring(0, arg.indexOf("="));
	if (opt.length == 0)
		opt = arg.substring(0, arg.indexOf(":"));
	if (opt.length > 0) {
		if (opt == "crypto")
			withCrypto = arg.substring(opt.length + 1, arg.length);
		else if (opt == "xslt")
			withLibXSLT = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "iconv")
			withIconv = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "ftp")
			withFTP = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "http")
			withHTTP = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "rsa-pkcs15")
			withRsaPkcs15 = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "gost")
			withGost = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "legacy-features")
			withLegacyFeatures = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "legacy-crypto")
			withLegacyFeatures = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "unicode")
			buildUnicode = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "debug")
			buildDebug = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "memcheck") {
			buildWithMemcheck = validateMemcheckOption(arg.substring(opt.length + 1, arg.length));
			if (buildWithMemcheck == "") {
				WScript.Echo("ERROR: Invalid value for 'memcheck' parameter, supported options are 'yes' or 'leaks', 'asan', and 'no'.\n");
				error = 1;
			} else if (buildWithMemcheck != "no") {
				WScript.Echo("Note: memcheck option '" + buildWithMemcheck + "' will be used, enabling debug symbols.\n");
				buildDebug = true;
			}
		} else if (opt == "pedantic")
			buildPedantic = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "cc")
			buildCc = arg.substring(opt.length + 1, arg.length);
		else if (opt == "cflags")
			buildCflags = arg.substring(opt.length + 1, arg.length);
		else if (opt == "static")
			buildStatic = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "prefix")
			buildPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "incdir")
			buildIncPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "bindir")
			buildBinPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "libdir")
			buildLibPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "sodir")
			buildSoPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "incdir")
			buildIncPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "include")
			buildInclude = arg.substring(opt.length + 1, arg.length);
		else if (opt == "lib")
			buildLib = arg.substring(opt.length + 1, arg.length);
		else if (opt == "cruntime") {
			cruntime = arg.substring(opt.length + 1, arg.length);
			cruntimeSet = 1;
		} else if (opt == "with-openssl3-engines") {
			withOpenSSL3Engines = strToBool(arg.substring(opt.length + 1, arg.length));
		} else {
			error = 1;
            WScript.Echo("ERROR: Unknown option'" + opt + "'\n");
		}
	} else if (i == 0 && arg == "help") {
		usage();
		WScript.Quit(0);
	} else {
		error = 1;
	}
}

if (cruntimeSet == 0 && buildDebug != 0) {
	cruntime = cruntime + "d";
}

// If we have an error here, it is because the user supplied bad parameters.
if (error != 0) {
	usage();
	WScript.Quit(error);
}

// Discover crypto support
var crlist, j, curcrypto;
crlist = withCrypto.split(",");
withCrypto = "";
withDefaultCrypto = "";
for (j = 0; j < crlist.length; j++) {
	if (crlist[j] == "openssl") {
		curcrypto="openssl";
		withOpenSSL = 1;
		withOpenSSLVersion = "300"; /* default */
	} else if (crlist[j] == "openssl=300" || crlist[j] == "openssl-300") {
		curcrypto = "openssl";
		withOpenSSL = 1;
		withOpenSSLVersion = "300";
	} else if (crlist[j] == "openssl=111" || crlist[j] == "openssl-111") {
		curcrypto="openssl";
		withOpenSSL = 1;
		withOpenSSLVersion = "111";
	} else if (crlist[j] == "nss") {
		curcrypto="nss";
		withNss = 1;
	} else if (crlist[j] == "mscrypto") {
		curcrypto="mscrypto";
		withMSCrypto = 1;
	} else if (crlist[j] == "mscng") {
		curcrypto="mscng";
		withMSCng = 1;
	} else {
		WScript.Echo("Unknown crypto engine \"" + crlist[j] + "\" is found. Aborting.");
		WScript.Quit(error);
	}
	if (j == 0) {
		withDefaultCrypto = curcrypto;
		withCrypto = curcrypto;
	} else {
		withCrypto = withCrypto + " " + curcrypto;
	}
}

// Discover the version.
discoverVersion();
if (error != 0) {
	WScript.Echo("Version discovery failed, aborting.");
	WScript.Quit(error);
}
WScript.Echo(baseName + " version: " + verMajorXmlSec + "." + verMinorXmlSec + "." + verMicroXmlSec);


// Configure libxmlsec.
configureXmlSec();
// Generate version.h.
configureXmlSecVersion();
if (error != 0) {
	WScript.Echo("Configuration failed, aborting.");
	WScript.Quit(error);
}


// Create the Makefile.
var fso = new ActiveXObject("Scripting.FileSystemObject");
fso.CopyFile(".\\Makefile.msvc", ".\\Makefile", true);
WScript.Echo("Created Makefile.");

// Display the final configuration.
var txtOut = "\nXMLSEC configuration\n";
txtOut += "----------------------------\n";
txtOut += "          Use Crypto: " + withCrypto + "\n";
txtOut += "  Use Default Crypto: " + withDefaultCrypto + "\n";
txtOut += "           Use MSCng: " + boolToStr(withMSCng) + "\n";
txtOut += "         Use OpenSSL: " + boolToStr(withOpenSSL) + "\n";
txtOut += " Use OpenSSL Version: " + withOpenSSLVersion + "\n";
txtOut += "             Use NSS: " + boolToStr(withNss) + "\n";
txtOut += "        Use MSCrypto: " + boolToStr(withMSCrypto) + "\n";
txtOut += "         Use LibXSLT: " + boolToStr(withLibXSLT) + "\n";
txtOut += "           Use iconv: " + boolToStr(withIconv) + "\n";
txtOut += " Enable RSA PKCS#1.5: " + boolToStr(withRsaPkcs15) + "\n";
txtOut += "         Enable GOST: " + boolToStr(withGost) + "\n";
txtOut += "Enable legacy crypto: " + boolToStr(withLegacyFeatures) + "\n";
txtOut += "         Support FTP: " + boolToStr(withFTP) + "\n";
txtOut += "        Support HTTP: " + boolToStr(withHTTP) + "\n";
txtOut += "\n";
txtOut += "Win32 build configuration\n";
txtOut += "-------------------------\n";
txtOut += "           Pedantic: " + boolToStr(buildPedantic) + "\n";
txtOut += "         C compiler: " + buildCc + "\n";
txtOut += "   C compiler flags: " + buildCflags + "\n";
txtOut += "   C-Runtime option: " + cruntime + "\n";
txtOut += "            Unicode: " + boolToStr(buildUnicode) + "\n";
txtOut += "      Debug symbols: " + boolToStr(buildDebug) + "\n";
txtOut += "           Memcheck: " + buildWithMemcheck + "\n";
txtOut += " Static xmlsec libs: " + boolToStr(buildStatic) + "\n";
txtOut += "     Install prefix: " + buildPrefix + "\n";
txtOut += "       Put tools in: " + buildBinPrefix + "\n";
txtOut += "     Put headers in: " + buildIncPrefix + "\n";
txtOut += " Put static libs in: " + buildLibPrefix + "\n";
txtOut += " Put shared libs in: " + buildSoPrefix + "\n";
txtOut += "       Include path: " + buildInclude + "\n";
txtOut += "           Lib path: " + buildLib + "\n";
txtOut += "\n";
txtOut += "Crypto configuration\n";
txtOut += "-------------------------\n";
txtOut += " Use OpenSSL3 Engine: " + boolToStr(withOpenSSL3Engines) + "\n";
txtOut += "\n";
txtOut += "\n";
txtOut += "DEPREACTED: the configure.js script is no longer supported and will be removed in a future release.\n"
txtOut += "Please use PowerShell version (configure.ps1) to configure the build instead.\n";
txtOut += "\n";

WScript.Echo(txtOut);

// Done.
