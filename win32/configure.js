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
var configFile = baseDir + "\\configure.in";
var versionFile = ".\\configure.txt";

/* Input and output files regarding the lib(e)xml features. The second
   output file is there for the compatibility reasons, otherwise it
   is identical to the first. */
var optsFileIn = baseDir + "\\config.h.in";
var optsFile = baseDir + "\\config.h";

/* Version strings for the binary distribution. Will be filled later 
   in the code. */
var verMajorXmlSec;
var verMinorXmlSec;
var verMicroXmlSec;

/* Libxmlsec features. */
var withCrypto = "openssl";
var withDefaultCrypto = "openssl";
var withOpenSSL = 0;
var withOpenSSL096 = 0;
var withNss = 0;
var withMSCrypto = 0;
var withLibXSLT = 1;
var withIconv = 1;

/* Win32 build options. */
var buildDebug = 0;
var buildStatic = 1;
var buildWithDLSupport = 1;
var buildPrefix = ".";
var buildBinPrefix = "$(PREFIX)\\bin";
var buildIncPrefix = "$(PREFIX)\\include";
var buildLibPrefix = "$(PREFIX)\\lib";
var buildSoPrefix = "$(PREFIX)\\lib";
var buildInclude = ".";
var buildLib = ".";
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
	txt += "Options can be specified in the form <option>=<value>, where the value is\n";
	txt += "either 'yes' or 'no'.\n\n";
	txt += "XmlSec Library options, default value given in parentheses:\n\n";
	txt += "  crypto:     Crypto engines list, first is default: \"openssl\",\n";
	txt += "              \"openssl_096\", \"nss\", \"mscrypto\" (\"" + withCrypto + "\");\n"
 	txt += "  xslt:       LibXSLT is used (" + (withLibXSLT? "yes" : "no")  + ")\n";	
 	txt += "  iconv:      Use the iconv library (" + (withIconv? "yes" : "no")  + ")\n";	
	txt += "\nWin32 build options, default value given in parentheses:\n\n";
	txt += "  debug:      Build unoptimised debug executables (" + (buildDebug? "yes" : "no")  + ")\n";
	txt += "  static:     Link libxmlsec statically to xmlsec (" + (buildStatic? "yes" : "no")  + ")\n";
	txt += "  with-dl:    Enable dynamic loading of xmlsec-crypto libraries (" + (buildWithDLSupport? "yes" : "no")  + ")\n";
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
	WScript.Echo(txt);
}

/* Discovers the version we are working with by reading the apropriate
   configuration file. Despite its name, this also writes the configuration
   file included by our makefile. */
function discoverVersion()
{
	var fso, cf, vf, ln, s;

	fso = new ActiveXObject("Scripting.FileSystemObject");
	cf = fso.OpenTextFile(configFile, 1);
	vf = fso.CreateTextFile(versionFile, true);
	vf.WriteLine("# " + versionFile);
	vf.WriteLine("# This file is generated automatically by " + WScript.ScriptName + ".");
	vf.WriteBlankLines(1);
	while (cf.AtEndOfStream != true) {
		ln = cf.ReadLine();
		s = new String(ln);
		if (s.search(/^XMLSEC_VERSION_MAJOR/) != -1) {
			WScript.Echo(verMajorXmlSec);
			vf.WriteLine(s);
			verMajorXmlSec = s.substring(s.indexOf("=") + 1, s.length)
		} else if(s.search(/^XMLSEC_VERSION_MINOR/) != -1) {
			vf.WriteLine(s);
			verMinorXmlSec = s.substring(s.indexOf("=") + 1, s.length)
		} else if(s.search(/^XMLSEC_VERSION_SUBMINOR/) != -1) {
			vf.WriteLine(s);
			verMicroXmlSec = s.substring(s.indexOf("=") + 1, s.length)
		}		
	}
	cf.Close();
	vf.WriteLine("BASEDIR=" + baseDir);
	vf.WriteLine("XMLSEC_SRCDIR=" + srcDir);
	vf.WriteLine("APPS_SRCDIR=" + srcDirApps);
	vf.WriteLine("BINDIR=" + binDir);
	vf.WriteLine("WITH_CRYPTO=" + withCrypto);	
	vf.WriteLine("WITH_DEFAULT_CRYPTO=" + withDefaultCrypto);	
	vf.WriteLine("WITH_OPENSSL=" + withOpenSSL);	
	vf.WriteLine("WITH_OPENSSL_096=" + withOpenSSL096);	
	vf.WriteLine("WITH_NSS=" + withNss);	
	vf.WriteLine("WITH_MSCRYPTO=" + withMSCrypto);	
	vf.WriteLine("WITH_LIBXSLT=" + (withLibXSLT ? "1" : "0"));
	vf.WriteLine("WITH_ICONV=" + (withIconv ? "1" : "0"));
	vf.WriteLine("DEBUG=" + (buildDebug? "1" : "0"));
	vf.WriteLine("STATIC=" + (buildStatic? "1" : "0"));
	vf.WriteLine("WITH_DL=" + (buildWithDLSupport ? "1" : "0"));
	vf.WriteLine("PREFIX=" + buildPrefix);
	vf.WriteLine("BINPREFIX=" + buildBinPrefix);
	vf.WriteLine("INCPREFIX=" + buildIncPrefix);
	vf.WriteLine("LIBPREFIX=" + buildLibPrefix);
	vf.WriteLine("SOPREFIX=" + buildSoPrefix);
	vf.WriteLine("INCLUDE=$(INCLUDE);" + buildInclude);
	vf.WriteLine("LIB=$(LIB);" + buildLib);
	vf.Close();
}

/* Configures xmlsec. This one will generate config.h from config.h.in
   taking what the user passed on the command line into account. */
function configureXmlSec()
{
	var fso, ofi, of, ln, s;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	ofi = fso.OpenTextFile(optsFileIn, 1);
	of = fso.CreateTextFile(optsFile, true);
	while (ofi.AtEndOfStream != true) {
		ln = ofi.ReadLine();
		s = new String(ln);
		if (s.search(/\@VERSION\@/) != -1) {
			of.WriteLine(s.replace(/\@VERSION\@/, 
				verMajorXmlSec + "." + verMinorXmlSec + "." + verMicroXmlSec));
		} else if (s.search(/\@XMLSECVERSION_NUMBER\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSECVERSION_NUMBER\@/, 
				verMajorXmlSec*10000 + verMinorXmlSec*100 + verMicroXmlSec*1));
		} else
			of.WriteLine(ln);
	}
	ofi.Close();
	of.Close();
}

/* Creates the readme file for the binary distribution of 'bname', for the
   version 'ver' in the file 'file'. This one is called from the Makefile when
   generating a binary distribution. The parameters are passed by make. */
function genReadme(bname, ver, file)
{
	var fso, f;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	f = fso.CreateTextFile(file, true);
	f.WriteLine("  " + bname + " " + ver);
	f.WriteLine("  --------------");
	f.WriteBlankLines(1);
	f.WriteLine("  This is " + bname + ", version " + ver + ", binary package for the native Win32/IA32");
	f.WriteLine("platform.");
	f.WriteBlankLines(1);
	f.WriteLine("  The directory named 'include' contains the header files. Place its");
	f.WriteLine("contents somewhere where it can be found by the compiler.");
	f.WriteLine("  The directory which answers to the name 'lib' contains the static and");
	f.WriteLine("dynamic libraries. Place them somewhere where they can be found by the");
	f.WriteLine("linker. The files whose names end with '_a.lib' are aimed for static");
	f.WriteLine("linking, the other files are lib/dll pairs.");
	f.WriteLine("  The directory called 'util' contains various programs which count as a");
	f.WriteLine("part of " + bname + ".");
	f.WriteBlankLines(1);
	f.WriteLine("  If you plan to develop your own programme, in C, which uses " + bname + ", then");
	f.WriteLine("you should know what to do with the files in the binary package. If you don't,");
	f.WriteLine("know this, then please, please do some research on how to use a");
	f.WriteLine("third-party library in a C programme. The topic belongs to the very basics"); 
	f.WriteLine("and you will not be able to do much without that knowledge.");
	f.WriteBlankLines(1);
	f.WriteLine("  If you wish to use " + bname + " solely through the supplied utilities,");
	f.WriteLine("such as xmlsec executable, then all you need to do is place the");
	f.WriteLine("contents of the 'lib' and 'util' directories from the binary package in a"); 
	f.WriteLine("directory on your disc which is mentioned in your PATH environment"); 
	f.WriteLine("variable. You can use an existing directory which is allready in the"); 
	f.WriteLine("path, such as 'C:\WINDOWS', or 'C:\WINNT'. You can also create a new"); 
	f.WriteLine("directory for " + bname + " and place the files there, but be sure to modify"); 
	f.WriteLine("the PATH environment variable and add that new directory to its list.");
	f.WriteBlankLines(1);
	f.WriteLine("  If you use other software which needs " + bname + ", then please consult the"); 
	f.WriteLine("documentation of that software and see if it mentions something about");
	f.WriteLine("how it uses " + bname + " and how it expects it to be installed. If you find");
	f.WriteLine("nothing, then the default installation, as described in the previous"); 
	f.WriteLine("paragraph, should be suficient.");
	f.WriteBlankLines(1);
	f.WriteLine("  If there is something you cannot keep for yourself, such as a problem,");
	f.WriteLine("a cheer of joy, a comment or a suggestion, feel free to contact me using");
	f.WriteLine("the address below.");
	f.WriteBlankLines(1);
	f.WriteLine("Igor Zlatkovic (igor@zlatkovic.com)");
	f.Close();
}

/*
 * main(),
 * Execution begins here.
 */

/* Parse the command-line arguments. */
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
		else if (opt == "debug")
			buildDebug = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "static")
			buildStatic = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "with-dl")
			buildWithDLSupport = strToBool(arg.substring(opt.length + 1, arg.length));
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
		else
			error = 1;
	} else if (i == 0) {
		if (arg == "genreadme") {
			// This command comes from the Makefile and will not be checked
			// for errors, because Makefile will always supply right parameters.
			genReadme(WScript.Arguments(1), WScript.Arguments(2), WScript.Arguments(3));
			WScript.Quit(0);
		} else if (arg == "help") {
			usage();
			WScript.Quit(0);
		}
	} else
		error = 1;
}
// If we have an error here, it is because the user supplied bad parameters.
if (error != 0) {
	usage();
	WScript.Quit(error);
}

// Discover crypto support
var crlist, j;
crlist = withCrypto.split(",");			
withCrypto = "";
for (j = 0; j < crlist.length; j++) {		
	if (crlist[j] == "openssl")
		withOpenSSL = 1;
	else if (crlist[j] == "openssl_096")
		withOpenSSL096 = 1;
	else if (crlist[j] == "nss")
		withNss = 1;
	else if (crlist[j] == "mscrypto")
		withMSCrypto = 1;
	else {
		WScript.Echo("Unknown crypto engine \"" + crlist[j] + "\" is found. Aborting.");
		WScript.Quit(error);
	}
	withCrypto = withCrypto + " " + crlist[j];
}
if ((withOpenSSL == 1) && (withOpenSSL096 == 1)) {
	WScript.Echo("Only one of \"openssl\" and \"openssl_096\" could be specified. Aborting.");
	WScript.Quit(error);
}
withDefaultCrypto = crlist[0];
if (withDefaultCrypto == "openssl_096")
	withDefaultCrypto = "openssl";

// Discover the version.
discoverVersion();
if (error != 0) {
	WScript.Echo("Version discovery failed, aborting.");
	WScript.Quit(error);
}
WScript.Echo(baseName + " version: " + verMajorXmlSec + "." + verMinorXmlSec + "." + verMicroXmlSec);


// Configure libxmlsec.
configureXmlSec();
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
txtOut += "        Use Crypto: " + withCrypto + "\n";
txtOut += "Use Default Crypto: " + withDefaultCrypto + "\n";
txtOut += "       Use OpenSSL: " + boolToStr(withOpenSSL) + "\n";
txtOut += "   Use OpenSSL 096: " + boolToStr(withOpenSSL096) + "\n";
txtOut += "           Use NSS: " + boolToStr(withNss) + "\n";
txtOut += "      Use MSCrypto: " + boolToStr(withMSCrypto) + "\n";
txtOut += "       Use LibXSLT: " + boolToStr(withLibXSLT) + "\n";
txtOut += "         Use iconv: " + boolToStr(withIconv) + "\n";
txtOut += "\n";
txtOut += "Win32 build configuration\n";
txtOut += "-------------------------\n";
txtOut += "     Debug symbols: " + boolToStr(buildDebug) + "\n";
txtOut += "     Static xmlsec: " + boolToStr(buildStatic) + "\n";
txtOut += "  Enable DL suport: " + boolToStr(buildWithDLSupport) + "\n";
txtOut += "    Install prefix: " + buildPrefix + "\n";
txtOut += "      Put tools in: " + buildBinPrefix + "\n";
txtOut += "    Put headers in: " + buildIncPrefix + "\n";
txtOut += "Put static libs in: " + buildLibPrefix + "\n";
txtOut += "Put shared libs in: " + buildSoPrefix + "\n";
txtOut += "      Include path: " + buildInclude + "\n";
txtOut += "          Lib path: " + buildLib + "\n";
WScript.Echo(txtOut);

// Done.
