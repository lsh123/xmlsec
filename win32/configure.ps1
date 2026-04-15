<#
.SYNOPSIS
    Configure script for xmlsec, specific for Windows with PowerShell.

    powershell -ExecutionPolicy Bypass -File configure.ps1 <options>

.DESCRIPTION
    This script will configure the libxmlsec build process and create necessary files.
    Run it with 'help' or an invalid option and it will tell you what options it accepts.

.NOTES
    March 2002, Igor Zlatkovic <igor@stud.fh-frankfurt.de>
        Created for LibXML and LibXSLT
    April 2002, Aleksey Sanin <aleksey@aleksey.com>
        Modified for XMLSec Library
    April 2026, Aleksey Sanin <aleksey@aleksey.com>
        Converted to PowerShell
#>

# The source directory, relative to the one where this file resides.
$baseDir = ".."
$srcDir = "$baseDir\src"
$srcDirApps = "$baseDir\apps"
# The directory where we put the binaries after compilation.
$binDir = "binaries"
# Base name of what we are building.
$baseName = "libxmlsec"

# Configure file which contains the version and the output file where
# we can store our build configuration.
$configFile = "$baseDir\configure.ac"
$versionFile = ".\configure.txt"

# This one will generate config.h for version / package info
$optsFile = "$baseDir\config.h"

# Input and output files regarding the xmlsec version.
$versionHeaderIn = "$baseDir\include\xmlsec\version.h.in"
$versionHeader = "$baseDir\include\xmlsec\version.h"

# Version strings for the binary distribution. Will be filled later in the code.
$script:verMajorXmlSec = ""
$script:verMinorXmlSec = ""
$script:verMicroXmlSec = ""

# Libxmlsec features.
$script:withCrypto = "mscng"
$script:withDefaultCrypto = "mscng"
$script:withOpenSSL = 0
$script:withOpenSSLVersion = ""
$script:withNss = 0
$script:withMSCrypto = 0
$script:withMSCng = 1
$script:withLibXSLT = 1
$script:withIconv = 0
$script:withFTP = 0
$script:withHTTP = 0
$script:withGost = 0
$script:withRsaPkcs15 = 1
$script:withLegacyFeatures = 0

# Win32 build options.
$script:buildUnicode = 1
$script:buildDebug = 0
$script:buildWithMemcheck = "no"
$script:buildPedantic = 1
$script:buildCc = "cl.exe"
$script:buildCflags = ""
$script:buildStatic = 1
$script:buildPrefix = "install.dir"
$script:buildBinPrefix = '$(PREFIX)\bin'
$script:buildIncPrefix = '$(PREFIX)\include'
$script:buildLibPrefix = '$(PREFIX)\lib'
$script:buildSoPrefix = '$(PREFIX)\bin'
$script:buildInclude = "."
$script:buildLib = "."
$script:cruntime = "/MD"

# Crypto options
$script:withOpenSSL3Engines = 0

# Local stuff
$script:errorFlag = 0

# Helper function, transforms the option variable into the 'Enabled'
# or 'Disabled' string.
function BoolToStr($opt) {
    if ($opt -eq 0 -or $opt -eq $false) { return "Disabled" }
    if ($opt -eq 1 -or $opt -eq $true) { return "Enabled" }
    $script:errorFlag = 1
    return "Undefined"
}

# Helper function, transforms the argument string into the boolean value.
function StrToBool($opt) {
    if ($opt -eq "0" -or $opt -eq "no") { return 0 }
    if ($opt -eq "1" -or $opt -eq "yes") { return 1 }
    $script:errorFlag = 1
    return 0
}

# Displays the details about how to use this script.
function Show-Usage {
    $scriptName = Split-Path -Leaf $PSCommandPath
    Write-Host "Usage:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File $scriptName <options>"
    Write-Host "  powershell -ExecutionPolicy Bypass -File $scriptName help"
    Write-Host ""        
    Write-Host "Options can be specified in the form <option>=<value>."
    Write-Host ""        
    Write-Host "Win32 build options:"
    Write-Host "  unicode:                  Build Unicode version (default: '$(if ($script:buildUnicode) { 'yes' } else { 'no' })')"
    Write-Host "  debug:                    Build unoptimised debug executables (default: '$(if ($script:buildDebug) { 'yes' } else { 'no' })')"
    Write-Host "  memcheck:                 Build unoptimised debug executables with memcheck reporting (default: '$($script:buildWithMemcheck)')"
    Write-Host "                            with possible options: 'yes' or 'leaks', 'asan', and 'no'."
    Write-Host "  pedantic:                 Build with more warnings enabled (default: '$(if ($script:buildPedantic) { 'yes' } else { 'no' })')"
    Write-Host "  cc:                       Build with the specified compiler (default: '$($script:buildCc)')"
    Write-Host "  cflags:                   Build with the specified compiler flags (default: '$($script:buildCflags)')"
    Write-Host "  static:                   Build static xmlsec libraries (default: '$(if ($script:buildStatic) { 'yes' } else { 'no' })')"
    Write-Host "  prefix:                   Base directory for the installation (default: '$($script:buildPrefix)')"
    Write-Host "  bindir:                   Directory where xmlsec and friends should be installed (default: '$($script:buildBinPrefix)')"
    Write-Host "  incdir:                   Directory where headers should be installed (default: '$($script:buildIncPrefix)')"
    Write-Host "  libdir:                   Directory where static and import libraries should be installed (default: '$($script:buildLibPrefix)')"
    Write-Host "  sodir:                    Directory where shared libraries should be installed (default: '$($script:buildSoPrefix)')"
    Write-Host "  include:                  Additional search path for the compiler, particularily where LibXML2 and other"
    Write-Host "                            dependencies headers can be found (default: '$($script:buildInclude)')"
    Write-Host "  lib:                      Additional search path for the linker, particularily where LibXML2 and other"
    Write-Host "                            dependencies libraroes can be found (default: '$($script:buildLib)')"
    Write-Host ""
    Write-Host "XML Security Library options:"
    Write-Host "  crypto:                   Crypto engines list, first is default crypto engine (default: '$($script:withCrypto)')"
    Write-Host "                            with possible options: 'mscng', 'openssl', 'nss', and 'mscrypto' (deprecated)"
    Write-Host "  xslt:                     LibXSLT is used (default: '$(if ($script:withLibXSLT) { 'yes' } else { 'no' })')"
    Write-Host "  iconv:                    Use the iconv library (default: '$(if ($script:withIconv) { 'yes' } else { 'no' })')"
    Write-Host "  ftp:                      Enable FTP support (default: '$(if ($script:withFTP) { 'yes' } else { 'no' })')"
    Write-Host "  http:                     Enable HTTP support (default: '$(if ($script:withHTTP) { 'yes' } else { 'no' })')"
    Write-Host "  rsa-pkcs15:               Enable RSA PKCS#1.5 key transport (default: '$(if ($script:withRsaPkcs15) { 'yes' } else { 'no' })')"
    Write-Host "  gost:                     Enable GOST algorithms (default: '$(if ($script:withGost) { 'yes' } else { 'no' })')"
    Write-Host "  legacy-features:          Enable legacy features and crypto algorithms (default: '$(if ($script:withLegacyFeatures) { 'yes' } else { 'no' })')"
    Write-Host ""        
    Write-Host "Crypto options:"
    Write-Host "  with-openssl3-engines:    Enable ENGINE interface support for OpenSSL (default: '$(if ($script:withOpenSSL3Engines) { 'yes' } else { 'no' })')"
    Write-Host ""
}

# Parses AC_INIT([name],[version],[url]) and extracts version components.
# Returns an array @(major, minor, subminor) or $null.
function ParseAcInit($str) {
    if ($str -match 'AC_INIT\(\[([^\]]*)\],\[(\d+)\.(\d+)\.(\d+)\],\[([^\]]*)\]\)') {
        return @($Matches[2], $Matches[3], $Matches[4])
    }
    return $null
}

function ParseConfigureAc {
    $ver = $null
    foreach ($ln in Get-Content $configFile) {
        $ver = ParseAcInit $ln
        if ($null -ne $ver) {
            break
        }
    }
    return $ver
}

# Discovers the version we are working with by reading the appropriate
# configuration file. Despite its name, this also writes the configuration
# file included by our makefile.
function DiscoverVersion {
    # Get version from configure.ac AC_INIT
    $ver = ParseConfigureAc
    if ($null -eq $ver) {
        $script:errorFlag = 1
        return
    }
    $script:verMajorXmlSec = $ver[0]
    $script:verMinorXmlSec = $ver[1]
    $script:verMicroXmlSec = $ver[2]

    # Write the configuration file for the Makefile.
    $lines = @()
    $lines += "# $versionFile"
    $lines += "# This file is generated automatically by $(Split-Path -Leaf $PSCommandPath)."
    $lines += ""
    $lines += "XMLSEC_VERSION_MAJOR=$($script:verMajorXmlSec)"
    $lines += "XMLSEC_VERSION_MINOR=$($script:verMinorXmlSec)"
    $lines += "XMLSEC_VERSION_SUBMINOR=$($script:verMicroXmlSec)"
    $lines += "BASEDIR=$baseDir"
    $lines += "XMLSEC_SRCDIR=$srcDir"
    $lines += "APPS_SRCDIR=$srcDirApps"
    $lines += "BINDIR=$binDir"
    $lines += "WITH_CRYPTO=$($script:withCrypto)"
    $lines += "WITH_DEFAULT_CRYPTO=$($script:withDefaultCrypto)"
    $lines += "WITH_OPENSSL=$($script:withOpenSSL)"
    $lines += "WITH_OPENSSL_VERSION=XMLSEC_OPENSSL_$($script:withOpenSSLVersion)"
    $lines += "WITH_OPENSSL3_ENGINES=$(if ($script:withOpenSSL3Engines) { '1' } else { '0' })"
    $lines += "WITH_NSS=$($script:withNss)"
    $lines += "WITH_MSCRYPTO=$($script:withMSCrypto)"
    $lines += "WITH_MSCNG=$($script:withMSCng)"
    $lines += "WITH_LIBXSLT=$(if ($script:withLibXSLT) { '1' } else { '0' })"
    $lines += "WITH_ICONV=$(if ($script:withIconv) { '1' } else { '0' })"
    $lines += "WITH_FTP=$(if ($script:withFTP) { '1' } else { '0' })"
    $lines += "WITH_HTTP=$(if ($script:withHTTP) { '1' } else { '0' })"
    $lines += "WITH_GOST=$(if ($script:withGost) { '1' } else { '0' })"
    $lines += "WITH_RSA_PKCS15=$(if ($script:withRsaPkcs15) { '1' } else { '0' })"
    $lines += "WITH_LEGACY_FEATURES=$(if ($script:withLegacyFeatures) { '1' } else { '0' })"
    $lines += "UNICODE=$(if ($script:buildUnicode) { '1' } else { '0' })"
    $lines += "DEBUG=$(if ($script:buildDebug) { '1' } else { '0' })"
    $lines += "MEMCHECK=$($script:buildWithMemcheck)"
    $lines += "PEDANTIC=$(if ($script:buildPedantic) { '1' } else { '0' })"
    $lines += "CC=$($script:buildCc)"
    $lines += "CFLAGS=$($script:buildCflags)"
    $lines += "STATIC=$(if ($script:buildStatic) { '1' } else { '0' })"
    $lines += "PREFIX=$($script:buildPrefix)"
    $lines += "BINPREFIX=$($script:buildBinPrefix)"
    $lines += "INCPREFIX=$($script:buildIncPrefix)"
    $lines += "LIBPREFIX=$($script:buildLibPrefix)"
    $lines += "SOPREFIX=$($script:buildSoPrefix)"
    $lines += 'INCLUDE=$(INCLUDE);' + $script:buildInclude
    $lines += 'LIB=$(LIB);' + $script:buildLib
    $lines += "CRUNTIME=$($script:cruntime)"
    $lines | Set-Content $versionFile -Encoding UTF8
}

# Configures xmlsec. This one will generate config.h for version / package info.
function ConfigureXmlSec {
    $packageName = "xmlsec1"
    $fullVersion = "$($script:verMajorXmlSec).$($script:verMinorXmlSec).$($script:verMicroXmlSec)"

    $lines = @()
    $lines += "/* config.h. Generated by $(Split-Path -Leaf $PSCommandPath) */"
    $lines += "#define PACKAGE_NAME `"$packageName`""
    $lines += "#define PACKAGE_VERSION `"$fullVersion`""
    $lines += "#define PACKAGE_STRING  `"$packageName $fullVersion`""
    $lines += "#define VERSION `"$fullVersion`""
    $lines | Set-Content $optsFile -Encoding UTF8
}

# This one will generate version.h from version.h.in.
function ConfigureXmlSecVersion {
    if (Test-Path $versionHeader) {
        # version.h is already generated, nothing to do.
        return
    }

    $content = Get-Content $versionHeaderIn
    $output = @()
    $fullVersion = "$($script:verMajorXmlSec).$($script:verMinorXmlSec).$($script:verMicroXmlSec)"
    $versionInfo = "$([int]$script:verMajorXmlSec + [int]$script:verMinorXmlSec):$($script:verMicroXmlSec):$($script:verMinorXmlSec)"

    foreach ($ln in $content) {
        if ($ln -match '@XMLSEC_VERSION_MAJOR@') {
            $output += $ln -replace '@XMLSEC_VERSION_MAJOR@', $script:verMajorXmlSec
        } elseif ($ln -match '@XMLSEC_VERSION_MINOR@') {
            $output += $ln -replace '@XMLSEC_VERSION_MINOR@', $script:verMinorXmlSec
        } elseif ($ln -match '@XMLSEC_VERSION_SUBMINOR@') {
            $output += $ln -replace '@XMLSEC_VERSION_SUBMINOR@', $script:verMicroXmlSec
        } elseif ($ln -match '@XMLSEC_VERSION@') {
            $output += $ln -replace '@XMLSEC_VERSION@', $fullVersion
        } elseif ($ln -match '@XMLSEC_VERSION_INFO@') {
            $output += $ln -replace '@XMLSEC_VERSION_INFO@', $versionInfo
        } else {
            $output += $ln
        }
    }
    $output | Set-Content $versionHeader -Encoding UTF8
}

function ValidateMemcheckOption($opt) {
    if ($opt -eq "yes" -or $opt -eq "leaks") { return "leaks" }
    if ($opt -eq "asan") { return "asan" }
    if ($opt -eq "no") { return "no" }
    return ""
}

#
# main(),
# Execution begins here.
#

# Parse the command-line arguments.
$cruntimeSet = 0
for ($i = 0; ($i -lt $args.Count) -and ($script:errorFlag -eq 0); $i++) {
    $arg = $args[$i]
    $eqIdx = $arg.IndexOf("=")
    $colIdx = $arg.IndexOf(":")
    $opt = ""
    $sepIdx = -1

    if ($eqIdx -ge 0) {
        $opt = $arg.Substring(0, $eqIdx)
        $sepIdx = $eqIdx
    } elseif ($colIdx -ge 0) {
        $opt = $arg.Substring(0, $colIdx)
        $sepIdx = $colIdx
    }

    if ($opt.Length -gt 0) {
        $val = $arg.Substring($sepIdx + 1)
        switch ($opt) {
            "crypto"              { $script:withCrypto = $val }
            "xslt"                { $script:withLibXSLT = StrToBool $val }
            "iconv"               { $script:withIconv = StrToBool $val }
            "ftp"                 { $script:withFTP = StrToBool $val }
            "http"                { $script:withHTTP = StrToBool $val }
            "rsa-pkcs15"          { $script:withRsaPkcs15 = StrToBool $val }
            "gost"                { $script:withGost = StrToBool $val }
            "legacy-features"     { $script:withLegacyFeatures = StrToBool $val }
            "legacy-crypto"       { $script:withLegacyFeatures = StrToBool $val }
            "unicode"             { $script:buildUnicode = StrToBool $val }
            "debug"               { $script:buildDebug = StrToBool $val }
            "memcheck" {
                $script:buildWithMemcheck = ValidateMemcheckOption $val
                if ($script:buildWithMemcheck -eq "") {
                    Write-Host "ERROR: Invalid value for 'memcheck' parameter, supported options are 'yes' or 'leaks', 'asan', and 'no'."
                    $script:errorFlag = 1
                } elseif ($script:buildWithMemcheck -ne "no") {
                    Write-Host "Note: Memcheck option '$($script:buildWithMemcheck)' is selected, enabling debug symbols."
                    $script:buildDebug = 1
                }
            }
            "pedantic"            { $script:buildPedantic = StrToBool $val }
            "cc"                  { $script:buildCc = $val }
            "cflags"              { $script:buildCflags = $val }
            "static"              { $script:buildStatic = StrToBool $val }
            "prefix"              { $script:buildPrefix = $val }
            "incdir"              { $script:buildIncPrefix = $val }
            "bindir"              { $script:buildBinPrefix = $val }
            "libdir"              { $script:buildLibPrefix = $val }
            "sodir"               { $script:buildSoPrefix = $val }
            "include"             { $script:buildInclude = $val }
            "lib"                 { $script:buildLib = $val }
            "cruntime" {
                $script:cruntime = $val
                $cruntimeSet = 1
            }
            "with-openssl3-engines" { $script:withOpenSSL3Engines = StrToBool $val }
            default {
                $script:errorFlag = 1
                Write-Host "ERROR: Unknown option '$opt'"
            }
        }
    } elseif ($i -eq 0 -and $arg -eq "help") {
        Show-Usage
        exit 0
    } else {
        $script:errorFlag = 1
    }
}

if ($cruntimeSet -eq 0 -and $script:buildDebug -ne 0) {
    $script:cruntime = $script:cruntime + "d"
}

# If we have an error here, it is because the user supplied bad parameters.
if ($script:errorFlag -ne 0) {
    Show-Usage
    exit $script:errorFlag
}

# Discover crypto support
$crlist = $script:withCrypto.Split(",")
$script:withCrypto = ""
$script:withDefaultCrypto = ""
for ($j = 0; $j -lt $crlist.Count; $j++) {
    $curcrypto = ""
    switch ($crlist[$j]) {
        "openssl" {
            $curcrypto = "openssl"
            $script:withOpenSSL = 1
            $script:withOpenSSLVersion = "300"  # default
        }
        { $_ -eq "openssl=300" -or $_ -eq "openssl-300" } {
            $curcrypto = "openssl"
            $script:withOpenSSL = 1
            $script:withOpenSSLVersion = "300"
        }
        { $_ -eq "openssl=111" -or $_ -eq "openssl-111" } {
            $curcrypto = "openssl"
            $script:withOpenSSL = 1
            $script:withOpenSSLVersion = "111"
        }
        "nss" {
            $curcrypto = "nss"
            $script:withNss = 1
        }
        "mscrypto" {
            $curcrypto = "mscrypto"
            $script:withMSCrypto = 1
        }
        "mscng" {
            $curcrypto = "mscng"
            $script:withMSCng = 1
        }
        default {
            Write-Host "Unknown crypto engine `"$($crlist[$j])`" is found. Aborting."
            exit $script:errorFlag
        }
    }
    if ($j -eq 0) {
        $script:withDefaultCrypto = $curcrypto
        $script:withCrypto = $curcrypto
    } else {
        $script:withCrypto = $script:withCrypto + " " + $curcrypto
    }
}

# Discover the version.
DiscoverVersion
if ($script:errorFlag -ne 0) {
    Write-Host "Version discovery failed, aborting."
    exit $script:errorFlag
}
Write-Host "$baseName version: $($script:verMajorXmlSec).$($script:verMinorXmlSec).$($script:verMicroXmlSec)"

# Configure libxmlsec.
ConfigureXmlSec
# Generate version.h.
ConfigureXmlSecVersion
if ($script:errorFlag -ne 0) {
    Write-Host "Configuration failed, aborting."
    exit $script:errorFlag
}

# Create the Makefile.
Copy-Item ".\Makefile.msvc" ".\Makefile" -Force
Write-Host "Created Makefile."

# Display the final configuration.
Write-Host ""
Write-Host "XMLSEC configuration"
Write-Host "----------------------------"
Write-Host "          Use Crypto: $($script:withCrypto)"
Write-Host "  Use Default Crypto: $($script:withDefaultCrypto)"
Write-Host "           Use MSCng: $(BoolToStr $script:withMSCng)"
Write-Host "         Use OpenSSL: $(BoolToStr $script:withOpenSSL)"
Write-Host " Use OpenSSL Version: $($script:withOpenSSLVersion)"
Write-Host "             Use NSS: $(BoolToStr $script:withNss)"
Write-Host "        Use MSCrypto: $(BoolToStr $script:withMSCrypto)"
Write-Host "         Use LibXSLT: $(BoolToStr $script:withLibXSLT)"
Write-Host "           Use iconv: $(BoolToStr $script:withIconv)"
Write-Host " Enable RSA PKCS#1.5: $(BoolToStr $script:withRsaPkcs15)"
Write-Host "         Enable GOST: $(BoolToStr $script:withGost)"
Write-Host "Enable legacy crypto: $(BoolToStr $script:withLegacyFeatures)"
Write-Host "         Support FTP: $(BoolToStr $script:withFTP)"
Write-Host "        Support HTTP: $(BoolToStr $script:withHTTP)"
Write-Host ""
Write-Host "Win32 build configuration"
Write-Host "-------------------------"
Write-Host "           Pedantic: $(BoolToStr $script:buildPedantic)"
Write-Host "         C compiler: $($script:buildCc)"
Write-Host "   C compiler flags: $($script:buildCflags)"
Write-Host "   C-Runtime option: $($script:cruntime)"
Write-Host "            Unicode: $(BoolToStr $script:buildUnicode)"
Write-Host "      Debug symbols: $(BoolToStr $script:buildDebug)"
Write-Host "           Memcheck: $($script:buildWithMemcheck)"
Write-Host " Static xmlsec libs: $(BoolToStr $script:buildStatic)"
Write-Host "     Install prefix: $($script:buildPrefix)"
Write-Host "       Put tools in: $($script:buildBinPrefix)"
Write-Host "     Put headers in: $($script:buildIncPrefix)"
Write-Host " Put static libs in: $($script:buildLibPrefix)"
Write-Host " Put shared libs in: $($script:buildSoPrefix)"
Write-Host "       Include path: $($script:buildInclude)"
Write-Host "           Lib path: $($script:buildLib)"
Write-Host ""
Write-Host "Crypto configuration"
Write-Host "-------------------------"
Write-Host " Use OpenSSL3 Engine: $(BoolToStr $script:withOpenSSL3Engines)"
Write-Host ""

# Done.
