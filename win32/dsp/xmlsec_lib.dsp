# Microsoft Developer Studio Project File - Name="xmlsec_lib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=xmlsec_lib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "xmlsec_lib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "xmlsec_lib.mak" CFG="xmlsec_lib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "xmlsec_lib - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "xmlsec_lib - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "xmlsec_lib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ReleaseLib"
# PROP BASE Intermediate_Dir "ReleaseLib"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "ReleaseLib"
# PROP Intermediate_Dir "ReleaseLib"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../" /I "../../../openssl/include" /I "../../../libxml2/include" /I "../../../libxslt/include" /I ".." /I "../.." /I "../../include" /I "../../../../openssl/include" /I "../../../../libxml2/include" /I "../../../../libxslt/include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"Release\libxmlsec_a.lib"

!ELSEIF  "$(CFG)" == "xmlsec_lib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "DebugLib"
# PROP BASE Intermediate_Dir "DebugLib"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "DebugLib"
# PROP Intermediate_Dir "DebugLib"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "../../../openssl/include" /I "../../../libxml2/include" /I "../../../libxslt/include" /I ".." /I "../.." /I "../../include" /I "../../../../openssl/include" /I "../../../../libxml2/include" /I "../../../../libxslt/include" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"Debug\libxmlsec_a.lib"

!ENDIF 

# Begin Target

# Name "xmlsec_lib - Win32 Release"
# Name "xmlsec_lib - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\src\aes.c
# End Source File
# Begin Source File

SOURCE=..\..\src\base64.c
# End Source File
# Begin Source File

SOURCE=..\..\src\bn.c
# End Source File
# Begin Source File

SOURCE=..\..\src\buffered.c
# End Source File
# Begin Source File

SOURCE=..\..\src\c14n.c
# End Source File
# Begin Source File

SOURCE=..\..\src\ciphers.c
# End Source File
# Begin Source File

SOURCE=..\..\src\debug.c
# End Source File
# Begin Source File

SOURCE=..\..\src\des.c
# End Source File
# Begin Source File

SOURCE=..\..\src\digests.c
# End Source File
# Begin Source File

SOURCE=..\..\src\dsa.c
# End Source File
# Begin Source File

SOURCE=..\..\src\enveloped.c
# End Source File
# Begin Source File

SOURCE=..\..\src\hmac.c
# End Source File
# Begin Source File

SOURCE=..\..\src\io.c
# End Source File
# Begin Source File

SOURCE=..\..\src\keyinfo.c
# End Source File
# Begin Source File

SOURCE=..\..\src\keys.c
# End Source File
# Begin Source File

SOURCE=..\..\src\keysmngr.c
# End Source File
# Begin Source File

SOURCE=..\..\src\membuf.c
# End Source File
# Begin Source File

SOURCE=..\..\src\ripemd160.c
# End Source File
# Begin Source File

SOURCE=..\..\src\rsa.c
# End Source File
# Begin Source File

SOURCE=..\..\src\sha1.c
# End Source File
# Begin Source File

SOURCE=..\..\src\transforms.c
# End Source File
# Begin Source File

SOURCE=..\..\src\x509.c
# End Source File
# Begin Source File

SOURCE=..\..\src\xmldsig.c
# End Source File
# Begin Source File

SOURCE=..\..\src\xmlenc.c
# End Source File
# Begin Source File

SOURCE=..\..\src\xmlsec.c
# End Source File
# Begin Source File

SOURCE=..\..\src\xmltree.c
# End Source File
# Begin Source File

SOURCE=..\..\src\xpath.c
# End Source File
# Begin Source File

SOURCE=..\..\src\xslt.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\include\xmlsec\base64.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\bn.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\buffered.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\ciphers.h
# End Source File
# Begin Source File

SOURCE=..\..\config.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\debug.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\digests.h
# End Source File
# Begin Source File

SOURCE=..\..\globals.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\io.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\keyinfo.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\keys.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\keysInternal.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\keysmngr.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\membuf.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\transforms.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\transformsInternal.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\version.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\x509.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\xmldsig.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\xmlenc.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\xmlsec.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\xmltree.h
# End Source File
# Begin Source File

SOURCE=..\..\include\xmlsec\xpath.h
# End Source File
# End Group
# End Target
# End Project
