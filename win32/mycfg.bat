@echo on
REM
REM This is my personal configuration file.
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the GitHub, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM

SET XMLSEC_CRYPTO=mscng

SET PREFIX=%USERHOME%\distro
SET LIBXML2_PREFIX=%PREFIX%\libxml2
SET LIBXSLT_PREFIX=%PREFIX%\libxslt
SET OPENSSL_PREFIX=%PREFIX%\openssl
SET XMLSEC_PREFIX=%PREFIX%\xmlsec

SET XMLSEC_INCLUDE=%LIBXML2_PREFIX%\include;%LIBXML2_PREFIX%\include\libxml2;%LIBXSLT_PREFIX%\include;%OPENSSL_PREFIX%\include;%MSSDK_INCLUDE%
SET XMLSEC_LIB=%LIBXML2_PREFIX%\lib;%LIBXSLT_PREFIX%\lib;%OPENSSL_PREFIX%\lib;%MSSDK_LIB%
SET XMLSEC_OPTIONS=crypto=%XMLSEC_CRYPTO% legacy-features=yes static=no debug=yes memcheck=leaks pedantic=yes

nmake clean
del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC_PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB%

@ECHO OFF
mkdir binaries
IF EXIST %LIBXML2_PREFIX%\bin\*.dll copy %LIBXML2_PREFIX%\bin\*.dll binaries
IF EXIST %LIBXML2_PREFIX%\bin\*.pdb copy %LIBXML2_PREFIX%\bin\*.pdb binaries
IF EXIST %LIBXML2_PREFIX%\lib\*.dll copy %LIBXML2_PREFIX%\lib\*.dll binaries
IF EXIST %LIBXML2_PREFIX%\lib\*.pdb copy %LIBXML2_PREFIX%\lib\*.pdb binaries

IF EXIST %LIBXSLT_PREFIX%\bin\*.dll copy %LIBXSLT_PREFIX%\bin\*.dll binaries
IF EXIST %LIBXSLT_PREFIX%\bin\*.pdb copy %LIBXSLT_PREFIX%\bin\*.pdb binaries
IF EXIST %LIBXSLT_PREFIX%\lib\*.dll copy %LIBXSLT_PREFIX%\lib\*.dll binaries
IF EXIST %LIBXSLT_PREFIX%\lib\*.pdb copy %LIBXSLT_PREFIX%\lib\*.pdb binaries

IF EXIST %OPENSSL_PREFIX%\bin\*.dll copy %OPENSSL_PREFIX%\bin\*.dll binaries
IF EXIST %OPENSSL_PREFIX%\bin\*.pdb copy %OPENSSL_PREFIX%\bin\*.pdb binaries
IF EXIST %OPENSSL_PREFIX%\lib\*.dll copy %OPENSSL_PREFIX%\lib\*.dll binaries
IF EXIST %OPENSSL_PREFIX%\lib\*.pdb copy %OPENSSL_PREFIX%\lib\*.pdb binaries

