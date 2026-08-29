REM
REM This is my personal configuration file.
REM I'm too lazy to type all of this over and over.
REM You are welcome to customize this file for your
REM needs but do not commit your customized version, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM

SET XMLSEC_CRYPTO=mscng
SET XMLSEC_DEBUG=no
SET XMLSEC_UNICODE=no

IF "%XMLSEC_DEBUG%" == "yes" (
    SET PREFIX=%USERHOME%\distro.debug
    SET XMLSEC_OPTIONS=debug=yes memcheck=yes cruntime=/MDd unicode=%XMLSEC_UNICODE%
) ELSE (
    SET PREFIX=%USERHOME%\distro.release
    SET XMLSEC_OPTIONS=debug=no memcheck=no cruntime=/MD unicode=%XMLSEC_UNICODE%
)

SET LIBXML2_PREFIX=%PREFIX%\libxml2
SET LIBXSLT_PREFIX=%PREFIX%\libxslt
SET OPENSSL_PREFIX=%PREFIX%\openssl
SET XMLSEC_PREFIX=%PREFIX%\xmlsec

SET XMLSEC_INCLUDE=%LIBXML2_PREFIX%\include;%LIBXML2_PREFIX%\include\libxml2;%LIBXSLT_PREFIX%\include;%OPENSSL_PREFIX%\include
IF DEFINED MSSDK_INCLUDE SET XMLSEC_INCLUDE=%XMLSEC_INCLUDE%;%MSSDK_INCLUDE%
SET XMLSEC_LIB=%LIBXML2_PREFIX%\lib;%LIBXSLT_PREFIX%\lib;%OPENSSL_PREFIX%\lib
IF DEFINED MSSDK_LIB SET XMLSEC_LIB=%XMLSEC_LIB%;%MSSDK_LIB%
SET XMLSEC_OPTIONS=crypto=%XMLSEC_CRYPTO% legacy-features=no static=no pedantic=yes %XMLSEC_OPTIONS%

nmake clean
if errorlevel 1 exit /b %ERRORLEVEL%
del /F /Q Makefile configure.txt
powershell -ExecutionPolicy Bypass -File configure.ps1 prefix=%XMLSEC_PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB%
if errorlevel 1 exit /b %ERRORLEVEL%

@ECHO OFF
if not exist binaries mkdir binaries
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
