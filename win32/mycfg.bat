@echo on
REM
REM This is my personal configuration file.
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the GitHub, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM

SET PREFIX=C:\local
SET XMLSEC_CRYPTO=mscrypto
SET OPENSSL_PREFIX=%PREFIX%\openssl-3.0.3
SET XMLSEC_INCLUDE=%PREFIX%\include;%PREFIX%\include\libxml2;%OPENSSL_PREFIX%\include;%MSSDK_INCLUDE%
SET XMLSEC_LIB=%PREFIX%\lib;%OPENSSL_PREFIX%\lib;%MSSDK_LIB%
SET XMLSEC_OPTIONS=pedantic=yes static=yes with-dl=yes iconv=no debug=yes xslt=yes crypto=%XMLSEC_CRYPTO% unicode=no

nmake clean
del /F Makefile configure.txt
cscript configure.js prefix=%PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB%

mkdir binaries
copy %PREFIX%\bin\*.dll binaries
copy %PREFIX%\lib\*.dll binaries
copy %OPENSSL_PREFIX%\bin\*.dll binaries
copy %OPENSSL_PREFIX%\lib\*.dll binaries

