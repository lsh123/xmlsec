@echo off
REM 
REM This is my personal configuration file. 
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the CVS, please.
REM 
REM Aleksey Sanin <aleksey@aleksey.com>
REM 

REM SET ICONV=e:\sdk\bin\iconv
REM SET LIBXML2=e:\sdk\bin\libxml2
REM SET LIBXSLT=e:\sdk\bin\libxslt
REM SET OPENSSL=e:\sdk\bin\openssl
REM SET XMLSEC_PREFIX=e:\sdk\bin\xmlsec
REM SET XMLSEC_INCLUDE=%ICONV%\include;%LIBXML2%\include;%LIBXSLT%\include;%OPENSSL%\include
REM SET XMLSEC_LIB=%ICONV%\lib;%LIBXML2%\lib;%LIBXSLT%\lib;%OPENSSL%\lib

SET XMLSEC_PREFIX=e:\sdk
SET MMSSDK_INCLUDE=
SET MMSSDK_LIB=
SET XMLSEC_INCLUDE=%XMLSEC_PREFIX%\include;%MSSDK_INCLUDE%
SET XMLSEC_LIB=%XMLSEC_PREFIX%\lib;%MSSDK_LIB%
SET XMLSEC_OPTIONS=static=yes debug=yes xslt=yes crypto=mscrypto

del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC_PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB% 
