@echo off
REM 
REM This is my personal configuration file. 
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the CVS, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM 

REM SET ICONV=d:\sdk\bin\iconv
REM SET LIBXML2=d:\sdk\bin\libxml2
REM SET LIBXSLT=d:\sdk\bin\libxslt
REM SET OPENSSL=d:\sdk\bin\openssl
REM SET XMLSEC_PREFIX=d:\sdk\bin\xmlsec
REM SET XMLSEC_INCLUDE=%ICONV%\include;%LIBXML2%\include;%LIBXSLT%\include;%OPENSSL%\include
REM SET XMLSEC_LIB=%ICONV%\lib;%LIBXML2%\lib;%LIBXSLT%\lib;%OPENSSL%\lib

SET XMLSEC_PREFIX=d:\sdk
SET MOZILLA_INCLUDES=%XMLSEC_PREFIX%\include\mozilla;%XMLSEC_PREFIX%\include\mozilla\nspr;%XMLSEC_PREFIX%\include\mozilla\public;%XMLSEC_PREFIX%\include\mozilla\public\nss
SET XMLSEC_INCLUDE=%XMLSEC_PREFIX%\include;%MOZILLA_INCLUDES%
SET XMLSEC_LIB=%XMLSEC_PREFIX%\lib
SET XMLSEC_OPTIONS=static=no debug=yes xslt=yes crypto=nss

del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC_PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB% 
