@echo off
REM 
REM This is my personal configuration file. 
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the CVS, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM 

SET ICONV=d:\sdk\bin\iconv
SET LIBXML2=d:\sdk\bin\libxml2
SET LIBXSLT=d:\sdk\bin\libxslt
SET NSS=d:\sdk\bin\mozilla
SET XMLSEC=d:\sdk\bin\xmlsec
SET XMLSEC_INCLUDE=%ICONV%\include;%LIBXML2%\include;%LIBXSLT%\include;%NSS%\include;%NSS%\include\nspr;%NSS%\public;%NSS%\public\nss
SET XMLSEC_LIB=%ICONV%\lib;%LIBXML2%\lib;%LIBXSLT%\lib;%NSS%\lib
SET XMLSEC_OPTIONS=static=yes debug=yes xslt=yes crypto=nss

del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB% 
