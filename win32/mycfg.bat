@echo off
REM 
REM This is my personal configuration file. 
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the CVS, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM 

SET LIBXML2=c:\sdk\libxml2
REM SET LIBXSLT=c:\sdk\libxslt
SET OPENSSL=c:\sdk\openssl
SET XMLSEC=c:\sdk\xmlsec
SET XMLSEC_INCLUDE=%LIBXML2%\include;%LIBXSLT%\include;%OPENSSL%\include
SET XMLSEC_LIB=%LIBXML2%\lib;%LIBXSLT%\lib;%OPENSSL%\lib
SET XMLSEC_OPTIONS=static=yes debug=yes xmlsec_debug=yes xslt=no

del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB% 
