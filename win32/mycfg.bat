@echo off
REM 
REM This is my personal configuration file. 
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the CVS, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM 

SET XMLSEC_PREFIX=d:\sdk
SET XMLSEC_INCLUDE=%XMLSEC_PREFIX%\include;%XMLSEC_PREFIX%\include\mozilla;%XMLSEC_PREFIX%\include\mozilla\nspr;%XMLSEC_PREFIX%\include\mozilla\public;%XMLSEC_PREFIX%\include\mozilla\public\nss;%MSSDK_INCLUDE%
SET XMLSEC_LIB=%XMLSEC_PREFIX%\lib;%MSSDK_LIB%
SET XMLSEC_OPTIONS=static=no debug=yes xslt=yes crypto=mscrypto,openssl,nss

del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC_PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB% 

mkdir binaries
copy %XMLSEC_PREFIX%\bin\*.dll binaries
