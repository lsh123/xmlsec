@echo off
REM
REM This is my personal configuration file.
REM I'm too lazy to type all of this over and over.
REM You are welcome to customize this file for your
REM needs but do not commit your customized version, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM

SET XMLSEC_PREFIX=%USERPROFILE%\xmlsec
SET XMLSEC_INCLUDE=%XMLSEC_PREFIX%\include
SET XMLSEC_LIB=%XMLSEC_PREFIX%\lib

IF DEFINED INCLUDE SET INCLUDE=%XMLSEC_INCLUDE%;%INCLUDE% ELSE SET INCLUDE=%XMLSEC_INCLUDE%
IF DEFINED LIB SET LIB=%XMLSEC_LIB%;%LIB% ELSE SET LIB=%XMLSEC_LIB%

cd /d "%~dp0"
nmake -f Makefile.w32 %*
if errorlevel 1 (echo Build failed. & exit /b %ERRORLEVEL%)
