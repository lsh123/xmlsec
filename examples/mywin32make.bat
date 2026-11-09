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

IF NOT DEFINED INCLUDE SET INCLUDE=
IF "%INCLUDE%"=="" SET INCLUDE=%XMLSEC_INCLUDE% ELSE SET INCLUDE=%XMLSEC_INCLUDE%;%INCLUDE%
IF NOT DEFINED LIB SET LIB=
IF "%LIB%"=="" SET LIB=%XMLSEC_LIB% ELSE SET LIB=%XMLSEC_LIB%;%LIB%

cd /d "%~dp0"
IF "%~1"=="" (nmake -f Makefile.w32) ELSE (nmake -f Makefile.w32 %*)
IF ERRORLEVEL 1 (echo Build failed. & exit /b %ERRORLEVEL%)
