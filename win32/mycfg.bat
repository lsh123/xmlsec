@echo on
REM
REM This is my personal configuration file.
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the GitHub, please.
REM
REM Aleksey Sanin <aleksey@aleksey.com>
REM

SET XMLSEC_CRYPTO=mscng,mscrypto

SET PREFIX=C:\local\distro
SET LIBXML2_PREFIX=%PREFIX%\libxml2
SET LIBXSLT_PREFIX=%PREFIX%\libxslt
SET OPENSSL_PREFIX=%PREFIX%\openssl
SET XMLSEC_PREFIX=%PREFIX%\xmlsec

SET XMLSEC_INCLUDE=%LIBXML2_PREFIX%\include;%LIBXML2_PREFIX%\include\libxml2;%LIBXSLT_PREFIX%\include;%OPENSSL_PREFIX%\include;%MSSDK_INCLUDE%
SET XMLSEC_LIB=%LIBXML2_PREFIX%\lib;%LIBXSLT_PREFIX%\lib;%OPENSSL_PREFIX%\lib;%MSSDK_LIB%
SET XMLSEC_OPTIONS=pedantic=yes static=yes with-dl=yes iconv=no cruntime=/MD debug=yes xslt=yes crypto=%XMLSEC_CRYPTO% unicode=yes legacy-crypto=yes 

nmake clean
del /F Makefile configure.txt
cscript configure.js prefix=%XMLSEC_PREFIX% %XMLSEC_OPTIONS% include=%XMLSEC_INCLUDE% lib=%XMLSEC_LIB%

mkdir binaries
copy %LIBXML2_PREFIX%\bin\*.dll binaries
copy %LIBXML2_PREFIX%\bin\*.pdb binaries
copy %LIBXML2_PREFIX%\lib\*.dll binaries
copy %LIBXML2_PREFIX%\lib\*.pdb binaries

copy %LIBXSLT_PREFIX%\bin\*.dll binaries
copy %LIBXSLT_PREFIX%\bin\*.pdb binaries
copy %LIBXSLT_PREFIX%\lib\*.dll binaries
copy %LIBXSLT_PREFIX%\lib\*.pdb binaries

copy %OPENSSL_PREFIX%\bin\*.dll binaries
copy %OPENSSL_PREFIX%\bin\*.pdb binaries
copy %OPENSSL_PREFIX%\lib\*.dll binaries
copy %OPENSSL_PREFIX%\lib\*.pdb binaries

