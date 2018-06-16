@echo off
REM
REM Run the tests standalone using the testrun.sh scripts under WSL
REM
REM Usage: RunTestsWithWSL <cryptobackend> <path to xmlsec executable>
REM
REM NOTE: requires Windows 10 1803 or higher with WSL installed (uses wslpath)
REM NOTE: PATH must be correctly set before running this script
REM NOTE: execute in this (win32) folder
REM
pushd ..
set CRYPTOBACKEND=%1
set XMLSECEXECUTABLE=%cd%\win32\%2
set TMPFOLDER=%cd%\win32\zztmp
if not exist %TMPFOLDER% mkdir %TMPFOLDER%
set WSLENV=TMPFOLDER/up:CRYPTOBACKEND/u:XMLSECEXECUTABLE/up
wsl sh ./tests/testrun.sh ./tests/testKeys.sh "$CRYPTOBACKEND" ./tests "$XMLSECEXECUTABLE" der
wsl sh ./tests/testrun.sh ./tests/testDsig.sh "$CRYPTOBACKEND" ./tests "$XMLSECEXECUTABLE" der
wsl sh ./tests/testrun.sh ./tests/testEnc.sh "$CRYPTOBACKEND" ./tests "$XMLSECEXECUTABLE" der
popd