@echo off
REM
REM Script to run the aes-gcm decryption/encryption tests standalone
REM
REM Ensure that your PATH is correctly set up to find any necessary
REM dll dependencies before running it
REM
powershell -executionpolicy remotesigned -File .\RunAesGcmDecryptTest.ps1 -folder ..\tests\nist-aesgcm\decrypt\aes128 -xmlsecExecutable binaries\xmlsec.exe
powershell -executionpolicy remotesigned -File .\RunAesGcmDecryptTest.ps1 -folder ..\tests\nist-aesgcm\decrypt\aes192 -xmlsecExecutable binaries\xmlsec.exe
powershell -executionpolicy remotesigned -File .\RunAesGcmDecryptTest.ps1 -folder ..\tests\nist-aesgcm\decrypt\aes256 -xmlsecExecutable binaries\xmlsec.exe
powershell -executionpolicy remotesigned -File .\RunAesGcmEncryptTests.ps1 -folder ..\tests\nist-aesgcm\encrypt -xmlsecExecutable binaries\xmlsec.exe