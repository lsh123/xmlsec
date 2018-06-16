<#

.SYNOPSIS
  Run the aes-gcm encryption tests from a particular folder

.DESCRIPTION
  Simple powershell script that loops over the test encryption data,
  encrypts to a temporary file and then decrypts the file.

.PARAMETER folder
  The name of the top-level folder containing the encryption tests

.PARAMETER xmlsecExecutable
  Full path to the xmlsec.exe executable to use to run the tests.
  It must be able to load any shared libraries required, so make
  sure the PATH is correctly set up before running the tests.

.PARAMETER cryptoBackend
  Name of the backend to use - e.g. mscng or openssl
  If not specified the default will be used

.EXAMPLE
    $env:Path += ";<path to folders with libxml2, libxslt etc. dlls>"
    .\RunAesGcmEncryptTests.ps1 -folder ..\tests\nist-aesgcm\encrypt -xmlsecExecutable .\binaries\xmlsec.exe

.NOTES

  From a command prompt:
    set PATH=%PATH%;<path to folders with libxml2, libxslt etc. dlls>
    Powershell.exe -executionpolicy remotesigned -File RunAesGcmEncryptTests.ps1 -folder ..\tests\nist-aesgcm\encrypt -xmlsecExecutable .\binaries\xmlsec.exe

  The expected folder structure is
  
  top-level
  |
  |- keys
  |- aes128
  |- aes192
  |- aes256

  In the keys folder are the xml files with the appropriate encryption/decryption keys for the test data

  The aes* folders contain the test data and encryption templates
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $folder,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $xmlsecExecutable,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    $cryptoBackend
)

$cryptoArgs = @()
if ($PSBoundParameters.ContainsKey("cryptoBackend")) {
    $cryptoArgs+='--crypto'
    $cryptoArgs+=$cryptoBackend
}

Get-ChildItem "$folder\aes*" |
ForEach-Object {


    $transformName = Split-Path $_ -Leaf
    $transformName+="-gcm"
    $folderName = $_

    & $xmlsecExecutable check-transforms @cryptoArgs $transformName >$null 2>&1
    $exitCode = $?
    Write-Host "Check transforms: $transformName " -NoNewline
    if ($exitCode) {
        Write-Host "[Pass]" -ForegroundColor Green
    } else {
        Write-Host "[Fail]" -ForegroundColor Red
        Continue
    }

    Get-ChildItem $_\*.tmpl |
    ForEach-Object {
     
        $dataFileRoot = Split-Path $_ -Parent
        $dataFile = $_.BaseName + ".data"
        $tmpFile = New-TemporaryFile
        $encryptPassed = $False

        & $xmlsecExecutable encrypt @cryptoArgs --keys-file $folder\keys\keys.xml --binary-data $dataFileRoot\$dataFile $_ > $tmpFile
        if ($?) {
            $encryptPassed = $True
        }

        Write-Host "Encrypt file " -NoNewline
        if ($encryptPassed) {
            Write-Host "[Pass]" -ForegroundColor Green
        } else {
            Write-Host "[Fail]" -ForegroundColor Red
            Remove-Item $tmpFile.FullName -Force
            Continue
        }

        $decryptOutput = New-TemporaryFile
        $decryptPassed = $False

        & $xmlsecExecutable decrypt @cryptoArgs --keys-file $folder\keys\keys.xml $tmpFile.FullName > $decryptOutput
        if ($?) {
            $decryptPassed = $True
        }

        Write-Host "Decrypt new file " -NoNewline
        if ($decryptPassed) {
            Write-Host "[Pass]" -ForegroundColor Green
        } else {
            Write-Host "[Fail]" -ForegroundColor Red
        }

        Remove-Item $tmpFile.FullName -Force
        Remove-Item $decryptOutput.FullName -Force
    }
}