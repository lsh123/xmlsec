<#

.SYNOPSIS
  Run the aes-gcm decryption tests from a particular folder

.DESCRIPTION
  Simple powershell script that loops over the test files corresponding to a particular key
  file and checks that the decryted output matches the expected result.

.PARAMETER folder
  The name of the top-level folder to run the tests in

.PARAMETER xmlsecExecutable
  Full path to the xmlsec.exe executable to use to run the tests.
  It must be able to load any shared libraries required, so make
  sure the PATH is correctly set up before running the tests.

.PARAMETER cryptoBackend
  Name of the backend to use - e.g. mscng or openssl
  If not specified the default will be used

.EXAMPLE
    $env:Path += ";<path to folders with libxml2, libxslt etc. dlls>"
    .\RunAesGcmDecryptTest.ps1 -folder ..\tests\nist-aesgcm\decrypt\aes128 -xmlsecExecutable .\binaries\xmlsec.exe

.NOTES

  From a command prompt:
    set PATH=%PATH%;<path to folders with libxml2, libxslt etc. dlls>
    Powershell.exe -executionpolicy remotesigned -File RunAesGcmDecryptTest.ps1 -folder ..\tests\nist-aesgcm\decrypt\aes128 -xmlsecExecutable .\binaries\xmlsec.exe

  The expected folder structure is
  
  top-level
  |
  |- keys
  |- files
  |- expected

  In the keys folder are the xml files with the appropriate decryption keys for the correspondingly named files in the files folder

  The files folder contains all the test data

  The expected folder has the expected results

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

$transformName = Split-Path $folder -Leaf
$transformName+="-gcm"

$cryptoArgs = @()
if ($PSBoundParameters.ContainsKey("cryptoBackend")) {
    $cryptoArgs+='--crypto'
    $cryptoArgs+=$cryptoBackend
}

& $xmlsecExecutable check-transforms @cryptoArgs $transformName >$null 2>&1
$exitCode = $?
Write-Host "Check transforms: $transformName " -NoNewline
if ($exitCode) {
    Write-Host "[Pass]" -ForegroundColor Green
} else {
    Write-Host "[Fail]" -ForegroundColor Red
    Exit 1
}

Get-ChildItem "$folder\keys" |
ForEach-Object {

    $TestName = $_.BaseName
    $keysFile = $_.FullName
    
    Write-Output "Testing $TestName"

    # Load the expected results
    $ExpectedResultsFile = "$folder\expected\$TestName.pt.base64"
    $ExpectedResults = Get-Content $ExpectedResultsFile

    # Loop over the test files
    $TestNumber = 0;
    Get-ChildItem "$folder\files\$TestName-*.xml" |
    Foreach-Object {
    
        $FileToDecrypt = $_.FullName
        $commandOutput = [System.IO.Path]::GetTempFileName()

        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = $xmlsecExecutable
        $processStartInfo.Arguments = "decrypt "
        if ($PSBoundParameters.ContainsKey("cryptoBackend")) {
            $processStartInfo.Arguments += "--crypto $cryptoBackend "
        }
        $processStartInfo.Arguments += "--keys-file ""$keysFile"" ""$FileToDecrypt"""
        $processStartInfo.WorkingDirectory = (Get-Location).Path
        $processStartInfo.RedirectStandardOutput = $True
        $processStartInfo.UseShellExecute = $False
        $processStartInfo.CreateNoWindow = $True

        $process = [System.Diagnostics.Process]::Start($processStartInfo)

        $process.WaitForExit()
        $commandStatus = $process.ExitCode

        $outStream = New-Object System.IO.FileStream($commandOutput, "Create")
        $writer = New-Object System.IO.BinaryWriter($outStream)
        $byteRead = -1;
        do {
            $byteRead = $process.StandardOutput.BaseStream.ReadByte()
            if ($byteRead -ge 0) {
                # Deal with the output stream adding CRNL line endings
                if ($byteRead -eq 13) {
                    $nextbyteRead = $process.StandardOutput.BaseStream.ReadByte()
                    if ($nextbyteRead -eq 10) {
                        $writer.Write([Byte]$nextbyteRead)
                    } else {
                        $writer.Write([Byte]$byteRead)
                        if ($nextbyteRead -ne -1) {
                            $writer.Write([Byte]$nextbyteRead)
                        }
                    }
                    $byteRead = $nextbyteRead
                } else {
                    $writer.Write([Byte]$byteRead)
                }
            } 
        } while ($byteRead -ge 0)
        $writer.Flush()
        $writer.Close()
        
        $TestPassed = $False
        if ($ExpectedResults[$TestNumber].Length -eq 0) {
            if ($commandStatus -ne 0) {
                $TestPassed = $True
            }
        } else {
            if ($commandStatus -eq 0) {
               $Bytes = Get-Content $commandOutput -Encoding Byte
               $base64EncodedOutput = [System.Convert]::ToBase64String($Bytes)

               if ($base64EncodedOutput -eq $ExpectedResults[$TestNumber]) {
                    $TestPassed = $True
               }
            }
        }
        Write-Host "$FileToDecrypt " -NoNewline
        if ($TestPassed) {
            Write-Host "[Pass]" -ForegroundColor Green
        } else {
            Write-Host "[Fail]" -ForegroundColor Red
        }
        $TestNumber++
    }

}