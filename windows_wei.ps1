#Requires -RunAsAdministrator

<#
.SYNOPSIS
Add or remove the Algo VPN

.DESCRIPTION
Add or remove the Algo VPN
See the examples for more information

.PARAMETER Add
Add the VPN to the local system

.PARAMETER Remove
Remove the VPN from the local system

.PARAMETER GetInstalledCerts
Retrieve Algo certs, if any, from the system certificate store

.PARAMETER SaveCerts
Save the Algo certs embedded in this file

.PARAMETER OutputDirectory
When saving the Algo certs, save to this directory

.PARAMETER Pkcs12DecryptionPassword
The decryption password for the user's PKCS12 certificate, sometimes called the "p12 password".
Note that this must be passed in as a SecureString, not a regular string.
You can create a secure string with the `Read-Host -AsSecureString` cmdlet.
See the examples for more information.

.EXAMPLE
client_USER.ps1 -Add

Adds the Algo VPN

.EXAMPLE
$p12pass = Read-Host -AsSecureString; client_USER.ps1 -Add -Pkcs12DecryptionPassword $p12pass

Create a variable containing the PKCS12 decryption password, then use it when adding the VPN.
This can be especially useful when troubleshooting, because you can use the same variable with
multiple calls to client_USER.ps1, rather than having to type the PKCS12 password each time.

.EXAMPLE
client_USER.ps1 -Remove

Removes the Algo VPN if installed.

.EXAMPLE
client_USER.ps1 -GetIntalledCerts

Show the Algo VPN's installed certificates, if any.

.EXAMPLE
client_USER.ps1 -SaveCerts -OutputDirectory $Home\Downloads

Save the embedded CA cert and encrypted user PKCS12 file.
#>
[CmdletBinding(DefaultParameterSetName="Add")] Param(
    [Parameter(ParameterSetName="Add")]
    [Switch] $Add,

    [Parameter(ParameterSetName="Add")]
    [SecureString] $Pkcs12DecryptionPassword,

    [Parameter(Mandatory, ParameterSetName="Remove")]
    [Switch] $Remove,

    [Parameter(Mandatory, ParameterSetName="GetInstalledCerts")]
    [Switch] $GetInstalledCerts,

    [Parameter(Mandatory, ParameterSetName="SaveCerts")]
    [Switch] $SaveCerts,

    [Parameter(ParameterSetName="SaveCerts")]
    [string] $OutputDirectory = "$PWD"
)

$ErrorActionPreference = "Stop"

$VpnServerAddress = "174.138.54.73"
$VpnName = "Algo VPN 174.138.54.73 IKEv2"
$VpnUser = "wei"
$CaCertificateBase64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI3VENDQVhLZ0F3SUJBZ0lKQU9NYmRkZ29vYXZWTUFvR0NDcUdTTTQ5QkFNQ01CZ3hGakFVQmdOVkJBTU0KRFRFM05DNHhNemd1TlRRdU56TXdIaGNOTVRnd09EQTVNREkxTkRVeVdoY05Namd3T0RBMk1ESTFORFV5V2pBWQpNUll3RkFZRFZRUUREQTB4TnpRdU1UTTRMalUwTGpjek1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFCnR5aE0zdVhpejRSNEZsbTRxOVphKzRwY0tISmhUQnJyMHZ3Q2VtWHo2cFRZcFZIamtSWDNyUFFKUVp6TVg2L00KQytUbjJkNEZzZ1NuQmhSQ1lFckFyaDJJbkgxcE1ieXpwSkx4aHFCR2hpZ2hIWFM3UWVEYnpQSlF5RmdPZVJxUQpvNEdITUlHRU1CMEdBMVVkRGdRV0JCUThLRHJpWEpPZzljaEh2VjBycy9TdVFVTmFjakJJQmdOVkhTTUVRVEEvCmdCUThLRHJpWEpPZzljaEh2VjBycy9TdVFVTmFjcUVjcEJvd0dERVdNQlFHQTFVRUF3d05NVGMwTGpFek9DNDEKTkM0M000SUpBT01iZGRnb29hdlZNQXdHQTFVZEV3UUZNQU1CQWY4d0N3WURWUjBQQkFRREFnRUdNQW9HQ0NxRwpTTTQ5QkFNQ0Eya0FNR1lDTVFEcXNjVDFaRUxHLzdSZUsxazZBektpcTIrcTViQmpQZlhEak1FTnltTkdJYVFWCmhEMzAvS0FPK1lyUWNSaGRIaEFDTVFEcU4wMmJnQ3hRTEFXRWY2eVJyYW9XZVcrcXpzeWl6K1FhMFdocnJqR24KY3Bhc0tXN1d3YmpPQ1Q1SUEvVTlrSDg9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
$UserPkcs12Base64 = "MIIEdQIBAzCCBDsGCSqGSIb3DQEHAaCCBCwEggQoMIIEJDCCAs8GCSqGSIb3DQEHBqCCAsAwggK8
AgEAMIICtQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIaswKAjqJIlkCAggAgIICiOtLLFi7
hlVbPJ2eb0nZMyv135q1iCStsJDIIt9Vy7XyTFSkqdFx8BeFeL5HQ3E0R+ny5OUI00Eif6tkC829
mZrSNGsLzXlutmUiLLSrJ2xScmRU9g4TRER8l/C3ZAHC7yXNMT5d7wVfefN1ugJkStsKVFRUH2VD
uJo2vbttNIT8u6f9d84q6E/SZ6gjKI84KHW7/JEyIxNTlLbfbvbqA67hUPFNSdOmXvoaP9DsciCM
e25+XRRxhzBY6B5ofvi9Y8PAlOtrINRpkemvGTmPJFmpVlS2oTvzxXL54f13SWsJ2xr7apyrsTrW
GPQfpyobWsyXy9lLabI7c6DfrNsVkqbnVku2IFeWllRz0LvqHMw9ujScrrG4wOvnC7dFh65JLB+U
Ta3eP7mTAtilIk+znSWFl0OOSx9PRkBXdbVgN+3RAXSxZyFGAOcFuylTKIrq7sj9T+3+jzHqcXln
4h3tcehtobb6LiqboqQdbhqFxGdHbnkwUaWn5eUnlcRPW1EK/jIheE+idhGjgMLyQBNT6lAJoOch
iniUQGr6JXnoJQ51ukqMU40qi7HhwxsRdxRWykOHJVkJENsmVMl/0Q5lHHmhEJGj7X5W8CEvqIsC
BXLAmEhKJzqyNS+EktbC3XanxSALwvILTetpHEd+huXU9P/UtE60jxOwudHaXwPSGSjm2q1OWP3G
A2LliklZzITqQqAw4LM/M3r3RnxwAPh1rTa01pLjTQIqAmM3xDpu8cfPeTS8O7kU+hB2K3dE256S
Sxoasfv3g1ta9RJFxEOcyv0W7a0ph1ZJW9zW8MoZEJOJZOO47jlVQLC+d6cyRVmUYc++MFLHNrMs
XizTY6UV8HzpVEWGB0wYuTCCAU0GCSqGSIb3DQEHAaCCAT4EggE6MIIBNjCCATIGCyqGSIb3DQEM
CgECoIHkMIHhMBwGCiqGSIb3DQEMAQMwDgQImT7PyNA6sO4CAggABIHAyxI54wCh1rwOzZXuv8Wr
gZSYANFKvVdIQX7X7DR1viO+MbK1wpARcXADCMFnNlz7OvtKCTXyFQZzYLd2FKmJkzZy0iEhBxMr
HPgy0S0D/3IUsW8s/qhkv+LFmA3lYft0AI3H3czKzEP+GxIdjPBJsPC/TtoZ/KZHOPFprzRP9Mso
OL8mjhfJwhQm1a8gEBpcZ+vBE2sVsUvVtEMLuxBJV+9UpEvfgy8axYAG5c57DKfQ2OniqoL8GbXh
gEoS6WyKMTwwFQYJKoZIhvcNAQkUMQgeBgB3AGUAaTAjBgkqhkiG9w0BCRUxFgQUNSzaOb5swCRn
lv/jnSGf1SFkQfAwMTAhMAkGBSsOAwIaBQAEFNIlt5OPA3ONz2BzWDPl8o7xYJ0uBAgsii39LFzP
EQICCAA="

if ($PsCmdlet.ParameterSetName -eq "Add" -and -not $Pkcs12DecryptionPassword) {
    $Pkcs12DecryptionPassword = Read-Host -AsSecureString -Prompt "Pkcs12DecryptionPassword"
}

<#
.SYNOPSIS
Create a temporary directory
#>
function New-TemporaryDirectory {
    [CmdletBinding()] Param()
    do {
        $guid = New-Guid | Select-Object -ExpandProperty Guid
        $newTempDirPath = Join-Path -Path $env:TEMP -ChildPath $guid
    } while (Test-Path -Path $newTempDirPath)
    New-Item -ItemType Directory -Path $newTempDirPath
}

<#
.SYNOPSIS
Retrieve any installed Algo VPN certificates
#>
function Get-InstalledAlgoVpnCertificates {
    [CmdletBinding()] Param()
    Get-ChildItem -LiteralPath Cert:\LocalMachine\Root |
        Where-Object {
            $_.Subject -match "^CN=${VpnServerAddress}$" -and $_.Issuer -match "^CN=${VpnServerAddress}$"
        }
    Get-ChildItem -LiteralPath Cert:\LocalMachine\My |
        Where-Object {
            $_.Subject -match "^CN=${VpnUser}$" -and $_.Issuer -match "^CN=${VpnServerAddress}$"
        }
}

function Save-AlgoVpnCertificates {
    [CmdletBinding()] Param(
        [String] $OutputDirectory = $PWD
    )
    $caCertPath = Join-Path -Path $OutputDirectory -ChildPath "cacert.pem"
    $userP12Path = Join-Path -Path $OutputDirectory -ChildPath "$VpnUser.p12"
    # NOTE: We cannot use ConvertFrom-Base64 here because it is not designed for binary data
    [IO.File]::WriteAllBytes(
        $caCertPath,
        [Convert]::FromBase64String($CaCertificateBase64))
    [IO.File]::WriteAllBytes(
        $userP12Path,
        [Convert]::FromBase64String($UserPkcs12Base64))
    return New-Object -TypeName PSObject -Property @{
        CaPem = $caCertPath
        UserPkcs12 = $userP12Path
    }
}

function Add-AlgoVPN {
    [Cmdletbinding()] Param()

    $workDir = New-TemporaryDirectory

    try {
        $certs = Save-AlgoVpnCertificates -OutputDirectory $workDir
        $importPfxCertParams = @{
            Password = $Pkcs12DecryptionPassword
            FilePath = $certs.UserPkcs12
            CertStoreLocation = "Cert:\LocalMachine\My"
        }
        Import-PfxCertificate @importPfxCertParams
        $importCertParams = @{
            FilePath =  $certs.CaPem
            CertStoreLocation = "Cert:\LocalMachine\Root"
        }
        Import-Certificate @importCertParams
    } finally {
        Remove-Item -Recurse -Force -LiteralPath $workDir
    }

    $addVpnParams = @{
        Name = $VpnName
        ServerAddress = $VpnServerAddress
        TunnelType = "IKEv2"
        AuthenticationMethod = "MachineCertificate"
        EncryptionLevel = "Required"
    }
    Add-VpnConnection @addVpnParams

    $setVpnParams = @{
        ConnectionName = $VpnName
        AuthenticationTransformConstants = "GCMAES256"
        CipherTransformConstants = "GCMAES256"
        EncryptionMethod = "AES256"
        IntegrityCheckMethod = "SHA384"
        DHGroup = "ECP384"
        PfsGroup = "ECP384"
        Force = $true
    }
    Set-VpnConnectionIPsecConfiguration @setVpnParams
}

function Remove-AlgoVPN {
    [CmdletBinding()] Param()
    Get-InstalledAlgoVpnCertificates | Remove-Item -Force
    Remove-VpnConnection -Name $VpnName -Force
}

switch ($PsCmdlet.ParameterSetName) {
    "Add" { Add-AlgoVPN }
    "Remove" { Remove-AlgoVPN }
    "GetInstalledCerts" { Get-InstalledAlgoVpnCertificates }
    "SaveCerts" {
        $certs = Save-AlgoVpnCertificates -OutputDirectory $OutputDirectory
        Get-Item -LiteralPath $certs.UserPkcs12, $certs.CaPem
    }
    default { throw "Unknown parameter set: '$($PsCmdlet.ParameterSetName)'" }
}
