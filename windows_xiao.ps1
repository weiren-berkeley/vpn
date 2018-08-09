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
$VpnUser = "xiao"
$CaCertificateBase64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI3VENDQVhLZ0F3SUJBZ0lKQU9NYmRkZ29vYXZWTUFvR0NDcUdTTTQ5QkFNQ01CZ3hGakFVQmdOVkJBTU0KRFRFM05DNHhNemd1TlRRdU56TXdIaGNOTVRnd09EQTVNREkxTkRVeVdoY05Namd3T0RBMk1ESTFORFV5V2pBWQpNUll3RkFZRFZRUUREQTB4TnpRdU1UTTRMalUwTGpjek1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFCnR5aE0zdVhpejRSNEZsbTRxOVphKzRwY0tISmhUQnJyMHZ3Q2VtWHo2cFRZcFZIamtSWDNyUFFKUVp6TVg2L00KQytUbjJkNEZzZ1NuQmhSQ1lFckFyaDJJbkgxcE1ieXpwSkx4aHFCR2hpZ2hIWFM3UWVEYnpQSlF5RmdPZVJxUQpvNEdITUlHRU1CMEdBMVVkRGdRV0JCUThLRHJpWEpPZzljaEh2VjBycy9TdVFVTmFjakJJQmdOVkhTTUVRVEEvCmdCUThLRHJpWEpPZzljaEh2VjBycy9TdVFVTmFjcUVjcEJvd0dERVdNQlFHQTFVRUF3d05NVGMwTGpFek9DNDEKTkM0M000SUpBT01iZGRnb29hdlZNQXdHQTFVZEV3UUZNQU1CQWY4d0N3WURWUjBQQkFRREFnRUdNQW9HQ0NxRwpTTTQ5QkFNQ0Eya0FNR1lDTVFEcXNjVDFaRUxHLzdSZUsxazZBektpcTIrcTViQmpQZlhEak1FTnltTkdJYVFWCmhEMzAvS0FPK1lyUWNSaGRIaEFDTVFEcU4wMmJnQ3hRTEFXRWY2eVJyYW9XZVcrcXpzeWl6K1FhMFdocnJqR24KY3Bhc0tXN1d3YmpPQ1Q1SUEvVTlrSDg9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
$UserPkcs12Base64 = "MIIEdwIBAzCCBD0GCSqGSIb3DQEHAaCCBC4EggQqMIIEJjCCAs8GCSqGSIb3DQEHBqCCAsAwggK8
AgEAMIICtQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIqYBVKp+RcF8CAggAgIICiGGO0kno
+K1RCYOwTV9qCX9DEVkH789rNm77X4CR1tbDkrzsjJ/m1BvgdNonOQzPDCJ2SBc8GAgxaW302zA5
GAz0BUdixU3cfKjGxZ8Oz6m7kPXm4KyUVD7RYbbPOCelsMugaVX3tKBEki75z8inuFUB5/Mc06Zc
DX8aSwd+mpUQGOidqPC2kmlLgRmIKFSwbSlxoyYWl18yotiODRorXFC9Q8kSJKtuGqqUQsoE8nfe
sQJwf4uE00a5r1xZr4Vpnzp78m7eEKXquC73tnyizfbyiy7Hm3GFcYuhNQ2hFam6FXDPEA+1M33b
qo510nGuYnG4sznYfKW+ov347YHLmxHj580koCtVm3o9qUT78yVcIhed7Vel8uppjl/8DqkQkiQl
jNc3DpmjJXif8ZaSPg3Os+tyr3H5B1ZWsd0yrZybToTXsuuUBP/yzv7XRpQjzFj+N733RKnrsdqb
YcYVPG/s5RUBaIbvrquyqD7HGxY0rnfHaDkzqAfduqzeDjX7Qc2cHeVS0MUmUiMag2S+IW2V8CRR
wwlwSKT2DKu4uuTcZL68678IRUENWQrD9gaXuh5V/QIuyBDjq/RWj9O6iiq1LXA3UBEFAL6uqmU2
US7rxTFKZMpTC7hLUpD7ykNuG4HmnMEiFKe8mQV6Jtd6R6cWmY+2XBYfktvfPvcyT4I/QnEUjEux
gwtmFPtyyBaEsGGdhnbwQGh7v5SWAH0Ut12rz9zJW5OJ70QtCpJc8nqa+7JPqUdl5M1omDqSMqUK
D0dweVTmMluPPFeT+bsB9ENvBATkOu7JaR6zLyLNnHoG4sDSREaZTwTl4jxR4eVTMQFoSlQbApGH
xOilRI5+Zvqmu90mB4p+hTCCAU8GCSqGSIb3DQEHAaCCAUAEggE8MIIBODCCATQGCyqGSIb3DQEM
CgECoIHkMIHhMBwGCiqGSIb3DQEMAQMwDgQI2MUqWBNQInoCAggABIHAv529fGY1k27h+rk9QDNu
ARiyafQ+vSp8t/NH1kqalKMDsJkU6T7tgvHL+f9Hgb/QhTMdcigcvg1KanIV8GAtB0xN4Iicy4VK
OcqGHluB3lMmeTURbz6epBZlacEeMwEpnA5TinJSSKFJasLkKOVz7Y8On3ZRiXxacu9H6plBgVCo
nLdVYpuNu5ZKkF06wRHYan6qM6F0+knqs9/1IdeIagvrKnaKGb71fJtlOUWGo6lagDwtA6zY4ZfW
ODKXBFIJMT4wFwYJKoZIhvcNAQkUMQoeCAB4AGkAYQBvMCMGCSqGSIb3DQEJFTEWBBR7IDznlJS5
e6rVK93dd8RA+TTSBzAxMCEwCQYFKw4DAhoFAAQUCja+UMiIbJXE6Ch1e4ah8a294H4ECIUtX2Ml
QVNRAgIIAA=="

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
