function Get-CSTrustProvider {
<#
.SYNOPSIS

List trust provider implementation details.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSTrustProvider lists information about registered trust providers and their respective capabilities. Considering the ease in which an attacker running elevated can hijack critical code signing functionality, it is important to sweep and baseline trust provider implementations.

.PARAMETER Guid

Specifies one or more trust provider GUIDs to retrieve information for. A GUID is a unique identifier for a trust providers. If -Guid is not specified, Get-CSTrustProvider will return all registered trust providers.

.PARAMETER DoNotCheckWow64

Specifies that trust providers should not be enumerated from WOW6432Node. -DoNotCheckWow64 is ideally specified on x86 Windows.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSTrustProvider

Lists all trust providers (x64 and x86) and their respective registered capabilities.

.EXAMPLE

Get-CSTrustProvider -Guid 00AAC56B-CD44-11D0-8CC2-00C04FC295EE, 573E31F8-DDBA-11D0-8CCB-00C04FC295EE

Lists trust provider (x64 and x86) implementations for the GUIDs associated with WINTRUST_ACTION_GENERIC_VERIFY_V2 and WINTRUST_ACTION_TRUSTPROVIDER_TEST.

.EXAMPLE

Get-CSTrustProvider -Guid F750E6C3-38EE-11D1-85E5-00C04FC295EE -DoNotCheckWow64

Lists the native (non-WoW64) trust provider implementation for the GUID associated with DRIVER_ACTION_VERIFY.

.OUTPUTS

CimSweep.TrustProvider

Outputs objects representing a trust provider as identified by its unique GUID.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.TrustProvider')]
    param (
        [Guid[]]
        $Guid,

        [Switch]
        $DoNotCheckWow64,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0

        $CapabilityList = @(
            'CertCheck',
            'Certificate',
            'Cleanup',
            'DiagnosticPolicy',
            'FinalPolicy',
            'Initialization',
            'Message',
            'Signature'
        )

        # These is the set of GUIDs I've actually encountered thus far.
        # There are bound to be more that I'm missing.
        $GuidFriendlyNames = @{
            '00AAC56B-CD44-11D0-8CC2-00C04FC295EE' = 'WINTRUST_ACTION_GENERIC_VERIFY_V2'
            '189A3842-3041-11D1-85E1-00C04FC295EE' = 'WINTRUST_ACTION_GENERIC_CERT_VERIFY'
            '31D1ADC1-D329-11D1-8ED8-0080C76516C6' = 'COREE_POLICY_PROVIDER'
            '573E31F8-AABA-11D0-8CCB-00C04FC295EE' = 'HTTPSPROV_ACTION'
            '573E31F8-DDBA-11D0-8CCB-00C04FC295EE' = 'WINTRUST_ACTION_TRUSTPROVIDER_TEST'
            '6078065b-8f22-4b13-bd9b-5b762776f386' = 'CONFIG_CI_ACTION_VERIFY'
            '64B9D180-8DA2-11CF-8736-00AA00A485EB' = 'WIN_SPUB_ACTION_PUBLISHED_SOFTWARE' # Windows Software Publishing Trust Provider
            '7801EBD0-CF4B-11D0-851F-0060979387EA' = 'CERT_CERTIFICATE_ACTION_VERIFY'
            'C6B2E8D0-E005-11CF-A134-00C04FD7BF43' = 'WIN_SPUB_ACTION_PUBLISHED_SOFTWARE_NOBADUI'
            'D41E4F1D-A407-11D1-8BC9-00C04FA30A41' = 'COR_POLICY_PROVIDER_DOWNLOAD'
            'D41E4F1F-A407-11D1-8BC9-00C04FA30A41' = 'COR_POLICY_LOCKDOWN_CHECK'
            'F750E6C3-38EE-11D1-85E5-00C04FC295EE' = 'DRIVER_ACTION_VERIFY'
            'FC451C16-AC75-11D1-B4B8-00C04FB66EA0' = 'WINTRUST_ACTION_GENERIC_CHAIN_VERIFY'
            # 'A7F4C378-21BE-494e-BA0F-BB12C5D208C5' = '' Related to .NET verification
            # '4ECC1CC8-31B7-45CE-B4B9-2DD45C2FF958' = '' Couldn't track down the original GUID name. This is related to MS Office.
        }

        $ArchMapping = @{}

        # Retrieve trust providers only for the architectures specified.
        # For targeting searching, this will seriously reduce bandwidth/latency.
        # x86 implies WoW64, x64 implies 64-bit on a WoW64 system, nothing specified implies attempting to retrieve both.
        $ArchMapping['x64'] = ''

        if (-not $DoNotCheckWow64) {
            $ArchMapping['x86'] = 'WOW6432Node\'
        }

        $GuidList = @{}
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Trust provider sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            foreach ($Capability in $CapabilityList) {
                foreach ($Arch in $ArchMapping.Keys) {
                    if ($Guid) { # Retrieve only the trust provider GUIDs specified. For targeting searching, this will seriously reduce bandwidth/latency.
                        foreach ($GuidEntry in $Guid) {
                            $Key = "$($GuidEntry)_$($Arch)"

                            $GuidSubkey = "SOFTWARE\$($ArchMapping[$Arch])Microsoft\Cryptography\Providers\Trust\$Capability\{$GuidEntry}"

                            Write-Progress -Id 2 -ParentId 1 -Activity "Current subkey:" -Status "HKLM\$GuidSubkey"

                            $Dll = Get-CSRegistryValue -Hive HKLM -SubKey $GuidSubkey -ValueName '$DLL' @CommonArgs | Select-Object -ExpandProperty ValueContent
                            $FuncName = Get-CSRegistryValue -Hive HKLM -SubKey $GuidSubkey -ValueName '$Function' @CommonArgs | Select-Object -ExpandProperty ValueContent

                            if ($Dll -or $FuncName){
                                if (-not $GuidList.ContainsKey($Key)) {
                                    $GuidList[$Key] = New-Object 'Collections.Generic.List[System.String[]]'
                                }

                                $GuidList[$Key].Add([String[]] @($Capability, $Dll, $FuncName))
                            }
                        }
                    } else { # Retrieve all trust provider GUIDs
                        $Subkey = "SOFTWARE\$($ArchMapping[$Arch])Microsoft\Cryptography\Providers\Trust\$Capability"

                        Write-Progress -Id 2 -ParentId 1 -Activity "Current subkey:" -Status $Subkey

                        Get-CSRegistryKey -Hive HKLM -SubKey $Subkey @CommonArgs | ForEach-Object {
                            $GuidSubkey = $_.Subkey.Split('\')[-1].Trim(@('{','}')) + "_$Arch"

                            $Dll = $_ | Get-CSRegistryValue -ValueName '$DLL' | Select-Object -ExpandProperty ValueContent
                            $FuncName = $_ | Get-CSRegistryValue -ValueName '$Function' | Select-Object -ExpandProperty ValueContent

                            if ($Dll -or $FuncName){
                                if (-not $GuidList.ContainsKey($GuidSubkey)) {
                                    $GuidList[$GuidSubkey] = New-Object 'Collections.Generic.List[System.String[]]'
                                }

                                $GuidList[$GuidSubkey].Add([String[]] @($Capability, $Dll, $FuncName))
                            }
                        }
                    }
                }
            }

            foreach ($GuidEntry in $GuidList.Keys) {
                $Capabilities = foreach ($Entry in $GuidList[$GuidEntry]) {
                    $Capability, $Dll, $FuncName = $Entry

                    [PSCustomObject] @{
                        CapabilityName = $Capability
                        Dll = $Dll
                        FunctionName = $FuncName
                    }
                }

                $RawGuid, $Arch = $GuidEntry.Split('_')

                $IsWow64 = $False

                if ($Arch -eq 'x86') { $IsWow64 = $True }

                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.TrustProvider'
                    Guid = $RawGuid
                    IsWow64 = $IsWow64
                    FriendlyName = $GuidFriendlyNames[$RawGuid]
                    Capabilities = $Capabilities
                }

                if ($Session.ComputerName) {
                    $ObjectProperties['PSComputerName'] = $ComputerName
                }

                [PSCustomObject] $ObjectProperties
            }
        }  
    }
}

function Get-CSSubjectInterfacePackage {
<#
.SYNOPSIS

List subject interface package (SIP) implementation details.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSSubjectInterfacePackage lists information about registered subject interface packages (SIP) and their respective capabilities. Considering the ease in which an attacker running elevated can hijack critical code signing functionality, it is important to sweep and baseline SIP implementations.

.PARAMETER Guid

Specifies one or more SIP GUIDs to retrieve information for. A GUID is a unique identifier for a SIP. If -Guid is not specified, Get-CSSubjectInterfacePackage will return all registered SIPs.

.PARAMETER DoNotCheckWow64

Specifies that SIPs should not be enumerated from WOW6432Node. -DoNotCheckWow64 is ideally specified on x86 Windows.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSSubjectInterfacePackage

Lists all subject interface packages (x64 and x86) and their respective registered capabilities.

.EXAMPLE

Get-CSSubjectInterfacePackage -Guid C689AAB8-8E78-11D0-8C47-00C04FC295EE

Lists subject interface packages (x64 and x86) implementations for the GUID associated with the portable executable file format.

.EXAMPLE

Get-CSSubjectInterfacePackage -Guid 603BCC1F-4B59-4E08-B724-D2C6297EF351 -DoNotCheckWow64

Lists the native (non-WoW64) subject interface package implementation for the GUID associated with PowerShell related files.

.OUTPUTS

CimSweep.SubjectInterfacePackage

Outputs objects representing a subject interface package as identified by its unique GUID.
#>
    
    [CmdletBinding()]
    [OutputType('CimSweep.SubjectInterfacePackage')]
    param (
        [Guid[]]
        $Guid,

        [Switch]
        $DoNotCheckWow64,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0

        $CapabilityList = @(
            'CryptSIPDllCreateIndirectData',
            'CryptSIPDllGetCaps',
            'CryptSIPDllGetSealedDigest',
            'CryptSIPDllGetSignedDataMsg',
            'CryptSIPDllIsMyFileType2',
            'CryptSIPDllPutSignedDataMsg',
            'CryptSIPDllRemoveSignedDataMsg',
            'CryptSIPDllVerifyIndirectData'
        )

        # These is the set of GUIDs I've actually encountered thus far.
        # There are bound to be more that I'm missing.
        $GuidFriendlyNames = @{
            'C689AABA-8E78-11d0-8C47-00C04FC295EE' = 'Cabinet'              # CRYPT_SUBJTYPE_CABINET_IMAGE
            'DE351A43-8E59-11d0-8C47-00C04FC295EE' = 'Catalog'              # CRYPT_SUBJTYPE_CATALOG_IMAGE
            '9BA61D3F-E73A-11d0-8CD2-00C04FC295EE' = 'CTL'                  # CRYPT_SUBJTYPE_CTL_IMAGE
            'DE351A42-8E59-11D0-8C47-00C04FC295EE' = 'Flat'                 # CRYPT_SUBJTYPE_FLAT_IMAGE
            'C689AAB8-8E78-11D0-8C47-00C04FC295EE' = 'PortableExecutable'   # CRYPT_SUBJTYPE_PE_IMAGE
            'C689AAB9-8E78-11D0-8C47-00C04FC295EE' = 'JavaClass'            # CRYPT_SUBJTYPE_JAVACLASS_IMAGE - modern wintrust.dll explicitly deregisters this SIP within DllRegisterServer
            '941C2937-1292-11D1-85BE-00C04FC295EE' = 'StructuredStorage'    # CRYPT_SUBJTYPE_SS_IMAGE - modern wintrust.dll explicitly deregisters this SIP within DllRegisterServer
            # "IsStructuredStorageFile" calls "StgIsStorageFile"
            '06C9E010-38CE-11D4-A2A3-00104BD35090' = 'WSHJScript'           # OID_JSSIP
            '1629F04E-2799-4DB5-8FE5-ACE10F17EBAB' = 'WSHVBScript'          # OID_VBSSIP
            '1A610570-38CE-11D4-A2A3-00104BD35090' = 'WSHWindowsScriptFile' # OID_WSFSIP
            '0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1' = 'AppX'
            '0F5F58B3-AADE-4B9A-A434-95742D92ECEB' = 'AppXBundle'
            'CF78C6DE-64A2-4799-B506-89ADFF5D16D6' = 'AppXEncrypted'
            'D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C' = 'AppXEncryptedBundle'
            '5598CFF1-68DB-4340-B57F-1CACF88C9A51' = 'AppXP7XSignature'
            '000C10F1-0000-0000-C000-000000000046' = 'MSI'
            '603BCC1F-4B59-4E08-B724-D2C6297EF351' = 'PowerShell'
            '9F3053C5-439D-4BF7-8A77-04F0450A1D9F' = 'ElectronicSoftwareDistribution'
            '9FA65764-C36F-4319-9737-658A34585BB7' = 'MicrosoftOfficeVBA'
            'E8406D45-5404-497e-8250-2260C3ABD51B' = 'VisualBasicEnvironment'
            # I only ever found this on VirusTotal
            'BA08A66F-113B-4D58-9329-A1B37AF30F0E' = 'SilverlightXAP'
                # xapauthenticodesip.dll - XAP_CryptSIPCreateIndirectData,XAP_CryptSIPGetSignedDataMsg,XAP_CryptSIPPutSignedDataMsg,XAP_CryptSIPRemoveSignedDataMsg,XAP_CryptSIPVerifyIndirectData,XAP_IsFileSupportedName
            'CB034CC7-4A2D-8E07-48E7-F82436FFA03E' = 'MicrosoftDynamicsNAV'
                # navsip.dll - NavSIPCreateIndirectData,NavSIPGetCaps,NavSIPGetSignedDataMsg,NavSIPIsFileSupportedName,NavSIPPutSignedDataMsg,NavSIPRemoveSignedDataMsg,NavSIPVerifyIndirectData
        }

        $ArchMapping = @{}

        # Retrieve SIPs only for the architectures specified.
        # For targeting searching, this will seriously reduce bandwidth/latency.
        # x86 implies WoW64, x64 implies 64-bit on a WoW64 system, nothing specified implies attempting to retrieve both.
        $ArchMapping['x64'] = ''

        if (-not $DoNotCheckWow64) {
            $ArchMapping['x86'] = 'WOW6432Node\'
        }

        $GuidList = @{}
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Subject Interface Package (SIP) sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            foreach ($Capability in $CapabilityList) {
                foreach ($Arch in $ArchMapping.Keys) {
                    if ($Guid) { # Retrieve only the SIP GUIDs specified. For targeting searching, this will seriously reduce bandwidth/latency.
                        foreach ($GuidEntry in $Guid) {
                            $Key = "$($GuidEntry)_$($Arch)"

                            $GuidSubkey = "SOFTWARE\$($ArchMapping[$Arch])Microsoft\Cryptography\OID\EncodingType 0\$Capability\{$GuidEntry}"

                            Write-Progress -Id 2 -ParentId 1 -Activity "Current subkey:" -Status "HKLM\$GuidSubkey"

                            $Dll = Get-CSRegistryValue -Hive HKLM -SubKey $GuidSubkey -ValueName Dll @CommonArgs | Select-Object -ExpandProperty ValueContent
                            $FuncName = Get-CSRegistryValue -Hive HKLM -SubKey $GuidSubkey -ValueName FuncName @CommonArgs | Select-Object -ExpandProperty ValueContent

                            if ($Dll -or $FuncName){
                                if (-not $GuidList.ContainsKey($Key)) {
                                    $GuidList[$Key] = New-Object 'Collections.Generic.List[System.String[]]'
                                }

                                $GuidList[$Key].Add([String[]] @($Capability, $Dll, $FuncName))
                            }
                        }
                    } else { # Retrieve all SIP GUIDs
                        $Subkey = "SOFTWARE\$($ArchMapping[$Arch])Microsoft\Cryptography\OID\EncodingType 0\$Capability"

                        Write-Progress -Id 2 -ParentId 1 -Activity "Current subkey:" -Status $Subkey

                        Get-CSRegistryKey -Hive HKLM -SubKey $Subkey @CommonArgs | ForEach-Object {
                            $GuidSubkey = $_.Subkey.Split('\')[-1].Trim(@('{','}')) + "_$Arch"

                            $Dll = $_ | Get-CSRegistryValue -ValueName Dll | Select-Object -ExpandProperty ValueContent
                            $FuncName = $_ | Get-CSRegistryValue -ValueName FuncName | Select-Object -ExpandProperty ValueContent

                            if ($Dll -or $FuncName){
                                if (-not $GuidList.ContainsKey($GuidSubkey)) {
                                    $GuidList[$GuidSubkey] = New-Object 'Collections.Generic.List[System.String[]]'
                                }

                                $GuidList[$GuidSubkey].Add([String[]] @($Capability, $Dll, $FuncName))
                            }
                        }
                    }
                }
            }

            foreach ($GuidEntry in $GuidList.Keys) {
                $Capabilities = foreach ($Entry in $GuidList[$GuidEntry]) {
                    $Capability, $Dll, $FuncName = $Entry

                    [PSCustomObject] @{
                        CapabilityName = $Capability
                        Dll = $Dll
                        FunctionName = $FuncName
                    }
                }

                $RawGuid, $Arch = $GuidEntry.Split('_')

                $IsWow64 = $False

                if ($Arch -eq 'x86') { $IsWow64 = $True }

                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.SubjectInterfacePackage'
                    Guid = $RawGuid
                    IsWow64 = $IsWow64
                    FriendlyName = $GuidFriendlyNames[$RawGuid]
                    Capabilities = $Capabilities
                }

                if ($Session.ComputerName) {
                    $ObjectProperties['PSComputerName'] = $ComputerName
                }

                [PSCustomObject] $ObjectProperties
            }
        }  
    }
}

Export-ModuleMember -Function Get-CSTrustProvider, Get-CSSubjectInterfacePackage