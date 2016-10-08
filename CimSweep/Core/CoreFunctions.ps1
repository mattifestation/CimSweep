function Get-CSRegistryKey {
<#
.SYNOPSIS

Enumerates registry subkeys for a specified path.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSRegistryKey returns all keys for a specified path.

.PARAMETER Hive

Specifies the registry hive. WMI only supports registry operations on the following hives: HKLM, HKCU, HKU, HKCR, HKCC.

.PARAMETER SubKey

Specifies the path that contains the subkeys to be enumerated. The absense of this argument will list the root keys for the specified hive.

.PARAMETER IncludeAcl

Specifies that the ACL for the key should be returned. -IncludeAcl will append an ACL property to each returned CimSweep.RegistryKey object. The ACL property is a System.Security.AccessControl.RegistrySecurity object. It is not recommended to use -IncludeAcl with -Recurse as it will significantly increase execution time and network bandwidth if used with CIM sessions.

.PARAMETER Recurse

Gets the registry keys in the specified subkey as well as all child keys.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSRegistryKey -Hive HKLM

.EXAMPLE

Get-CSRegistryKey -Hive HKCU -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\

.EXAMPLE

Get-CSRegistryKey -Hive HKLM -Recurse -CimSession $CimSession

Lists all registry keys on a remote system in the HKLM hive.

.EXAMPLE

Get-CSRegistryKey -Hive HKLM | Get-CSRegistryKey

Lists all 2nd level registry keys starting from the root of HKLM.

.INPUTS

PSObject

Accepts output from Get-CSRegistryKey. This enables recursion.

.OUTPUTS

CimSweep.RegistryKey

Outputs a list of objects representing registry keys.

.NOTES

It is not recommended to recursively list all registry keys from most parent keys as obtaining the results can be time consuming. It is recommended to use Get-CSRegistryKey with targeted subkey paths.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.RegistryKey')]
    param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        [ValidateSet('HKLM', 'HKCU', 'HKU', 'HKCR', 'HKCC')]
        $Hive,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        $SubKey = '',

        [Switch]
        $IncludeAcl,

        [Switch]
        $Recurse,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
        }

        $AddAcl = @{}
        if ($PSBoundParameters['IncludeAcl']) { $AddAcl['IncludeAcl'] = $True }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # These values are defined in WinReg.h and here:
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa390387.aspx
            switch ($Hive) {
                'HKLM' { $HiveVal = [UInt32] 2147483650 }
                'HKCU' { $HiveVal = [UInt32] 2147483649 }
                'HKU'  { $HiveVal = [UInt32] 2147483651 }
                'HKCR' { $HiveVal = [UInt32] 2147483648 }
                'HKCC' { $HiveVal = [UInt32] 2147483653 }
            }

            $TrimmedKey = $SubKey.Trim('\')

            $CimMethodArgs = @{
                ClassName =  'StdRegProv'
                Namespace =  'root/default'
                MethodName = 'EnumKey'
            }

            if ($Session.Id) { $CimMethodArgs['CimSession'] = $Session }

            $RegistryMethodArgs = @{
                hDefKey = $HiveVal
                sSubKeyName = $TrimmedKey
            }

            $CimMethodArgs['Arguments'] = $RegistryMethodArgs

            $Result = Invoke-CimMethod @CimMethodArgs @Timeout

            if ($Result.sNames) {
                foreach ($KeyName in $Result.sNames) {
                    $NewSubKey = "$TrimmedKey\$KeyName".Trim('\')

                    # I would like for this to just be a PSCustomObject but it has to remain
                    # a hashtable since I am using it as splatted arguments to itself in the
                    # case of recursion.
                    $ObjectProperties = [Ordered] @{
                        PSTypeName = 'CimSweep.RegistryKey'
                        Hive = $Hive
                        SubKey = $NewSubKey
                    }

                    $DefaultProperties = @('Hive', 'SubKey') -as [Type] 'Collections.Generic.List[String]'

                    if ($IncludeAcl) {
                        $GetSDArgs = @{
                            Namespace = 'root/default'
                            ClassName = 'StdRegProv'
                            MethodName = 'GetSecurityDescriptor'
                            Arguments = @{
                                hDefKey = $HiveVal
                                sSubKeyName = $NewSubKey
                            }
                        }

                        $SessionArg = @{}
                        if ($Session.Id) { $SessionArg['CimSession'] = $Session }

                        $GetSDResult = Invoke-CimMethod @GetSDArgs @SessionArg
                        $RegSD = $null

                        if ($GetSDResult.ReturnValue -eq 0) {
                            $Win32SDToBinarySDArgs = @{
                                ClassName = 'Win32_SecurityDescriptorHelper'
                                MethodName = 'Win32SDToBinarySD'
                                Arguments = @{
                                    Descriptor = $GetSDResult.Descriptor
                                }
                            }

                            $ConversionResult = Invoke-CimMethod @Win32SDToBinarySDArgs @SessionArg

                            if ($ConversionResult.ReturnValue -eq 0) {
                                $RegSD = New-Object Security.AccessControl.RegistrySecurity
                                $RegSD.SetSecurityDescriptorBinaryForm($ConversionResult.BinarySD, 'All')
                            }
                        }

                        if ($null -eq $RegSD) {
                            Write-Warning "[$ComputerName] Unable to obtain registry key ACL for: $Hive\$NewSubKey"
                        }

                        $ObjectProperties['ACL'] = $RegSD
                    }

                    if ($Result.PSComputerName) {
                        $ObjectProperties['PSComputerName'] = $Result.PSComputerName
                        $DefaultProperties.Add('PSComputerName')
                    } else {
                        $ObjectProperties['PSComputerName'] = $null
                    }

                    if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                    $KeyObject = New-Object -TypeName PSObject -Property $ObjectProperties

                    Set-DefaultDisplayProperty -InputObject $KeyObject -PropertyNames $DefaultProperties

                    $KeyObject

                    if ($PSBoundParameters['Recurse']) {
                        $ObjectProperties.Remove('PSTypeName')
                        $ObjectProperties.Remove('PSComputerName')
                        $ObjectProperties.Remove('ACL')
                        Get-CSRegistryKey @ObjectProperties @Timeout @AddAcl -Recurse
                    }
                }
            }
        }
    }
}

function Get-CSRegistryValue {
<#
.SYNOPSIS

Enumerates registry value names and data types for a specified path.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSRegistryValue returns all value name and type information for a specified path.

.PARAMETER Hive

Specifies the registry hive. WMI only supports registry operations on the following hives: HKLM, HKCU, HKU, HKCR, HKCC.

.PARAMETER SubKey

Specifies the path that contains the subkeys to be enumerated. The absense of this argument will list the root keys for the specified hive.

.PARAMETER ValueName

Specifies the registry value name.

.PARAMETER ValueType

Specifies the registry value type. This parameter is only necessary when retrieving the default value for a key when no other values are present. By default, Get-CSRegistryValue does not require you to specify the type since it first obtains the type by calling EnumValues. EnumValues will not return the default value type though if it is the only value present in a key.

.PARAMETER ValueNameOnly

Specifies that the content of the registry value should not be received. This switch can be used to speed up Get-CSRegistryValue and reduce network bandwidth when the content is not desired.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSRegistryValue -Hive HKCU -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Lists all value names present in the current user Run key.

.EXAMPLE

Get-CSRegistryKey -Hive HKLM -Subkey SYSTEM\CurrentControlSet\Services -CimSession $CimSession | Get-CSRegistryValue

Get the value names and types for all services on a remote system.

.EXAMPLE

Get-CSRegistryValue -Hive HKLM -Subkey SOFTWARE\Microsoft\Windows\CurrentVersion\Run

.EXAMPLE

Get-CSRegistryValue -Hive HKLM -Subkey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ValueName CurrentVersion

.INPUTS

CimSweep.RegistryKey

Accepts output from Get-CSRegistryKey. This allows you to list all registry value names for all keys contained within a parent key.

.OUTPUTS

CimSweep.RegistryValue

Outputs a list of objects representing registry value names, their respective types, and content for a specified key.

#>
    
    [CmdletBinding(DefaultParameterSetName='HiveValueNameNoType')]
    [OutputType('CimSweep.RegistryValue')]
    param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValueNameNoType')]
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValues')]
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValueNameWithType')]
        [String]
        [ValidateSet('HKLM', 'HKCU', 'HKU', 'HKCR', 'HKCC')]
        $Hive,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValueNameNoType')]
        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValues')]
        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValueNameWithType')]
        [String]
        $SubKey = '',

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValueNameNoType')]
        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'HiveValueNameWithType')]
        [Parameter(ParameterSetName = 'PathValueNameNoType')]
        [Parameter(ParameterSetName = 'PathValueNameWithType')]
        [String]
        $ValueName,

        [Parameter(Mandatory = $True, ParameterSetName = 'HiveValueNameWithType')]
        [Parameter(Mandatory = $True, ParameterSetName = 'PathValueNameWithType')]
        [String]
        [ValidateSet(
            'REG_NONE',
            'REG_SZ',
            'REG_EXPAND_SZ',
            'REG_BINARY',
            'REG_DWORD',
            'REG_QWORD',
            'REG_MULTI_SZ',
            'REG_RESOURCE_LIST',
            'REG_FULL_RESOURCE_DESCRIPTOR',
            'REG_RESOURCE_REQUIREMENTS_LIST'
        )]
        $ValueType,

        [Parameter(Mandatory = $True, ParameterSetName = 'HiveValues')]
        [Parameter(Mandatory = $True, ParameterSetName = 'PathValues')]
        [Switch]
        $ValueNameOnly,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        $Type = @{
            0  = 'REG_NONE'
            1  = 'REG_SZ'
            2  = 'REG_EXPAND_SZ'
            3  = 'REG_BINARY'
            4  = 'REG_DWORD'
            7  = 'REG_MULTI_SZ'
            8  = 'REG_RESOURCE_LIST' # Just treat this as binary
            9  = 'REG_FULL_RESOURCE_DESCRIPTOR' # Just treat this as binary
            10 = 'REG_RESOURCE_REQUIREMENTS_LIST' # Just treat this as binary
            11 = 'REG_QWORD'
        }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            switch ($Hive) {
                'HKLM' { $HiveVal = [UInt32] 2147483650 }
                'HKCU' { $HiveVal = [UInt32] 2147483649 }
                'HKU'  { $HiveVal = [UInt32] 2147483651 }
                'HKCR' { $HiveVal = [UInt32] 2147483648 }
                'HKCC' { $HiveVal = [UInt32] 2147483653 }
            }

            $TrimmedKey = $SubKey.Trim('\')

            $CimMethodArgs = @{
                ClassName = 'StdRegProv'
                Namespace = 'root/default'
            }

            if ($Session.Id) { $CimMethodArgs['CimSession'] = $Session }

            if ($PSBoundParameters['ValueType']) {
                switch ($ValueType) {
                    'REG_NONE' {
                        $CimMethodArgs['MethodName'] = 'GetBinaryValue'
                        $ReturnProp = 'uValue'
                    }

                    'REG_SZ' {
                        $CimMethodArgs['MethodName'] = 'GetStringValue'
                        $ReturnProp = 'sValue'
                    }

                    'REG_EXPAND_SZ' {
                        $CimMethodArgs['MethodName'] = 'GetExpandedStringValue'
                        $ReturnProp = 'sValue'
                    }

                    'REG_MULTI_SZ' {
                        $CimMethodArgs['MethodName'] = 'GetMultiStringValue'
                        $ReturnProp = 'sValue'
                    }

                    'REG_DWORD' {
                        $CimMethodArgs['MethodName'] = 'GetDWORDValue'
                        $ReturnProp = 'uValue'
                    }

                    'REG_QWORD' {
                        $CimMethodArgs['MethodName'] = 'GetQWORDValue'
                        $ReturnProp = 'uValue'
                    }

                    'REG_BINARY' {
                        $CimMethodArgs['MethodName'] = 'GetBinaryValue'
                        $ReturnProp = 'uValue'
                    }

                    'REG_RESOURCE_LIST' {
                        $CimMethodArgs['MethodName'] = 'GetBinaryValue'
                        $ReturnProp = 'uValue'
                    }

                    'REG_FULL_RESOURCE_DESCRIPTOR' {
                        $CimMethodArgs['MethodName'] = 'GetBinaryValue'
                        $ReturnProp = 'uValue'
                    }

                    'REG_RESOURCE_REQUIREMENTS_LIST' {
                        $CimMethodArgs['MethodName'] = 'GetBinaryValue'
                        $ReturnProp = 'uValue'
                    }
                }

                $RegistryMethodArgs = @{
                    hDefKey = $HiveVal
                    sSubKeyName = $TrimmedKey
                    sValueName = $ValueName
                }

                $CimMethodArgs['Arguments'] = $RegistryMethodArgs

                $ValueContent = $null

                if (-not $PSBoundParameters['ValueNameOnly']) {
                    $Result = Invoke-CimMethod @CimMethodArgs @Timeout

                    if ($Result.ReturnValue -eq 0) {
                        $ValueContent = $Result."$ReturnProp"
                    }
                }

                $ObjectProperties = [Ordered] @{
                    Hive = $Hive
                    SubKey = $TrimmedKey
                    ValueName = if ($ValueName) { $ValueName } else { '(Default)' }
                    Type = $ValueType
                    ValueContent = $ValueContent
                }

                $DefaultProperties = [String[]] $ObjectProperties.Keys -as [Type] 'Collections.Generic.List[String]'
                $ObjectProperties['PSTypeName'] = 'CimSweep.RegistryValue'

                if ($Result.PSComputerName) {
                    $ObjectProperties['PSComputerName'] = $Result.PSComputerName
                    $DefaultProperties.Add('PSComputerName')
                } else {
                    $ObjectProperties['PSComputerName'] = $null
                }

                if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                $ValueObject = [PSCustomObject] $ObjectProperties

                Set-DefaultDisplayProperty -InputObject $ValueObject -PropertyNames $DefaultProperties

                $ValueObject
            } else {
                $CimMethodArgs['MethodName'] = 'EnumValues'

                $RegistryMethodArgs = @{
                    hDefKey = $HiveVal
                    sSubKeyName = $TrimmedKey
                }

                $CimMethodArgs['Arguments'] = $RegistryMethodArgs

                $Result = Invoke-CimMethod @CimMethodArgs @Timeout

                # Only progress if EnumValues returns actual value and type data
                if ($Result.Types.Length) {
                    $Types = $Result.Types.ForEach({$Type[$_]})

                    $ValueNames = $Result.sNames

                    for ($i = 0; $i -lt $Result.Types.Length; $i++) {
                        $ValueContent = $null

                        $CimMethod2Args = @{
                            ClassName = 'StdRegProv'
                            Namespace = 'root/default'
                        }

                        if ($Session.Id) { $CimMethod2Args['CimSession'] = $Session }

                        switch ($Types[$i]) {
                            'REG_NONE' {
                                $CimMethod2Args['MethodName'] = 'GetBinaryValue'
                                $ReturnProp = 'uValue'
                            }

                            'REG_SZ' {
                                $CimMethod2Args['MethodName'] = 'GetStringValue'
                                $ReturnProp = 'sValue'
                            }

                            'REG_EXPAND_SZ' {
                                $CimMethod2Args['MethodName'] = 'GetExpandedStringValue'
                                $ReturnProp = 'sValue'
                            }

                            'REG_MULTI_SZ' {
                                $CimMethod2Args['MethodName'] = 'GetMultiStringValue'
                                $ReturnProp = 'sValue'
                            }

                            'REG_DWORD' {
                                $CimMethod2Args['MethodName'] = 'GetDWORDValue'
                                $ReturnProp = 'uValue'
                            }

                            'REG_QWORD' {
                                $CimMethod2Args['MethodName'] = 'GetQWORDValue'
                                $ReturnProp = 'uValue'
                            }

                            'REG_BINARY' {
                                $CimMethod2Args['MethodName'] = 'GetBinaryValue'
                                $ReturnProp = 'uValue'
                            }

                            'REG_RESOURCE_LIST' {
                                $CimMethod2Args['MethodName'] = 'GetBinaryValue'
                                $ReturnProp = 'uValue'
                            }

                            'REG_FULL_RESOURCE_DESCRIPTOR' {
                                $CimMethod2Args['MethodName'] = 'GetBinaryValue'
                                $ReturnProp = 'uValue'
                            }

                            'REG_RESOURCE_REQUIREMENTS_LIST' {
                                $CimMethod2Args['MethodName'] = 'GetBinaryValue'
                                $ReturnProp = 'uValue'
                            }

                            default {
                                Write-Warning "[$ComputerName] $($Result.Types[$i]) is not a supported registry value type. Hive: $Hive. SubKey: $SubKey"
                    
                                $CimMethod2Args['MethodName'] = 'GetBinaryValue'
                                $ReturnProp = 'uValue'
                            }
                        }

                        $RegistryMethod2Args = @{
                            hDefKey = $HiveVal
                            sSubKeyName = $TrimmedKey
                            sValueName = $ValueNames[$i]
                        }

                        $CimMethod2Args['Arguments'] = $RegistryMethod2Args

                        if (($PSBoundParameters.ContainsKey('ValueName') -and ($ValueName -eq $ValueNames[$i])) -or (-not $PSBoundParameters.ContainsKey('ValueName'))) {
                            $ValueContent = $null

                            if (-not $PSBoundParameters['ValueNameOnly']) {
                                $Result2 = Invoke-CimMethod @CimMethod2Args @Timeout

                                if ($Result2.ReturnValue -eq 0) {
                                    $ValueContent = $Result2."$ReturnProp"
                                }
                            }

                            $ObjectProperties = [Ordered] @{
                                Hive = $Hive
                                SubKey = $TrimmedKey
                                ValueName = if ($ValueNames[$i]) { $ValueNames[$i] } else { '(Default)' }
                                Type = $Types[$i]
                                ValueContent = $ValueContent
                            }

                            $DefaultProperties = [String[]] $ObjectProperties.Keys -as [Type] 'Collections.Generic.List[String]'
                            $ObjectProperties['PSTypeName'] = 'CimSweep.RegistryValue'

                            if ($Result.PSComputerName) {
                                $ObjectProperties['PSComputerName'] = $Result.PSComputerName
                                $DefaultProperties.Add('PSComputerName')
                            } else {
                                $ObjectProperties['PSComputerName'] = $null
                            }

                            if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                            $ValueObject = [PSCustomObject] $ObjectProperties

                            Set-DefaultDisplayProperty -InputObject $ValueObject -PropertyNames $DefaultProperties

                            $ValueObject
                        }
                    }
                }
            }
        }
    }
}

function Get-CSEventLog {
<#
.SYNOPSIS

Gets a list of event logs on the computer.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSEventLog lists the available event logs from which event entries can be retrieved via WMI. 

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.NOTES

Get-CSEventLog is useful for determining which event log to filter off of in Get-CSEventLogEntry.

.EXAMPLE

Get-CSEventLog

List all available event logs queryable via WMI.

.EXAMPLE

Get-CSEventLog | Get-CSEventLogEntry

List event log entries from all available event logs. Note: Get-CSEventLogEntry without any additional arguments will return entries from all event logs by default.

.OUTPUTS

CimSweep.EventLog

Outputs objects representing the available event logs which can be piped to Get-CSEventLogEntry.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.EventLog')]
    param(
        [Switch]
        $NoProgressBar,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
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

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Event log sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            Get-CimInstance -ClassName Win32_NTEventlogFile -Property LogfileName @CommonArgs @Timeout | ForEach-Object {
                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.EventLog'
                    LogName = $_.LogfileName
                }

                $DefaultProperties = @('LogName') -as [Type] 'Collections.Generic.List[String]'

                if ($_.PSComputerName) {
                    $ObjectProperties['PSComputerName'] = $_.PSComputerName
                    $DefaultProperties.Add('PSComputerName')
                } else {
                    $ObjectProperties['PSComputerName'] = $null
                }

                if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                $EventLog = [PSCustomObject] $ObjectProperties

                Set-DefaultDisplayProperty -InputObject $EventLog -PropertyNames $DefaultProperties

                $EventLog
            }
        }
    }
}

function Get-CSEventLogEntry {
<#
.SYNOPSIS

Gets the events in an event log on the local or remote computers.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

The Get-CSEventLogEntry cmdlet gets events and event logs on the local and remote computers.

Use the parameters of Get-CSEventLogEntry to search for events by using their property values. Get-CSEventLogEntry gets only the events that match all of the specified property values.

.PARAMETER LogName

Specifies the event log. Event log names can be obtained with Get-CSEventLog.

.PARAMETER EventCode

Gets only events with the specified event code. EventCode refers to the value of the lower 16-bits of the EventIdentifier property. EventCode matches the value displayed in the Windows Event Viewer.

.PARAMETER EventIdentifier

Gets only events with the specified event identifier.

.PARAMETER EntryType

Gets only events with the specified entry type. Valid values are Error, Information, FailureAudit, SuccessAudit, and Warning. The default is all events.

.PARAMETER TimeGenerated

Gets only the events that occur within one second the specified date and time. Enter a DateTime object, such as the one returned by the Get-Date cmdlet. Note: Datetimes are automatically converted to UTC.

.PARAMETER TimeGeneratedAfter

Gets only the events that occur after the specified date and time. Enter a DateTime object, such as the one returned by the Get-Date cmdlet. Note: Datetimes are automatically converted to UTC.

.PARAMETER TimeGeneratedBefore

Gets only the events that occur before the specified date and time. Enter a DateTime object, such as the one returned by the Get-Date cmdlet. Note: Datetimes are automatically converted to UTC.

.PARAMETER Message

Gets events that have the specified string in their messages. You can use this property to search for messages that contain certain words or phrases. Wildcards are permitted.

.PARAMETER Source

Gets events that were written to the log by the specified sources.

.PARAMETER UserName

Gets only the events that are associated with the specified user names.

.PARAMETER LimitOutput

Specifies that an explicit list of Win32_Process properties should be returned. This can significantly reduce the time it takes to sweep across many systems is only a subset of properties are desired.

.PARAMETER Property

Specifies the desired properties to retrieve from Win32_Process instances. The following properties are returned when limited output is desired: ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSEventLogEntry

Returns every event log entry.

.EXAMPLE

Get-CSEventLogEntry -CimSession $CimSession -LogName Security -EventIdentifier 4624

Returns all successful logon events on the remote system.

.EXAMPLE

Get-CSEventLogEntry -CimSession $CimSession -EntryType FailureAudit

.INPUTS

CimSweep.EventLog

Accepts input from Get-CSEventLog.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_NTLogEvent

Outputs Win32_NtLogEvent instances.
#>

    [OutputType('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_NTLogEvent')]
    [CmdletBinding(DefaultParameterSetName='DefaultOutput')]
    param(
        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $LogName,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [UInt32[]]
        $EventCode,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [UInt32[]]
        $EventIdentifier,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateSet('Error', 'Information', 'FailureAudit', 'SuccessAudit', 'Warning')]
        $EntryType,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $TimeGenerated,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        [Alias('After')]
        $TimeGeneratedAfter,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        [Alias('Before')]
        $TimeGeneratedBefore,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Message,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Source,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Switch]
        $LimitOutput,

        [Parameter(ParameterSetName='RestrictOutput')]
        [String[]]
        [ValidateSet(
            'Category',
            'CategoryString',
            'ComputerName',
            'Data',
            'EventCode',
            'EventIdentifier',
            'EventType',
            'InsertionStrings',
            'Logfile',
            'Message',
            'RecordNumber',
            'SourceName',
            'TimeGenerated',
            'TimeWritten',
            'Type',
            'User')]
        $Property = @('LogFile', 'CategoryString', 'EventCode', 'EventIdentifier', 'Message', 'SourceName', 'TimeGenerated', 'Type'),

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Switch]
        $NoProgressBar,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName='DefaultOutput')]
        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName='RestrictOutput')]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
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

        $PropertyList = @{}
        if ($PSBoundParameters['LimitOutput'] -or $PSBoundParameters['Property']) { $PropertyList['Property'] = $Property }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Event log entry sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $EventLogEntryArgs = @{}

            $FilterComponents = New-Object 'Collections.ObjectModel.Collection`1[System.String]'

            $TypeMapping = @{
                Error =        [Byte] 1
                Warning =      [Byte] 2
                Information =  [Byte] 3
                SuccessAudit = [Byte] 4
                FailureAudit = [Byte] 5
            }

            if ($PSBoundParameters['LogName']) { $FilterComponents.Add("LogFile='$LogName'") }
            if ($PSBoundParameters['EventCode']) { $FilterComponents.Add("($(($EventCode | ForEach-Object { "EventCode = $_" }) -join ' OR '))") }
            if ($PSBoundParameters['EventIdentifier']) { $FilterComponents.Add("($(($EventIdentifier | ForEach-Object { "EventIdentifier = $_" }) -join ' OR '))") }
            if ($PSBoundParameters['EntryType']) { $FilterComponents.Add("EventType=$($TypeMapping[$EntryType])") }
            if ($PSBoundParameters['TimeGenerated']) {
                # Mask off milliseconds. I can't think of anyone who would want to search within millisecond granularity.
                $BeginningOfSecond = $TimeGenerated.AddMilliseconds(- $TimeGenerated.Millisecond)
                $EndOfSecond = $BeginningOfSecond.AddSeconds(1)

                $FilterComponents.Add("TimeGenerated>='$($BeginningOfSecond.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff+000'))' AND TimeGenerated<='$($EndOfSecond.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff+000'))'")
            }
            if ($PSBoundParameters['TimeGeneratedBefore']) { $FilterComponents.Add("TimeGenerated<'$($TimeGeneratedBefore.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff+000'))'") }
            if ($PSBoundParameters['TimeGeneratedAfter']) { $FilterComponents.Add("TimeGenerated>'$($TimeGeneratedAfter.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff+000'))'") }
            if ($PSBoundParameters['Message']) { $FilterComponents.Add("Message LIKE '%$($Message)%'") }
            if ($PSBoundParameters['Source']) { $FilterComponents.Add("SourceName LIKE '%$Source%'") }

            if ($FilterComponents.Count) {
                $Filter = $FilterComponents -join ' AND '
                $EventLogEntryArgs['Filter'] = $Filter
            }

            Get-CimInstance -ClassName Win32_NTLogEvent @CommonArgs @EventLogEntryArgs @PropertyList @Timeout
        }
    }
}

function Get-CSMountedVolumeDriveLetter {
<#
.SYNOPSIS

Lists mounted drive letters present.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSMountedVolumeDriveLetter lists the drive letters of mounted drives. This is primarily used as a helper for Get-CSDirectoryListing when no parameters are provided.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSMountedVolumeDriveLetter

Lists mounted drive letters on a local system.

.EXAMPLE

Get-CSMountedVolumeDriveLetter -CimSession $CimSession

Lists mounted drive letters on a remote system.

.OUTPUTS

CimSweep.DiskInfo

Outputs a list of mounted drive letters.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.DiskInfo')]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $Result = Get-CimInstance -ClassName Win32_LogicalDisk -Property DeviceID @CommonArgs @Timeout

            foreach ($Volume in $Result) {
                if ($Volume.DeviceID) {
                    $ObjectProperties = [Ordered] @{
                        PSTypeName = 'CimSweep.DiskInfo'
                        DriveLetter = $Volume.DeviceID[0]
                        DirectoryPath = "$($Volume.DeviceID)\"
                    }

                    $DefaultProperties = 'DriveLetter', 'DirectoryPath' -as [Type] 'Collections.Generic.List[String]'

                    if ($Volume.PSComputerName) {
                        $ObjectProperties['PSComputerName'] = $Volume.PSComputerName
                        $DefaultProperties.Add('PSComputerName')
                    } else {
                        $ObjectProperties['PSComputerName'] = $null
                    }

                    if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                    $DiskInfo = [PSCustomObject] $ObjectProperties

                    Set-DefaultDisplayProperty -InputObject $DiskInfo -PropertyNames $DefaultProperties

                    $DiskInfo
                }
            }
        }
    }
}

function Get-CSDirectoryListing {
<#
.SYNOPSIS

Lists files and directories present in the specified directory.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSDirectoryListing performs a WMI/CIM-based file/directory listing of the specified directory.

.PARAMETER DirectoryPath

Specifies the directory. Do not include the file name. If a specific file name is desired, specify the file name with the FileName parameter.

.PARAMETER FileName

Specifies that information for a specific file should be returned.

.PARAMETER FileSize

Only return files with the specified file sizes.

.PARAMETER Extension

Only return files with the specified file extensions.

.PARAMETER Hidden

Only return hidden files

.PARAMETER LastModified

Specifies that only files modified on specified date should be returned.

.PARAMETER LastModifiedAfter

Specifies that only files modified after the specified date should be returned.

.PARAMETER LastModifiedBefore

Specifies that only files modified before the specified date should be returned.

.PARAMETER LastAccessed

Specifies that only files accessed on specified date should be returned.

.PARAMETER LastAccessedAfter

Specifies that only files accessed after the specified date should be returned.

.PARAMETER LastAccessedBefore

Specifies that only files accessed before the specified date should be returned.

.PARAMETER CreationDate

Specifies that only files created on specified date should be returned.

.PARAMETER CreationDateAfter

Specifies that only files created after the specified date should be returned.

.PARAMETER CreationDateBefore

Specifies that only files created before the specified date should be returned.

.PARAMETER File

Specifies that only files should be returned for the specified directory. This is to be used as a performance enhancement for wrapper functions.

.PARAMETER Directory

Specifies that only directories should be listed.

.PARAMETER IncludeAcl

Specifies that the ACL for the returned file or directory should be included. -IncludeAcl will append an ACL property to each returned object. The ACL property is a System.Security.AccessControl.FileSecurity or DirectorySecurity object. It is not recommended to use -IncludeAcl with -Recurse as it will significantly increase execution time and network bandwidth if used with CIM sessions.

.PARAMETER DoNotDetectRecursiveDirs

Do not perform checks on self-referential directories when performing recursion. Many tools allow you to not follow path pointed to by symlinks. Unfortunately, Win32_Directory doesn't reflect whether or not a directory is a symlink. By default, Get-CSDirectoryListing will attempt to check if it's recursing through a self-referential directory. There is a possibility that this could lead to false negatives though. This option specifies that this check should not be performed.

.PARAMETER Recurse

Recurse on all child directories.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSDirectoryListing

Directory listing for the root of each mounted drive.

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\Windows\System32\ -CimSession $CimSession

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\Windows\System32\ -FileName kernel32.dll

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\Windows\System32\Tasks -Recurse

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\ -Extension exe, dll, sys -Recurse -CimSession $CimSession, $CimSession2

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\Users -Directory | Get-CSDirectoryListing -Extension exe, dll -Recurse

Lists all EXE and DLL files present in all user directories.

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\ -Directory -Recurse

Lists all directories present in C:\.

.EXAMPLE

Get-CSDirectoryListing 'c:\$recycle.bin' -Recurse

List all files and directories present in c:\$recycle.bin. Note: single quotes are necessary since PowerShell will attempt to expand "$recycle" by default.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/CIM_LogicalFile

Outputs a CIM_DataFile, Win32_ShortcutFile, or a Win32_Directory instance representing file, shortcut, or directory information.

.NOTES

Filter parameters in Get-CSDirectoryListing only apply to files, not directories.
#>

    [CmdletBinding(DefaultParameterSetName = 'DirOnly')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/CIM_LogicalFile')]
    param(
        [Parameter(ValueFromPipelineByPropertyName = $True, Position = 0)]
        [Alias('Name')]
        [String]
        [ValidatePattern('^[A-Za-z]:\\.*$')]
        $DirectoryPath,

        [Parameter(ParameterSetName = 'FileQuery')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $FileName,

        [Parameter(ParameterSetName = 'FileQuery')]
        [ValidateNotNullOrEmpty()]
        [UInt64[]]
        $FileSize,

        [Parameter(ParameterSetName = 'FileQuery')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Extension,

        [Parameter(ParameterSetName = 'FileQuery')]
        [Switch]
        $Hidden,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $LastModified,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $LastModifiedAfter,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $LastModifiedBefore,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $LastAccessed,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $LastAccessedAfter,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $LastAccessedBefore,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $CreationDate,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $CreationDateAfter,

        [Parameter(ParameterSetName = 'FileQuery')]
        [DateTime]
        [ValidateNotNullOrEmpty()]
        $CreationDateBefore,

        [Parameter(ParameterSetName = 'FileQuery')]
        [Switch]
        $File,

        [Parameter(ParameterSetName = 'DirOnly')]
        [Switch]
        $Directory,

        [Switch]
        $IncludeAcl,

        [Switch]
        $DoNotDetectRecursiveDirs,
        
        [Switch]
        $Recurse,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        if (-not $DirectoryPath) {
            # If no directory path is provided, perform a file/directory listing of the root of all mounted partitions
            Get-CSMountedVolumeDriveLetter | Get-CSDirectoryListing @PSBoundParameters
            return
        } else {
            Write-Verbose "[$ComputerName] Current directory: $DirectoryPath"
        }

        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            # Normalize the directory path
            $TrimmedPath = $DirectoryPath.TrimEnd('\')

            # The validation regex guarantees that $DirectoryPath[0] will contain a drive letter
            $DriveLetter = $TrimmedPath[0]
            $NewPath = $TrimmedPath.Substring(2)

            # Build targeted Win32_Directory query
            $Filter = "Drive = `"$($DriveLetter):`" AND Path=`"$($NewPath.Replace('\', '\\'))\\`""

            $DirArguments = @{
                ClassName = 'Win32_Directory'
                Filter = $Filter
            }

            # Efficiency improvement: since only file objects will be returned,
            # only request the Name property to save bandwidth
            if ($PSCmdlet.ParameterSetName -eq 'FileQuery') { $DirArguments['Property'] = 'Name' }

            # Only obtain directory information if -File was not specified
            if (-not $PSBoundParameters['File']) {
                # Get all directories present in the specified folder
                Get-CimInstance @CommonArgs @DirArguments @Timeout | ForEach-Object {
                    $DirObject = $_

                    # Append the CimSession instance. This enables piping Get-CSDirectoryListing to itself
                    Add-Member -InputObject $DirObject -MemberType NoteProperty -Name CimSession -Value $CimSession

                    # Output the directories present if file query arguments are not present
                    if ($PSCmdlet.ParameterSetName -ne 'FileQuery') {
                        if ($IncludeAcl) {
                            $AssocArgs = @{
                                InputObject = $DirObject
                                ResultClassName = 'Win32_LogicalFileSecuritySetting'
                            }

                            $DirectorySecurity = Get-CimAssociatedInstance @AssocArgs @CommonArgs -ErrorAction SilentlyContinue
                            $DirectorySD = $null

                            if ($DirectorySecurity) {
                                $SD = Invoke-CimMethod -InputObject $DirectorySecurity -MethodName GetSecurityDescriptor @CommonArgs

                                if ($SD.ReturnValue -eq 0) {
                                    $Win32SDToBinarySDArgs = @{
                                        ClassName = 'Win32_SecurityDescriptorHelper'
                                        MethodName = 'Win32SDToBinarySD'
                                        Arguments = @{
                                            Descriptor = $SD.Descriptor
                                        }
                                    }

                                    $ConversionResult = Invoke-CimMethod @Win32SDToBinarySDArgs @CommonArgs

                                    if ($ConversionResult.ReturnValue -eq 0) {
                                        $DirectorySD = New-Object Security.AccessControl.DirectorySecurity
                                        $DirectorySD.SetSecurityDescriptorBinaryForm($ConversionResult.BinarySD, 'All')
                                    }
                                }
                            }

                            Add-Member -InputObject $DirObject -MemberType NoteProperty -Name ACL -Value $DirectorySD

                            if ($null -eq $DirectorySD) {
                                Write-Warning "[$ComputerName] Unable to obtain directory ACL for: $($DirObject.Name)"
                            }
                        }

                        $DirObject
                    }

                    if ($PSBoundParameters['Recurse']) {
                        $PSBoundParametersCopy = $PSBoundParameters

                        # Remove the provided Path arg since we're providing the subdirectory
                        $null = $PSBoundParametersCopy.Remove('DirectoryPath')

                        # 1) Match on directories that have three subdirectories of the same name
                        # 2) Match on two sets of identical subdirectories to a parent directory.
                        # Thanks to Lee Holmes for the suggestions!
                        # Since Win32_Directory doesn't capture if a directory is a symlink, 
                        if ((-not $PSBoundParameters['DoNotDetectRecursiveDirs']) -and (($DirObject.Name -match '^.*(\\[^\\]+)\1\1\1$') -or ($DirObject.Name -match '\\([^\\]+)\\([^\\]+)\\(.*\\\1\\\2){2}$'))) {
                            Write-Warning "[$ComputerName] Possible self-referential directory detected! Directory path: $($DirObject.Name)"
                        } else {
                            Get-CSDirectoryListing @PSBoundParametersCopy -DirectoryPath $DirObject.Name
                        }
                    }
                }
            }

            if (-not $PSBoundParameters['Directory']) {
                $FilterComponents = New-Object 'Collections.ObjectModel.Collection`1[System.String]'

                $DmtfFormat = 'yyyyMMddHHmmss.ffffff+000'

                if ($PSBoundParameters['FileName']) { $FilterComponents.Add("($(($FileName | ForEach-Object { "Name=``"$($TrimmedPath.Replace('\', '\\'))\\$_``"" }) -join ' OR '))") }
                if ($PSBoundParameters['FileSize']) { $FilterComponents.Add("($(($FileSize | ForEach-Object { "FileSize = $_" }) -join ' OR '))") }
                if ($PSBoundParameters['Extension']) { $FilterComponents.Add("($(($Extension | ForEach-Object { "Extension =``"$_``"" }) -join ' OR '))") }
                if ($PSBoundParameters['LastModified']) {
                    $BeginningOfSecond = $LastModified.AddMilliseconds(- $LastModified.Millisecond)
                    $EndOfSecond = $BeginningOfSecond.AddSeconds(1)

                    $FilterComponents.Add("LastModified>=`"$($BeginningOfSecond.ToUniversalTime().ToString($DmtfFormat))`" AND LastModified<=`"$($EndOfSecond.ToUniversalTime().ToString($DmtfFormat))`"")
                }
                if ($PSBoundParameters['LastModifiedBefore']) { $FilterComponents.Add("LastModified<`"$($LastModifiedBefore.ToUniversalTime().ToString($DmtfFormat))`"") }
                if ($PSBoundParameters['LastModifiedAfter']) { $FilterComponents.Add("LastModified>`"$($LastModifiedAfter.ToUniversalTime().ToString($DmtfFormat))`"") }
                if ($PSBoundParameters['LastAccessed']) {
                    $BeginningOfSecond = $LastAccessed.AddMilliseconds(- $LastAccessed.Millisecond)
                    $EndOfSecond = $BeginningOfSecond.AddSeconds(1)

                    $FilterComponents.Add("LastAccessed>=`"$($BeginningOfSecond.ToUniversalTime().ToString($DmtfFormat))`" AND LastAccessed<=`"$($EndOfSecond.ToUniversalTime().ToString($DmtfFormat))`"")
                }
                if ($PSBoundParameters['LastAccessedBefore']) { $FilterComponents.Add("LastAccessed<`"$($LastAccessedBefore.ToUniversalTime().ToString($DmtfFormat))`"") }
                if ($PSBoundParameters['LastAccessedAfter']) { $FilterComponents.Add("LastAccessed>`"$($LastAccessedAfter.ToUniversalTime().ToString($DmtfFormat))`"") }
                if ($PSBoundParameters['CreationDate']) {
                    $BeginningOfSecond = $CreationDate.AddMilliseconds(- $CreationDate.Millisecond)
                    $EndOfSecond = $BeginningOfSecond.AddSeconds(1)

                    $FilterComponents.Add("CreationDate>=`"$($BeginningOfSecond.ToUniversalTime().ToString($DmtfFormat))`" AND CreationDate<=`"$($EndOfSecond.ToUniversalTime().ToString($DmtfFormat))`"")
                }
                if ($PSBoundParameters['CreationDateBefore']) { $FilterComponents.Add("CreationDate<`"$($CreationDateBefore.ToUniversalTime().ToString($DmtfFormat))`"") }
                if ($PSBoundParameters['CreationDateAfter']) { $FilterComponents.Add("CreationDate>`"$($CreationDateAfter.ToUniversalTime().ToString($DmtfFormat))`"") }
                if ($PSBoundParameters['Hidden']) { $FilterComponents.Add('Hidden = "True"') }

                $FileFilter = $null

                # Join all the WQL query components
                if ($FilterComponents.Count) {
                    $FileFilter = ' AND ' + ($FilterComponents -join ' AND ')
                }

                $FileArguments = @{
                    ClassName = 'CIM_DataFile'
                    Filter = $DirArguments['Filter'] + $FileFilter
                }

                # Get all files present in the specified folder
                Get-CimInstance @CommonArgs @FileArguments @Timeout | ForEach-Object {
                    $Object = $_
                    Add-Member -InputObject $Object -MemberType NoteProperty -Name CimSession -Value $CimSession

                    if ($IncludeAcl) {
                        $AssocArgs = @{
                            InputObject = $Object
                            ResultClassName = 'Win32_LogicalFileSecuritySetting'
                        }

                        $FileSecurity = Get-CimAssociatedInstance @AssocArgs @CommonArgs -ErrorAction SilentlyContinue
                        $FileSD = $null

                        if ($FileSecurity) {
                            $SD = Invoke-CimMethod -InputObject $FileSecurity -MethodName GetSecurityDescriptor @CommonArgs

                            if ($SD.ReturnValue -eq 0) {
                                $Win32SDToBinarySDArgs = @{
                                    ClassName = 'Win32_SecurityDescriptorHelper'
                                    MethodName = 'Win32SDToBinarySD'
                                    Arguments = @{
                                        Descriptor = $SD.Descriptor
                                    }
                                }

                                $ConversionResult = Invoke-CimMethod @Win32SDToBinarySDArgs @CommonArgs

                                if ($ConversionResult.ReturnValue -eq 0) {
                                    $FileSD = New-Object Security.AccessControl.FileSecurity
                                    $FileSD.SetSecurityDescriptorBinaryForm($ConversionResult.BinarySD, 'All')
                                }
                            }
                        }

                        Add-Member -InputObject $Object -MemberType NoteProperty -Name ACL -Value $FileSD

                        if ($null -eq $FileSD) {
                            Write-Warning "[$ComputerName] Unable to obtain file ACL for: $($Object.Name)"
                        }
                    }

                    $Object
                }
            }
        }
    }
}

function Get-CSService {
<#
.SYNOPSIS

Gets the services including installed drivers on a local or remote computer.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

The Get-CSService cmdlet gets objects that represent the services on a local computer or on a remote computer, including running and stopped services.

.PARAMETER Name

Specifies the service names of services to be retrieved. Wildcards are permitted. By default, Get-Service gets all of the services on the computer.

.PARAMETER DisplayName

Specifies the display names of services to be retrieved. Wildcards are permitted. By default, Get-Service gets all services on the computer.

.PARAMETER State

Specifies the current state of the base service. Accepted values are Stopped, Start Pending, Stop Pending, Running, Continue Pending, Pause Pending, Paused, and Unknown.

.PARAMETER StartMode

Specifies the start mode of the Windows base service. Accepted values are Boot, System, Auto, Manual, and Disabled.

.PARAMETER ServiceType

Specifies the type of service provided to calling processes. Accepted values are Kernel Driver, File System Driver, Adapter, Recognizer Driver, Own Process, Share Process, and Interactive Process.

.PARAMETER PathName

Specifies the full path or a portion of the path to the service binary file that implements the service.

.PARAMETER Description

Specifies the service description.

.PARAMETER UserModeServices

Specifies that only classes of type Win32_Service should be returned.

.PARAMETER Drivers

Specifies that only classes of type Win32_SystemDriver should be returned.

.PARAMETER LimitOutput

Specifies that an explicit list of Win32_Process properties should be returned. This can significantly reduce the time it takes to sweep across many systems is only a subset of properties are desired.

.PARAMETER Property

Specifies the desired properties to retrieve from Win32_Process instances. The following properties are returned when limited output is desired: ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

.PARAMETER IncludeAcl

Specifies that the ACL for the service should be returned. -IncludeAcl will append an ACL property to each returned object. The ACL property is a CimSweep.ServiceSecurity object.

.PARAMETER IncludeFileInfo

Specifies that the ACL file hosting the service be returned. -IncludeFileInfo will append a FileInfo property to each returned object. The FileInfo property is a CIM_DataFile instance.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSService

.EXAMPLE

Get-CSService -State Running

Lists running services.

.EXAMPLE

Get-CSService -ServiceType 'Kernel Driver'

.EXAMPLE

Get-CSService -PathName svchost.exe

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/Win32_BaseService

Outputs Win32_Service or Win32_SystemDriver instances both of which derive from Win32_BaseService.
#>

    [CmdletBinding(DefaultParameterSetName='DefaultOutput')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/Win32_BaseService')]
    param(
        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $DisplayName,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateSet('Stopped', 'Start Pending', 'Stop Pending', 'Running', 'Continue Pending', 'Pause Pending', 'Paused', 'Unknown')]
        $State,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateSet('Boot', 'System', 'Auto', 'Manual', 'Disabled')]
        $StartMode,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateSet('Kernel Driver', 'File System Driver', 'Adapter', 'Recognizer Driver', 'Own Process', 'Share Process', 'Interactive Process')]
        $ServiceType,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $PathName,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Description,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Switch]
        $UserModeServices,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Switch]
        $Drivers,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Switch]
        $LimitOutput,

        [Parameter(ParameterSetName='RestrictOutput')]
        [String[]]
        [ValidateSet(
            'AcceptPause',
            'AcceptStop',
            'Caption',
            'CreationClassName',
            'Description',
            'DesktopInteract',
            'DisplayName',
            'ErrorControl',
            'ExitCode',
            'InstallDate',
            'Name',
            'PathName',
            'ServiceSpecificExitCode',
            'ServiceType',
            'Started',
            'StartMode',
            'StartName',
            'State',
            'Status',
            'SystemCreationClassName',
            'SystemName',
            'TagId')]
        $Property = @('Name', 'DisplayName', 'Description', 'State', 'ServiceType', 'PathName'),

        [Switch]
        $IncludeAcl,

        [Switch]
        $IncludeFileInfo,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Switch]
        $NoProgressBar,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
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

        $PropertyList = @{}
        if ($PSBoundParameters['LimitOutput'] -or $PSBoundParameters['Property']) { $PropertyList['Property'] = $Property }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        <#
        # This won't compile using Add-Type in Nano Server TP5 due to
        # a bug where it cannot determine the proper framework dir.

        Add-Type -TypeDefinition @'
        using System;
        using System.Security.AccessControl;

        namespace CimSweep
        {
            [Flags]
            public enum ServiceFlags
            {
                QueryConfig =         0x00000001,
                ChangeConfig =        0x00000002,
                QueryStatus =         0x00000004,
                EnumerateDependents = 0x00000008,
                Start =               0x00000010,
                Stop =                0x00000020,
                PauseContinue =       0x00000040,
                Interrogate =         0x00000080,
                UserDefinedControl =  0x00000100,
                Delete =              0x00010000,
                ReadControl =         0x00020000,
                WriteDac =            0x00040000,
                WriteOwner =          0x00080000
            }

            // I have no clue why this class isn't defined in .NET. Psh
            public class ServiceSecurity : ObjectSecurity<ServiceFlags>
	        {
                public ServiceSecurity() : base(false, ResourceType.Service)
		        {
		        }
            }
        }
        '@ -ReferencedAssemblies ([System.Security.AccessControl.ResourceType].Assembly.Location)
        #>

        # Helper function code used supply ACL information Get-CSService when Get-CSService -IncludeAcl is used.
        # The pure reflection version of the above C# code:
        function Local:Get-ServiceSecurityType {
            [OutputType('CimSweep.ServiceSecurity')]
            param ()

            $ServiceSecurityType = 'CimSweep.ServiceSecurity' -as [Type]

            if (-not $ServiceSecurityType) {
                $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null)
                $DynamicAssembly = New-Object Reflection.AssemblyName('CimSweepAssembly')
                $AssemblyBuilder = $AppDomain.DefineDynamicAssembly($DynamicAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('CimSweepModule', $false)

                $EnumTypeAttributes = [Reflection.TypeAttributes]::Public
                $EnumBuilder = $ModuleBuilder.DefineEnum('CimSweep.ServiceFlags', $EnumTypeAttributes, [Int])
                $null = $EnumBuilder.DefineLiteral('QueryConfig', 0x00000001)
                $null = $EnumBuilder.DefineLiteral('ChangeConfig', 0x00000002)
                $null = $EnumBuilder.DefineLiteral('QueryStatus', 0x00000004)
                $null = $EnumBuilder.DefineLiteral('EnumerateDependents', 0x00000008)
                $null = $EnumBuilder.DefineLiteral('Start', 0x00000010)
                $null = $EnumBuilder.DefineLiteral('Stop', 0x00000020)
                $null = $EnumBuilder.DefineLiteral('PauseContinue', 0x00000040)
                $null = $EnumBuilder.DefineLiteral('Interrogate', 0x00000080)
                $null = $EnumBuilder.DefineLiteral('UserDefinedControl', 0x00000100)
                $null = $EnumBuilder.DefineLiteral('AllAccess', 0x000F01FF)
                $null = $EnumBuilder.DefineLiteral('Delete', 0x00010000)
                $null = $EnumBuilder.DefineLiteral('ReadControl', 0x00020000)
                $null = $EnumBuilder.DefineLiteral('WriteDac', 0x00040000)
                $null = $EnumBuilder.DefineLiteral('WriteOwner', 0x00080000)

                $FlagsConstructor = [FlagsAttribute].GetConstructor([Type[]] @())
                $FlagsAttribute = New-Object Reflection.Emit.CustomAttributeBuilder -ArgumentList $FlagsConstructor, ([Object[]] @())

                # Reflection version of applying [Flags] to the enum
                $EnumBuilder.SetCustomAttribute($FlagsAttribute)

                $EnumType = $EnumBuilder.CreateType()

                $BaseType = [Security.AccessControl.ObjectSecurity`1].MakeGenericType([Type[]] @($EnumType))
                $TypeAttributes = [Reflection.TypeAttributes] 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit'

                $TypeBuilder = $ModuleBuilder.DefineType('CimSweep.ServiceSecurity', $TypeAttributes, $BaseType)

                $MethodAttributes = [Reflection.MethodAttributes] 'PrivateScope, Public, HideBySig, SpecialName, RTSpecialName'
                $CallingConvention = [Reflection.CallingConventions] 'Standard, HasThis'
                $ConstructorBuilder = $TypeBuilder.DefineConstructor($MethodAttributes, $CallingConvention, [Type[]] @())
                $ILGen = $ConstructorBuilder.GetILGenerator()

                # I got this by building the above C# then disassembling it. When dealing with implementing
                # methods (in this case, a constructor), you only get to assemble CIL opcodes. No compilation. :(
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_0)
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_2)
                $ILGen.Emit([Reflection.Emit.OpCodes]::Call, $BaseType.GetConstructor([Reflection.BindingFlags] 'NonPublic, Instance', $null, [Type[]] @([Boolean], [Security.AccessControl.ResourceType]), $null))
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ret)

                $ServiceSecurityType = $TypeBuilder.CreateType()
            }

            $ServiceSecurityType
        }

        $ServiceSecurityType = Get-ServiceSecurityType
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Service sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $FilterComponents = New-Object 'Collections.ObjectModel.Collection`1[System.String]'

            $ServiceEntryArgs = @{}

            if ($PSBoundParameters['Name']) { $FilterComponents.Add("Name LIKE '%$Name%'") }
            if ($PSBoundParameters['DisplayName']) { $FilterComponents.Add("DisplayName LIKE '%$DisplayName%'") }
            if ($PSBoundParameters['State']) { $FilterComponents.Add("State = '$State'") }
            if ($PSBoundParameters['StartMode']) { $FilterComponents.Add("StartMode = '$StartMode'") }
            if ($PSBoundParameters['ServiceType']) { $FilterComponents.Add("ServiceType = '$ServiceType'") }
            if ($PSBoundParameters['PathName']) { $FilterComponents.Add("PathName LIKE '%$PathName%'") }
            if ($PSBoundParameters['Description']) { $FilterComponents.Add("Description LIKE '%$Description%'") }

            if ($FilterComponents.Count) {
                $Filter = $FilterComponents -join ' AND '
                $ServiceEntryArgs['Filter'] = $Filter
            }

            $ClassName = 'Win32_BaseService'
            if ($UserModeServices -and (-not $Drivers)) { $ClassName = 'Win32_Service' }
            if ($Drivers -and (-not $UserModeServices)) { $ClassName = 'Win32_SystemDriver' }

            Get-CimInstance -ClassName $ClassName @CommonArgs @ServiceEntryArgs @PropertyList @Timeout | ForEach-Object {
                $CurrentService = $_

                $IsWin32Service = $CurrentService.PSTypeNames -contains 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Service'

                if ($IncludeAcl) {
                    $ServiceSd = $null

                    if ($IsWin32Service) {
                        $GetSDResult = Invoke-CimMethod -InputObject $CurrentService -MethodName GetSecurityDescriptor @CommonArgs

                        if ($GetSDResult.ReturnValue -eq 0) {
                            $Win32SDToBinarySDArgs = @{
                                ClassName = 'Win32_SecurityDescriptorHelper'
                                MethodName = 'Win32SDToBinarySD'
                                Arguments = @{
                                    Descriptor = $GetSDResult.Descriptor
                                }
                            }

                            # Convert the WMI security descriptor to a raw byte array.
                            $ConversionResult = Invoke-CimMethod @Win32SDToBinarySDArgs

                            if ($ConversionResult.ReturnValue -eq 0) {
                                # Convert to a proper, fully parsed .NET class (using the ServiceSecurity class created with reflection above).
                                $ServiceSD = [Activator]::CreateInstance($ServiceSecurityType)
                                $ServiceSD.SetSecurityDescriptorBinaryForm($ConversionResult.BinarySD, 'All')
                            }
                        }

                        if ($null -eq $ServiceSd) {
                            Write-Warning "[$ComputerName] Unable to obtain service ACL for: $($_.DisplayName) ($($_.Name))"
                        }
                    }

                    Add-Member -InputObject $CurrentService -NotePropertyName ACL -NotePropertyValue $ServiceSd
                }

                if ($IncludeFileInfo) {
                    $FileInfo = $null

                    $RootServicePath = "SYSTEM\CurrentControlSet\Services\$($CurrentService.Name)"

                    $ServicePath = $null

                    if ($IsWin32Service) {
                        $ServicePath = (Get-CSRegistryValue -Hive HKLM -SubKey "$RootServicePath\Parameters" -ValueName ServiceDll @CommonArgs).ValueContent

                        if (-not $ServicePath) {
                            $ServicePath = (Get-CSRegistryValue -Hive HKLM -SubKey $RootServicePath -ValueName ServiceDll @CommonArgs).ValueContent
                        }

                        if (-not $ServicePath) {
                            $ServicePath = (Get-CSRegistryValue -Hive HKLM -SubKey $RootServicePath -ValueName ImagePath @CommonArgs).ValueContent
                        }
                    } else {
                        $ServicePath = $CurrentService.PathName
                    }

                    if (-not $ServicePath) {
                        Write-Error "[$ComputerName] Unable to obtain path for the following service: $($CurrentService.Name)"
                    } else {
                        $OriginalPath = $ServicePath
                        $NormalizedPath = $null

                        if ($IsWin32Service) {
                            if ($OriginalPath -match '(?<ServicePath>[a-z]:\\.+?(\.exe|\.dll))') {
                                $NormalizedPath = $Matches.ServicePath
                            }
                        } else {
                            # Normalize a driver image path
                            if ($OriginalPath.StartsWith('\??\')) {
                                $NormalizedPath = $OriginalPath.Substring(4)
                            } else {
                                $NormalizedPath = $OriginalPath
                            }
                        }
                        
                        if ($null -eq $NormalizedPath) {
                            Write-Error "[$ComputerName] Unable to normalize path for the following service: $($CurrentService.Name). Path obtained: $OriginalPath. Please submit an issue containing the service path so that the regular expression can be improved."
                        }

                        # Splitting these up for use by Get-CSDirectoryListing
                        $Directory = Split-Path -Path $NormalizedPath -Parent
                        $File = Split-Path -Path $NormalizedPath -Leaf

                        $FileInfo = Get-CSDirectoryListing -DirectoryPath $Directory -FileName $File -IncludeAcl @CommonArgs

                        if ($null -eq $FileInfo) {
                            Write-Error "[$ComputerName] Unable to obtain file information for the following service: $($CurrentService.Name). Path obtained: $NormalizedPath. It is likely that the file does not exist."
                        }
                    }

                    Add-Member -InputObject $CurrentService -NotePropertyName FileInfo -NotePropertyValue $FileInfo
                }

                $CurrentService
            }
        }
    }
}

function Get-CSProcess {
<#
.SYNOPSIS

Gets the processes that are running on the local computer or a remote computer.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

The Get-CSProcess cmdlet gets the processes on a local or remote computer.

.PARAMETER Name

Specifies one or more processes by process name.

.PARAMETER ProcessID

Specifies one or more processes by process ID (PID).

.PARAMETER ParentProcessId

Specifies one or more processes by parent process ID (PPID).

.PARAMETER CommandLine

Specifies the command line used to start a specific process, if applicable.

.PARAMETER ExecutablePath

Specifies the path to the executable file of the process.

.PARAMETER LimitOutput

Specifies that an explicit list of Win32_Process properties should be returned. This can significantly reduce the time it takes to sweep across many systems is only a subset of properties are desired.

.PARAMETER Property

Specifies the desired properties to retrieve from Win32_Process instances. The following properties are returned when limited output is desired: ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSProcess

.EXAMPLE

Get-CSProcess -Name chrome

.EXAMPLE

Get-CSProcess -ProcessID 4 -CimSession $CimSession

.EXAMPLE

Get-CSProcess -LimitOutput

Retrieves Win32_Process instances with only the following properties: ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

.EXAMPLE

Get-CSProcess -LimitOutput -Property Name, ProcessId

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process

Outputs Win32_Process instances.
#>

    [CmdletBinding(DefaultParameterSetName='DefaultOutput')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process')]
    param(
        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Alias('Id')]
        [UInt32]
        $ProcessID,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [UInt32]
        $ParentProcessId,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CommandLine,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ExecutablePath,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Switch]
        $LimitOutput,

        [Parameter(ParameterSetName='RestrictOutput')]
        [String[]]
        [ValidateSet(
            'Caption',
            'CommandLine',
            'CreationClassName',
            'CreationDate',
            'CSCreationClassName',
            'CSName',
            'Description',
            'ExecutablePath',
            'ExecutionState',
            'Handle',
            'HandleCount',
            'InstallDate',
            'KernelModeTime',
            'MaximumWorkingSetSize',
            'MinimumWorkingSetSize',
            'Name',
            'OSCreationClassName',
            'OSName',
            'OtherOperationCount',
            'OtherTransferCount',
            'PageFaults',
            'PageFileUsage',
            'ParentProcessId',
            'PeakPageFileUsage',
            'PeakVirtualSize',
            'PeakWorkingSetSize',
            'Priority',
            'PrivatePageCount',
            'ProcessId',
            'QuotaNonPagedPoolUsage',
            'QuotaPagedPoolUsage',
            'QuotaPeakNonPagedPoolUsage',
            'QuotaPeakPagedPoolUsage',
            'ReadOperationCount',
            'ReadTransferCount',
            'SessionId',
            'Status',
            'TerminationDate',
            'ThreadCount',
            'UserModeTime',
            'VirtualSize',
            'WindowsVersion',
            'WorkingSetSize',
            'WriteOperationCount',
            'WriteTransferCount')]
        $Property = @('ProcessId', 'ParentProcessId', 'Name', 'ExecutablePath', 'CommandLine'),

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Switch]
        $NoProgressBar,

        [Parameter(ParameterSetName='DefaultOutput')]
        [Parameter(ParameterSetName='RestrictOutput')]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
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

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        $PropertyList = @{}
        if ($PSBoundParameters['LimitOutput'] -or $PSBoundParameters['Property']) { $PropertyList['Property'] = $Property }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Process sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $FilterComponents = New-Object 'Collections.ObjectModel.Collection`1[System.String]'

            $ProcessEntryArgs = @{}

            if ($PSBoundParameters['Name']) { $FilterComponents.Add("Name LIKE '%$Name%'") }
            if ($PSBoundParameters['ProcessID']) { $FilterComponents.Add("ProcessID = $ProcessID") }
            if ($PSBoundParameters['ParentProcessID']) { $FilterComponents.Add("ParentProcessID = $ParentProcessID") }
            if ($PSBoundParameters['CommandLine']) { $FilterComponents.Add("CommandLine LIKE '%$CommandLine%'") }
            if ($PSBoundParameters['ExecutablePath']) { $FilterComponents.Add("ExecutablePath LIKE '%$ExecutablePath%'") }

            if ($FilterComponents.Count) {
                $Filter = $FilterComponents -join ' AND '
                $ProcessEntryArgs['Filter'] = $Filter
            }

            Get-CimInstance -ClassName Win32_Process @CommonArgs @ProcessEntryArgs @PropertyList @Timeout
        }
    }
}

function Get-CSEnvironmentVariable {
<#
.SYNOPSIS

Lists all system and user-specific environment variables.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSEnvironmentVariable returns all system and user environment variables. Get-CSEnvironmentVariable doesn't rely upon the Win32_Environment class as it doesn't return all environment variables.

.PARAMETER VariableName

Specifies a specific environment variable name. If no environment variable name is specified, all variables are returned.

.PARAMETER SystemVariable

Specifies that only system-scope environment variables should be returned.

.PARAMETER UserVariable

Specifies that only user-scope environment variables should be returned.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSEnvironmentVariable

Lists all local user-scope and system-scope environment variables.

.EXAMPLE

Get-CSEnvironmentVariable -SystemVariable

Lists only local, system-scope environment variables.

.EXAMPLE

Get-CSEnvironmentVariable -VariableName Path

Lists all local user-scope and system-scope "Path" environment variables.

.EXAMPLE

Get-CSEnvironmentVariable -CimSession $CimSession

Lists all user-scope and system-scope environment variables from a remote CIM session.

.OUTPUTS

CimSweep.EnvironmentVariable

Outputs objects consisting of the name, value, and scope (user vs. system) of an environment variable.
#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType('CimSweep.EnvironmentVariable')]
    param(
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
        [Alias('Name')]
        [String]
        [ValidateNotNullOrEmpty()]
        $VariableName,

        [Parameter(Mandatory = $True, ParameterSetName = 'System')]
        [Alias('System')]
        [Switch]
        $SystemVariable,

        [Parameter(Mandatory = $True, ParameterSetName = 'User')]
        [Alias('User')]
        [Switch]
        $UserVariable,

        [Switch]
        $NoProgressBar,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
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

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        $SystemEnvPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

        $ObjectType = 'CimSweep.EnvironmentVariable'
        $DefaultPropertyNames = 'Name', 'User', 'VariableValue'
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - environment variable sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            # Performance enhancements are realized when specifying a specific environment variable name.
            if ($PSBoundParameters['VariableName']) {
                if (($PSCmdlet.ParameterSetName -eq 'System') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    $Result = Get-CSRegistryValue -Hive HKLM -SubKey $SystemEnvPath -ValueName $VariableName -ValueType REG_SZ @CommonArgs @Timeout

                    if ($Result.ValueContent) {
                        $ObjectProperties = [Ordered] @{
                            PSTypeName = $ObjectType
                            Name = $Result.ValueName
                            User = '<SYSTEM>'
                            VariableValue = $Result.ValueContent
                        }

                        $DefaultProperties = $DefaultPropertyNames -as [Type] 'Collections.Generic.List[String]'

                        if ($Result.PSComputerName) {
                            $ObjectProperties['PSComputerName'] = $Result.PSComputerName
                            $DefaultProperties.Add('PSComputerName')
                        } else {
                            $ObjectProperties['PSComputerName'] = $null
                        }

                        if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                        $EnvVarInfo = [PSCustomObject] $ObjectProperties

                        Set-DefaultDisplayProperty -InputObject $EnvVarInfo -PropertyNames $DefaultProperties

                        $EnvVarInfo
                    }
                }

                if (($PSCmdlet.ParameterSetName -eq 'User') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    # Get the SIDS for each user in the registry
                    $HKUSIDs = Get-HKUSID @CommonArgs @Timeout

                    # Iterate over each local user hive
                    foreach ($SID in $HKUSIDs) {
                        $Result = Get-CSRegistryValue -Hive HKU -SubKey "$SID\Volatile Environment" -ValueName $VariableName -ValueType REG_SZ @CommonArgs @Timeout

                        if ($Result.ValueContent) {
                            $ObjectProperties = [Ordered] @{
                                PSTypeName = $ObjectType
                                Name = $Result.ValueName
                                User = $SID
                                VariableValue = $Result.ValueContent
                            }

                            $DefaultProperties = $DefaultPropertyNames -as [Type] 'Collections.Generic.List[String]'

                            if ($Result.PSComputerName) {
                                $ObjectProperties['PSComputerName'] = $Result.PSComputerName
                                $DefaultProperties.Add('PSComputerName')
                            } else {
                                $ObjectProperties['PSComputerName'] = $null
                            }

                            if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                            $EnvVarInfo = [PSCustomObject] $ObjectProperties

                            Set-DefaultDisplayProperty -InputObject $EnvVarInfo -PropertyNames $DefaultProperties

                            $EnvVarInfo
                        } else {
                            $Result = Get-CSRegistryValue -Hive HKU -SubKey "$SID\Environment" -ValueName $VariableName -ValueType REG_SZ @CommonArgs @Timeout

                            if ($Result.ValueContent) {
                                $ObjectProperties = [Ordered] @{
                                    PSTypeName = $ObjectType
                                    Name = $Result.ValueName
                                    User = $SID
                                    VariableValue = $Result.ValueContent
                                }

                                $DefaultProperties = $DefaultPropertyNames -as [Type] 'Collections.Generic.List[String]'

                                if ($Result.PSComputerName) {
                                    $ObjectProperties['PSComputerName'] = $Result.PSComputerName
                                    $DefaultProperties.Add('PSComputerName')
                                } else {
                                    $ObjectProperties['PSComputerName'] = $null
                                }

                                if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                                $EnvVarInfo = [PSCustomObject] $ObjectProperties

                                Set-DefaultDisplayProperty -InputObject $EnvVarInfo -PropertyNames $DefaultProperties

                                $EnvVarInfo
                            }
                        }
                    }
                }
            } else { # Retrieve all environment variables
                if (($PSCmdlet.ParameterSetName -eq 'System') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    Get-CSRegistryValue -Hive HKLM -SubKey $SystemEnvPath @CommonArgs @Timeout | ForEach-Object {
                        $ObjectProperties = [Ordered] @{
                            PSTypeName = $ObjectType
                            Name = $_.ValueName
                            User = '<SYSTEM>'
                            VariableValue = $_.ValueContent
                        }

                        $DefaultProperties = $DefaultPropertyNames -as [Type] 'Collections.Generic.List[String]'

                        if ($_.PSComputerName) {
                            $ObjectProperties['PSComputerName'] = $_.PSComputerName
                            $DefaultProperties.Add('PSComputerName')
                        } else {
                            $ObjectProperties['PSComputerName'] = $null
                        }

                        if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                        $EnvVarInfo = [PSCustomObject] $ObjectProperties

                        Set-DefaultDisplayProperty -InputObject $EnvVarInfo -PropertyNames $DefaultProperties

                        $EnvVarInfo
                    }
                }

                if (($PSCmdlet.ParameterSetName -eq 'User') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    # Get the SIDS for each user in the registry
                    $HKUSIDs = Get-HKUSID @CommonArgs @Timeout

                    # Iterate over each local user hive
                    foreach ($SID in $HKUSIDs) {
                        Get-CSRegistryValue -Hive HKU -SubKey "$SID\Volatile Environment" @CommonArgs @Timeout | ForEach-Object {
                            $ObjectProperties = [Ordered] @{
                                PSTypeName = $ObjectType
                                Name = $_.ValueName
                                User = $SID
                                VariableValue = $_.ValueContent
                            }

                            $DefaultProperties = $DefaultPropertyNames -as [Type] 'Collections.Generic.List[String]'

                            if ($_.PSComputerName) {
                                $ObjectProperties['PSComputerName'] = $_.PSComputerName
                                $DefaultProperties.Add('PSComputerName')
                            } else {
                                $ObjectProperties['PSComputerName'] = $null
                            }

                            if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                            $EnvVarInfo = [PSCustomObject] $ObjectProperties

                            Set-DefaultDisplayProperty -InputObject $EnvVarInfo -PropertyNames $DefaultProperties

                            $EnvVarInfo
                        }

                        Get-CSRegistryValue -Hive HKU -SubKey "$SID\Environment" @CommonArgs @Timeout | ForEach-Object {
                            $ObjectProperties = [Ordered] @{
                                PSTypeName = $ObjectType
                                Name = $_.ValueName
                                User = $SID
                                VariableValue = $_.ValueContent
                            }

                            $DefaultProperties = $DefaultPropertyNames -as [Type] 'Collections.Generic.List[String]'

                            if ($_.PSComputerName) {
                                $ObjectProperties['PSComputerName'] = $_.PSComputerName
                                $DefaultProperties.Add('PSComputerName')
                            } else {
                                $ObjectProperties['PSComputerName'] = $null
                            }

                            if ($Session.Id) { $ObjectProperties['CimSession'] = $Session }

                            $EnvVarInfo = [PSCustomObject] $ObjectProperties

                            Set-DefaultDisplayProperty -InputObject $EnvVarInfo -PropertyNames $DefaultProperties

                            $EnvVarInfo
                        }
                    }
                }
            }
        }
    }
}

function Get-CSWmiNamespace {
<#
.SYNOPSIS

Returns a list of WMI namespaces present within the specified namespace.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSWmiNamespace returns all child namespaces for the specified WMI namespace and optionally includes the ACL for each namespace. An attacker can use WMI namespaces as a C2 mechanism as well as backdoor a system by modifying ACLs.

.PARAMETER Namespace

Specifies the WMI repository namespace in which to list sub-namespaces. Get-WmiNamespace defaults to the ROOT namespace.

.PARAMETER Recurse

Specifies that namespaces should be recursed upon starting from the specified root namespace.

.PARAMETER IncludeAcl

Specifies that the ACL for the namespace should be returned. -IncludeAcl will append an ACL property to each returned object. The ACL property is a CimSweep.WmiNamespaceSecurity object.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSWmiNamespace

.EXAMPLE

Get-CSWmiNamespace -Recurce

.EXAMPLE

Get-CSWmiNamespace -Namespace ROOT/CIMV2

.EXAMPLE

Get-CSWmiNamespace -Namespace ROOT/CIMV2 -Recurse

.EXAMPLE

Get-CSWmiNamespace -Recurse -IncludeAcl -CimSession $CimSession

.EXAMPLE

Get-CSWmiNamespace -Recurse -IncludeAcl

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#root/__NAMESPACE
#>

    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#root/__NAMESPACE')]
    Param (
        [String]
        [ValidateNotNullOrEmpty()]
        $Namespace = 'ROOT',

        [Switch]
        $Recurse,

        [Switch]
        $IncludeAcl,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        $RecurseArg = @{}
        if ($Recurse) { $RecurseArg['Recurse'] = $True }

        $IncludeAclArg = @{}
        if ($IncludeAcl) { $IncludeAclArg['IncludeAcl'] = $True }

        function Local:Get-NamespaceSecurityType {
            [OutputType('CimSweep.WmiNamespaceSecurity')]
            param ()

            $NamespaceSecurityType = 'CimSweep.WmiNamespaceSecurity' -as [Type]

            if (-not $NamespaceSecurityType) {
                $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null)
                $DynamicAssembly = New-Object Reflection.AssemblyName('CimSweepAssembly')
                $AssemblyBuilder = $AppDomain.DefineDynamicAssembly($DynamicAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('CimSweepModule', $false)

                $EnumTypeAttributes = [Reflection.TypeAttributes]::Public
                $EnumBuilder = $ModuleBuilder.DefineEnum('CimSweep.NamespaceFlags', $EnumTypeAttributes, [Int])
                $null = $EnumBuilder.DefineLiteral('Enable', 0x00000001)        # Grants the security principal read permissions.
                $null = $EnumBuilder.DefineLiteral('MethodExecute', 0x00000002) # Grants the security principal to execute methods.
                $null = $EnumBuilder.DefineLiteral('FullWrite', 0x00000004)     # Grants the security principal to write to classes and instances.
                $null = $EnumBuilder.DefineLiteral('PartialWrite', 0x00000008)  # Grants the security principal to update or delete CIM instances that are static.
                $null = $EnumBuilder.DefineLiteral('WriteProvider', 0x00000010) # Grants the security principal to update or delete CIM instances that are dynamic.
                $null = $EnumBuilder.DefineLiteral('RemoteEnable', 0x00000020)  # Grants the security principal to remotely access the server.
                $null = $EnumBuilder.DefineLiteral('Subscribe', 0x00000040)     # Specifies that a consumer can subscribe to the events delivered to a sink. Used in IWbemEventSink::SetSinkSecurity
                $null = $EnumBuilder.DefineLiteral('Publish', 0x00000080)       # Specifies that the account can publish events to the instance of __EventFilter that defines the event filter for a permanent consumer.
                $null = $EnumBuilder.DefineLiteral('ReadControl', 0x00020000)   # Allows the security principal to read the security descriptor of CIM namespace.
                $null = $EnumBuilder.DefineLiteral('WriteDac', 0x00040000)      # Allows the security principal to modify the security descriptor of CIM namespace.

                $FlagsConstructor = [FlagsAttribute].GetConstructor([Type[]] @())
                $FlagsAttribute = New-Object Reflection.Emit.CustomAttributeBuilder -ArgumentList $FlagsConstructor, ([Object[]] @())

                # Reflection version of applying [Flags] to the enum
                $EnumBuilder.SetCustomAttribute($FlagsAttribute)

                $EnumType = $EnumBuilder.CreateType()

                $BaseType = [Security.AccessControl.ObjectSecurity`1].MakeGenericType([Type[]] @($EnumType))
                $TypeAttributes = [Reflection.TypeAttributes] 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit'

                $TypeBuilder = $ModuleBuilder.DefineType('CimSweep.WmiNamespaceSecurity', $TypeAttributes, $BaseType)

                $MethodAttributes = [Reflection.MethodAttributes] 'PrivateScope, Public, HideBySig, SpecialName, RTSpecialName'
                $CallingConvention = [Reflection.CallingConventions] 'Standard, HasThis'
                $ConstructorBuilder = $TypeBuilder.DefineConstructor($MethodAttributes, $CallingConvention, [Type[]] @())
                $ILGen = $ConstructorBuilder.GetILGenerator()

                # I got this by building the above C# then disassembling it. When dealing with implementing
                # methods (in this case, a constructor), you only get to assemble CIL opcodes. No compilation. :(
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_0)
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ldc_I4_2)
                $ILGen.Emit([Reflection.Emit.OpCodes]::Call, $BaseType.GetConstructor([Reflection.BindingFlags] 'NonPublic, Instance', $null, [Type[]] @([Boolean], [Security.AccessControl.ResourceType]), $null))
                $ILGen.Emit([Reflection.Emit.OpCodes]::Ret)

                $NamespaceSecurityType = $TypeBuilder.CreateType()
            }

            $NamespaceSecurityType
        }

        $NamespaceSecurityType = Get-NamespaceSecurityType
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            $DefaultProperties = 'FullyQualifiedNamespace' -as [Type] 'Collections.Generic.List[String]'

            $CommonArgs = @{}
            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $TrimmedNamespace = $Namespace.Trim([Char[]] @('/', '\'))

            Get-CimInstance -Namespace $TrimmedNamespace -ClassName __NAMESPACE @CommonArgs | ForEach-Object {
                $FullyQualifiedNamespace = '{0}/{1}' -f $TrimmedNamespace, $_.Name

                if ($IncludeAcl) {
                    $NamespaceSD = $null

                    $GetSDArgs = @{
                        Namespace = $FullyQualifiedNamespace
                        ClassName = '__SystemSecurity'
                        MethodName = 'GetSecurityDescriptor'
                    }

                    $GetSDResult = Invoke-CimMethod @GetSDArgs @CommonArgs @Timeout -ErrorAction SilentlyContinue

                    if ($GetSDResult.ReturnValue -eq 0) {
                        $Win32SDToBinarySDArgs = @{
                            ClassName = 'Win32_SecurityDescriptorHelper'
                            MethodName = 'Win32SDToBinarySD'
                            Arguments = @{
                                Descriptor = $GetSDResult.Descriptor
                            }
                        }

                        $ConversionResult = Invoke-CimMethod @Win32SDToBinarySDArgs @CommonArgs @Timeout

                        if ($ConversionResult.ReturnValue -eq 0) {
                            $NamespaceSD = [Activator]::CreateInstance($NamespaceSecurityType)
                            $NamespaceSD.SetSecurityDescriptorBinaryForm($ConversionResult.BinarySD, 'All')
                        }
                    }

                    if ($null -eq $NamespaceSD) {
                        Write-Warning "[$ComputerName] Unable to obtain WMI namespace ACL for: $FullyQualifiedNamespace"
                    }

                    Add-Member -InputObject $_ -NotePropertyName ACL -NotePropertyValue $NamespaceSD
                }

                Add-Member -InputObject $_ -NotePropertyName FullyQualifiedNamespace -NotePropertyValue $FullyQualifiedNamespace
                Set-DefaultDisplayProperty -InputObject $_ -PropertyNames $DefaultProperties

                $_

                if ($Recurse) {
                    Get-CSWmiNamespace -Namespace $FullyQualifiedNamespace @CommonArgs @RecurseArg @IncludeAclArg @Timeout
                }
            }
        }
    }
}
