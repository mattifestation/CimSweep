filter Get-CSRegistryKey {
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

.PARAMETER Path

Specifies the desired registry hive and path in the standard PSDrive format. e.g. HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion. This parameter enables local tab expansion of key paths. Note: the tab expansion expands based on local registry paths not remote paths.

.PARAMETER Recurse

Gets the registry keys in the specified subkey as well as all child keys.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSRegistryKey -Hive HKLM

.EXAMPLE

Get-CSRegistryKey -Hive HKCU -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\

.EXAMPLE

Get-CSRegistryKey -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\

.EXAMPLE

Get-CSRegistryKey -Hive HKLM -Recurse -CimSession $CimSession

Lists all registry keys on a remote system in the HKLM hive.

.EXAMPLE

Get-CSRegistryKey -Hive HKLM | Get-CSRegistryKey

Lists all 2nd level registry keys starting from the root of HKLM.

.INPUTS

PSObject

Accepts output from Get-CSRegistryKey. This enables recursion.

Microsoft.Management.Infrastructure.CimSession

Get-CSRegistryKey accepts established CIM sessions over the pipeline.

.OUTPUTS

PSObject

Outputs a list of custom objects representing registry keys.

.NOTES

It is not recommended to recursively list all registry keys from most parent keys as obtaining the results can be time consuming. It is recommended to use Get-CSRegistryKey with targeted subkey paths.

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        [ValidateSet('HKLM', 'HKCU', 'HKU', 'HKCR', 'HKCC')]
        $Hive,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        $SubKey = '',

        [Parameter(Mandatory = $True, ParameterSetName = 'PSDrivePath')]
        [String]
        [ValidatePattern('^(HKLM|HKCU|HKU|HKCR|HKCC):\\.*$')]
        $Path,

        [Switch]
        $Recurse,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    # Note: -Path is not guaranteed to expand if the PSDrive doesn't exist. e.g. HKCR doesn't exist by default.
    # The point of -Path is to speed up your workflow.
    if ($PSBoundParameters['Path']) {
        $Result = $Path -match '^(?<Hive>HKLM|HKCU|HKU|HKCR|HKCC):\\(?<SubKey>.*)$'

        $Hive = $Matches.Hive
        $SubKey = $Matches.SubKey
    }

    $TrimmedKey = $SubKey.Trim('\')

    switch ($Hive) {
        'HKLM' { $HiveVal = [UInt32] 2147483650 }
        'HKCU' { $HiveVal = [UInt32] 2147483649 }
        'HKU'  { $HiveVal = [UInt32] 2147483651 }
        'HKCR' { $HiveVal = [UInt32] 2147483648 }
        'HKCC' { $HiveVal = [UInt32] 2147483653 }
    }

    $CimMethodArgs = @{
        ClassName = 'StdRegProv'
        Namespace = 'root/default'
        MethodName = 'EnumKey'
    }

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) {
        $CimMethodArgs['CimSession'] = $CimSession
        $CommonArgs['CimSession'] = $CimSession
    }

    $RegistryMethodArgs = @{
        hDefKey = $HiveVal
        sSubKeyName = $TrimmedKey
    }

    $CimMethodArgs['Arguments'] = $RegistryMethodArgs

    $Result = Invoke-CimMethod @CimMethodArgs
    
    if ($Result.sNames) {
        foreach ($KeyName in $Result.sNames) {
            $ObjectProperties = [Ordered] @{
                Hive = $Hive
                SubKey = "$TrimmedKey\$KeyName".Trim('\')
                CimSession = $CimSession
            }

            $KeyObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Add-Member -InputObject $KeyObject -MemberType NoteProperty -Name PSComputerName -Value $Result.PSComputerName
            $KeyObject.PSObject.TypeNames.Insert(0, 'CimSweep.RegistryKey')

            $KeyObject

            if ($PSBoundParameters['Recurse']) {
                Get-CSRegistryKey -Recurse @ObjectProperties
            }
        }
    }
}

filter Get-CSRegistryValue {
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

.PARAMETER Path

Specifies the desired registry hive and path in the standard PSDrive format. e.g. HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion. This parameter enables local tab expansion of key paths. Note: the tab expansion expands based on local registry paths not remote paths.

.PARAMETER ValueName

Specifies the registry value name.

.PARAMETER ValueNameOnly

Specifies that the content of the registry value should not be received. This switch can be used to speed up Get-CSRegistryValue and reduce network bandwidth when the content is not desired.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSRegistryValue -Hive HKCU -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Lists all value names present in the current user Run key.

.EXAMPLE

Get-CSRegistryKey -Path HKLM:\SYSTEM\CurrentControlSet\Services\ -CimSession $CimSession | Get-CSRegistryValue

Get the value names and types for all services on a remote system.

.EXAMPLE

Get-CSRegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

.EXAMPLE

Get-CSRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -ValueName CurrentVersion

.INPUTS

PSObject

Accepts output from Get-CSRegistryKey. This allows you to list all registry value names for all keys contained within a parent key.

Microsoft.Management.Infrastructure.CimSession

Get-CSRegistryValue accepts established CIM sessions over the pipeline.

.OUTPUTS

PSObject

Outputs a list of custom objects representing registry value names, their respective types, and content for a specified key.

#>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        [ValidateSet('HKLM', 'HKCU', 'HKU', 'HKCR', 'HKCC')]
        $Hive,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        $SubKey = '',

        [Parameter(Mandatory = $True, ParameterSetName = 'PSDrivePath')]
        [String]
        [ValidatePattern('^(HKLM|HKCU|HKU|HKCR|HKCC):\\.*$')]
        $Path,

        [Parameter(ValueFromPipelineByPropertyName = $True, ParameterSetName = 'ExplicitPath')]
        [String]
        $ValueName,

        [Switch]
        $ValueNameOnly,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    # Note: -Path is not guaranteed to expand if the PSDrive doesn't exist. e.g. HKCR doesn't exist by default.
    # The point of -Path is to speed up your workflow.
    if ($PSBoundParameters['Path']) {
        $Result = $Path -match '^(?<Hive>HKLM|HKCU|HKU|HKCR|HKCC):\\(?<SubKey>.*)$'

        $Hive = $Matches.Hive
        $SubKey = $Matches.SubKey
    }

    switch ($Hive) {
        'HKLM' { $HiveVal = [UInt32] 2147483650 }
        'HKCU' { $HiveVal = [UInt32] 2147483649 }
        'HKU'  { $HiveVal = [UInt32] 2147483651 }
        'HKCR' { $HiveVal = [UInt32] 2147483648 }
        'HKCC' { $HiveVal = [UInt32] 2147483653 }
    }

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

    $TrimmedKey = $SubKey.Trim('\')

    $CimMethodArgs = @{
        ClassName = 'StdRegProv'
        Namespace = 'root/default'
        MethodName = 'EnumValues'
    }

    if ($PSBoundParameters['CimSession']) { $CimMethodArgs['CimSession'] = $CimSession }

    $RegistryMethodArgs = @{
        hDefKey = $HiveVal
        sSubKeyName = $TrimmedKey
    }

    $CimMethodArgs['Arguments'] = $RegistryMethodArgs

    $Result = Invoke-CimMethod @CimMethodArgs

    if ($Result.ReturnValue -eq 0) {

        $Types = $Result.Types.ForEach({$Type[$_]})

        $ValueNames = $Result.sNames

        for ($i = 0; $i -lt $Result.Types.Length; $i++) {
            $ValueContent = $null

            $CimMethod2Args = @{
                ClassName = 'StdRegProv'
                Namespace = 'root/default'
            }

            if ($PSBoundParameters['CimSession']) { $CimMethod2Args['CimSession'] = $CimSession }

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
                    Write-Warning "$($Result.Types[$i]) is not a supported registry value type. Hive: $Hive. SubKey: $SubKey"
                    
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

            if (($PSBoundParameters['ValueName'] -and ($ValueName -eq $ValueNames[$i])) -or (-not $PSBoundParameters['ValueName'])) {
                $ValueContent = $null

                if (-not $PSBoundParameters['ValueNameOnly']) {
                    $Result2 = Invoke-CimMethod @CimMethod2Args

                    if ($Result2.ReturnValue -eq 0) {
                        $ValueContent = $Result2."$ReturnProp"
                    }
                }

                $ObjectProperties = [Ordered] @{
                    Hive = $Hive
                    SubKey = $TrimmedKey
                    ValueName = if ($ValueNames[$i]) { $ValueNames[$i] } else { '' }
                    Type = $Types[$i]
                    ValueContent = $ValueContent
                    PSComputerName = $Result.PSComputerName
                    CimSession = $CimSession
                }

                $ValueObject = New-Object -TypeName PSObject -Property $ObjectProperties
                $ValueObject.PSObject.TypeNames.Insert(0, 'CimSweep.RegistryValue')

                $ValueObject
            }
        }
    }
}

filter Get-HKUSID {
<#
.SYNOPSIS

Returns a hashtable mapping SIDs present in the HKU hive to account names.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-HKUSID is a helper function that returns user SIDs from the root of the HKU hive. Remotely querying HKU for each local user is ideal over querying HKCU.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.
#>

    [OutputType([Hashtable])]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    # Get a SID to username mapping
    $Accounts = Get-CimInstance -ClassName Win32_Account -Property SID, Name @CommonArgs

    # Get all user specific hives
    $AllUserHives = Get-CSRegistryKey -Hive HKU @CommonArgs
        
    $UserSidToName = @{}

    foreach ($Account in $Accounts) {
        if ($Account.SID -in $AllUserHives.SubKey) {
            $UserSidToName[($Account.SID)] = $Account.Name
        }
    }

    return $UserSidToName
}

filter Get-CSEventLog {
<#
.SYNOPSIS

Gets a list of event logs on the computer.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.NOTES

Get-CSEventLog is useful for determining which event log to filter off of in Get-CSEventLogEntry.

.INPUTS

PSObject

Accepts input from Get-CSEventLog.

Microsoft.Management.Infrastructure.CimSession

Get-CSEventLog accepts established CIM sessions over the pipeline.

.OUTPUTS

PSObject

Outptus a custom object that can be piped to Get-CSEventLog entry.
#>

    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    Get-CimInstance @CommonArgs -Query 'SELECT LogfileName FROM Win32_NTEventlogFile' | ForEach-Object {
        $Properties = [Ordered] @{
            LogName = $_.LogfileName
            PSComputerName = $_.PSComputerName
            CimSession = $CimSession
        }

        $EventLog = New-Object -TypeName PSObject -Property $Properties
        $EventLog.PSObject.TypeNames.Insert(0, 'CimSweep.EventLog')
        $EventLog
    }
}

filter Get-CSEventLogEntry {
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

.PARAMETER EventIdentifier

Gets only events with the specified event identifier.

.PARAMETER EntryType

Gets only events with the specified entry type. Valid values are Error, Information, FailureAudit, SuccessAudit, and Warning. The default is all events.

.PARAMETER After

Gets only the events that occur after the specified date and time. Enter a DateTime object, such as the one returned by the Get-Date cmdlet. Note: Datetimes are automatically converted to UTC.

.PARAMETER Before

Gets only the events that occur before the specified date and time. Enter a DateTime object, such as the one returned by the Get-Date cmdlet. Note: Datetimes are automatically converted to UTC.

.PARAMETER Message

Gets events that have the specified string in their messages. You can use this property to search for messages that contain certain words or phrases. Wildcards are permitted.

.PARAMETER Source

Gets events that were written to the log by the specified sources.

.PARAMETER UserName

Gets only the events that are associated with the specified user names.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSEventLogEntry

Returns every event log entry.

.EXAMPLE

Get-CSEventLogEntry -CimSession $CimSession -LogName Security -EventIdentifier 4624

Returns all successful logon events on the remote system.

.EXAMPLE

Get-CSEventLogEntry -CimSession $CimSession -EntryType FailureAudit

.INPUTS

PSObject

Accepts input from Get-CSEventLog.

Microsoft.Management.Infrastructure.CimSession

Get-CSEventLogEntry accepts established CIM sessions over the pipeline.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance

Outputs Win32_NtLogEvent instances.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $LogName,

        [UInt32]
        $EventIdentifier,

        [String]
        [ValidateSet('Error', 'Information', 'FailureAudit', 'SuccessAudit', 'Warning')]
        $EntryType,

        [DateTime]
        [ValidateNotNullOrEmpty()]
        $After,

        [DateTime]
        [ValidateNotNullOrEmpty()]
        $Before,

        [String]
        [ValidateNotNullOrEmpty()]
        $Message,

        [String]
        [ValidateNotNullOrEmpty()]
        $Source,

        [String]
        [ValidateNotNullOrEmpty()]
        $UserName,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

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
    if ($PSBoundParameters['EventIdentifier']) { $FilterComponents.Add("EventIdentifier=$EventIdentifier") }
    if ($PSBoundParameters['EntryType']) { $FilterComponents.Add("EventType=$($TypeMapping[$EntryType])") }
    if ($PSBoundParameters['Before']) { $FilterComponents.Add("TimeGenerated<'$($Before.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff+000'))'") }
    if ($PSBoundParameters['After']) { $FilterComponents.Add("TimeGenerated>'$($After.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff+000'))'") }
    if ($PSBoundParameters['Message']) { $FilterComponents.Add("Message LIKE '%$($Message)%'") }
    if ($PSBoundParameters['Source']) { $FilterComponents.Add("SourceName LIKE '%$Source%'") }
    if ($PSBoundParameters['UserName']) { $FilterComponents.Add("User LIKE '%$UserName%'") }

    if ($FilterComponents.Count) {
        $Filter = $FilterComponents -join ' AND '
        $EventLogEntryArgs['Filter'] = $Filter
    }

    Get-CimInstance @CommonArgs @EventLogEntryArgs -ClassName Win32_NTLogEvent
}

filter Get-CSMountedVolumeDriveLetter {
<#
.SYNOPSIS

Lists the mounted drive letters present. This is primarily used as a helper for Get-CSDirectoryListing when no parameters are provided.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSMountedVolumeDriveLetter accepts established CIM sessions over the pipeline.

.OUTPUTS

PSObject

Outputs a list of mounted drive letters.
#>

    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    $Result = Get-CimInstance @CommonArgs -Query 'SELECT DeviceID FROM Win32_LogicalDisk'

    foreach ($Volume in $Result) {
        if ($Volume.DeviceID) {
            $Properties = [Ordered] @{
                DriveLetter = $Volume.DeviceID[0]
                DirectoryPath = "$($Volume.DeviceID)\"
                PSComputerName = $Volume.PSComputerName
                CimSession = $CimSession
            }

            $DiskInfo = New-Object -TypeName PSObject -Property $Properties
            $DiskInfo.PSObject.TypeNames.Insert(0, 'CimSweep.DiskInfo')
            $DiskInfo
        }
    }
}

filter Get-CSDirectoryListing {
<#
.SYNOPSIS

Lists files and directories present in the specified directory.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSDirectoryListing performs a WMI/CIM-based file/directory listing of the specified directory.

.PARAMETER DirectoryPath

Specifies the directory.

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

.PARAMETER DirectoryOnly

Specifies that only directories should be listed.

.PARAMETER Recurse

Recurse on all child directories.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

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

$CimSession, $CimSession2 | Get-CSDirectoryListing -DirectoryPath C:\ -Extension exe, dll, sys -Recurse

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\Users -DirectoryOnly | Get-CSDirectoryListing -Extension exe, dll -Recurse

Lists all EXE and DLL files present in all user directories.

.EXAMPLE

Get-CSDirectoryListing -DirectoryPath C:\ -DirectoryOnly -Recurse

Lists all directories present in C:\.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSDirectoryListing accepts established CIM sessions over the pipeline.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance

Outputs a CIM_DataFile or Win32_Directory instance representing file or directory information.

.NOTES

Filter parameters in Get-CSDirectoryListing only apply to files, not directories.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    [CmdletBinding(DefaultParameterSetName = 'DirOnly')]
    param(
        [Parameter(ValueFromPipelineByPropertyName = $True, Mandatory = $True, Position = 0)]
        [Alias('Name')]
        [String]
        [ValidatePattern('^(?<ValidDriveLetter>[A-Za-z]:)(?<ValidPath>\\.*)$')]
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

        [Parameter(ParameterSetName = 'DirOnly')]
        [Switch]
        $DirectoryOnly,
        
        [Switch]
        $Recurse,

        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    # Normalize the directory path
    $TrimmedPath = $DirectoryPath.TrimEnd('\')

    # The validation regex guarantees that $Path[0] will contain a drive letter
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

    # Get all directories present in the specified folder
    Get-CimInstance @CommonArgs @DirArguments | ForEach-Object {
        $DirObject = $_
        $DirObject.PSObject.TypeNames.Insert(0, 'CimSweep.LogicalFile')

        # Append the CimSession instance. This enables piping Get-CSDirectoryListing to itself
        Add-Member -InputObject $DirObject -MemberType NoteProperty -Name CimSession -Value $CimSession

        # Output the directories present if file query arguments are not present
        if ($PSCmdlet.ParameterSetName -ne 'FileQuery') { $DirObject }

        if ($PSBoundParameters['Recurse']) {
            $PSBoundParametersCopy = $PSBoundParameters

            # Remove the provided DirectoryPath arg since we're providing the subdirectory
            $null = $PSBoundParametersCopy.Remove('DirectoryPath')

            Get-CSDirectoryListing @PSBoundParametersCopy -DirectoryPath $DirObject.Name
        }
    }

    if (-not $PSBoundParameters['DirectoryOnly']) {
        $FilterComponents = New-Object 'Collections.ObjectModel.Collection`1[System.String]'

        # To do: to make exact datetime matches more usable, I may need to not account for milliseconds
        # and scan for a range that matched within the second.
        $DmtfFormat = 'yyyyMMddHHmmss.ffffff+000'

        if ($PSBoundParameters['FileName']) { $FilterComponents.Add("($(($FileName | % { "Name=``"$($TrimmedPath.Replace('\', '\\'))\\$_``"" }) -join ' OR '))") }
        if ($PSBoundParameters['FileSize']) { $FilterComponents.Add("($(($FileSize | % { "FileSize = $_" }) -join ' OR '))") }
        if ($PSBoundParameters['Extension']) { $FilterComponents.Add("($(($Extension | % { "Extension =``"$_``"" }) -join ' OR '))") }
        if ($PSBoundParameters['LastModified']) { $FilterComponents.Add("LastModified=`"$($LastModified.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['LastModifiedBefore']) { $FilterComponents.Add("LastModified<`"$($LastModifiedBefore.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['LastModifiedAfter']) { $FilterComponents.Add("LastModified>`"$($LastModifiedAfter.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['LastAccessed']) { $FilterComponents.Add("LastAccessed=`"$($LastAccessed.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['LastAccessedBefore']) { $FilterComponents.Add("LastAccessed<`"$($LastAccessedBefore.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['LastAccessedAfter']) { $FilterComponents.Add("LastAccessed>`"$($LastAccessedAfter.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['CreationDate']) { $FilterComponents.Add("CreationDate=`"$($CreationDate.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['CreationDateBefore']) { $FilterComponents.Add("CreationDate<`"$($CreationDateBefore.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['CreationDateAfter']) { $FilterComponents.Add("CreationDate>`"$($CreationDateAfter.ToUniversalTime().ToString($DmtfFormat))`"") }
        if ($PSBoundParameters['CreationDateAfter']) { $FilterComponents.Add('Hidden = "True"') }

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
        Get-CimInstance @CommonArgs @FileArguments | ForEach-Object {
            $Object = $_
            $Object.PSObject.TypeNames.Insert(0, 'CimSweep.LogicalFile')
            Add-Member -InputObject $Object -MemberType NoteProperty -Name CimSession -Value $CimSession
            $Object
        }
    }
}

filter Get-CSService {
<#
.SYNOPSIS

Gets the services on a local or remote computer.

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

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSService

.EXAMPLE

Get-CSService -State Running

Lists running services.

.EXAMPLE

Get-CSService -ServiceType 'Kernel Driver'

.EXAMPLE

Get-CSService -PathName svchost.exe

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSService accepts established CIM sessions over the pipeline.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance

Outputs Win32_Service instances.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        [ValidateNotNullOrEmpty()]
        $DisplayName,

        [String]
        [ValidateSet('Stopped', 'Start Pending', 'Stop Pending', 'Running', 'Continue Pending', 'Pause Pending', 'Paused', 'Unknown')]
        $State,

        [String]
        [ValidateSet('Boot', 'System', 'Auto', 'Manual', 'Disabled')]
        $StartMode,

        [String]
        [ValidateSet('Kernel Driver', 'File System Driver', 'Adapter', 'Recognizer Driver', 'Own Process', 'Share Process', 'Interactive Process')]
        $ServiceType,

        [String]
        [ValidateNotNullOrEmpty()]
        $PathName,

        [String]
        [ValidateNotNullOrEmpty()]
        $Description,

        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

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

    Get-CimInstance @CommonArgs @ServiceEntryArgs -ClassName Win32_Service
}

filter Get-CSProcess {
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

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSProcess

.EXAMPLE

Get-CSProcess -Name chrome

.EXAMPLE

Get-CSProcess -ProcessID 4 -CimSession $CimSession

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSProcess accepts established CIM sessions over the pipeline.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance

Outputs Win32_Process instances.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Alias('Id')]
        [UInt32]
        $ProcessID,

        [UInt32]
        $ParentProcessId,

        [String]
        [ValidateNotNullOrEmpty()]
        $CommandLine,

        [String]
        [ValidateNotNullOrEmpty()]
        $ExecutablePath,

        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    $FilterComponents = New-Object 'Collections.ObjectModel.Collection`1[System.String]'

    $ServiceEntryArgs = @{}

    if ($PSBoundParameters['Name']) { $FilterComponents.Add("Name LIKE '%$Name%'") }
    if ($PSBoundParameters['ProcessID']) { $FilterComponents.Add("ProcessID = $ProcessID") }
    if ($PSBoundParameters['ParentProcessID']) { $FilterComponents.Add("ParentProcessID = $ParentProcessID") }
    if ($PSBoundParameters['CommandLine']) { $FilterComponents.Add("CommandLine LIKE '%$CommandLine%'") }
    if ($PSBoundParameters['ExecutablePath']) { $FilterComponents.Add("ExecutablePath LIKE '%$ExecutablePath%'") }

    if ($FilterComponents.Count) {
        $Filter = $FilterComponents -join ' AND '
        $ServiceEntryArgs['Filter'] = $Filter
    }

    Get-CimInstance @CommonArgs @ServiceEntryArgs -ClassName Win32_Process
}