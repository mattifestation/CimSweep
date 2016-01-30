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

.OUTPUTS

PSObject

Outputs a list of custom objects representing registry keys.

.NOTES

It is not recommended to recursively list all registry keys from most parent keys as obtaining the results can be time consuming. It is recommended to use Get-CSRegistryKey with targeted subkey paths.

#>

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

        [Parameter(ValueFromPipelineByPropertyName = $True)]
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

.OUTPUTS

PSObject

Outputs a list of custom objects representing registry value names, their respective types, and content for a specified key.

#>

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

        [String]
        $ValueName,

        [Switch]
        $ValueNameOnly,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
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
        1  = 'REG_SZ'
        2  = 'REG_EXPAND_SZ'
        3  = 'REG_BINARY'
        4  = 'REG_DWORD'
        7  = 'REG_MULTI_SZ'
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
                'REG_SZ' {
                    $CimMethod2Args['MethodName'] = 'GetStringValue'
                    $ReturnProp = 'sValue'
                }

                'REG_EXPAND_SZ' {
                    $CimMethod2Args['MethodName'] = 'GetExpandedStringValue'
                    $ReturnProp = 'sValue'
                }

                'MultiString' {
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

                'REG_RESOURCE_REQUIREMENTS_LIST' {
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

function Get-HKUSID {
<#
.SYNOPSIS

Returns the user SIDs present in the HKU hive.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-HKUSID is a helper function that returns user SIDs from the root of the HKU hive. Remotely querying HKU for each local user is ideal over querying HKCU.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

#>

    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    # Get a SID to username mapping
    $Accounts = Get-CimInstance @CommonArgs -Query 'SELECT Name, SID FROM Win32_Account'

    # Get all user specific hives
    $AllUserHives = Get-CSRegistryKey @CommonArgs -Hive HKU | Select-Object -ExpandProperty SubKey
        
    $UserNameToHiveSid = @{}

    foreach ($Account in $Accounts) {
        if ($Account.SID -in $AllUserHives) {
            $Account.SID
        }
    }
}

function Get-CSRegistryAutoStart {
<#
.SYNOPSIS

List installed autostart execution points present in the registry.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSRegistryAutoStart lists autorun points present in the registry locally or remotely.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

#>

    [OutputType([PSObject])]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    # Get the SIDS for each user in the registry
    $HKUSIDs = Get-HKUSID @CommonArgs

    $AutoStartPaths = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($AutoStartPath in $AutoStartPaths) {
        Get-CSRegistryValue @CommonArgs -Hive HKLM -SubKey $AutoStartPath

        # Iterate over each local user hive
        foreach ($SID in $HKUSIDs) {
            Get-CSRegistryValue @CommonArgs -Hive HKU -SubKey "$SID\$AutoStartPath"
        }
    }
}

function Get-CSEventLog {
<#
.SYNOPSIS

Gets a list of event logs on the computer.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.NOTES

Get-CSEventLog is useful for determining which event log to filter off of in Get-CSEventLogEntry.
#>

    param(
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

        [Parameter(ValueFromPipelineByPropertyName = $True)]
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

function Get-CSMountedVolumeDriveLetter {
<#
.SYNOPSIS

Lists the mounted drive letters present. This is primarily used as a helper for Get-CSDirectoryListing when no parameters are provided.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.OUTPUTS

PSObject

Outputs a list of mounted drive letters.
#>

    param(
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

Lists files and directories present the specified directory.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSDirectoryListing performs a WMI/CIM-based file/directory listing of the specified directory.

.PARAMETER DirectoryPath

Specifies the directory.

.PARAMETER FileName

Specifies that information for a specific file should be returned.

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

.INPUTS

PSObject

Accepts input from Get-CSMountedVolumeDriveLetter and itself (Get-CSDirectoryListing).

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance

Outputs a CIM_DataFile or Win32_Directory instance representing file or directory information.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    [CmdletBinding(DefaultParameterSetName = 'FileName')]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String]
        [ValidatePattern('^[A-Za-z]?:\\.*$')]
        $DirectoryPath,

        [Parameter(ParameterSetName = 'FileName')]
        [ValidateNotNullOrEmpty()]
        $FileName,

        [Parameter(ParameterSetName = 'Recurse')]
        [Switch]
        $Recurse,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    # Perform a directory listing of the root of each mounted drive if no path is provided
    if (-not $PSBoundParameters['DirectoryPath']) {
        Get-CSMountedVolumeDriveLetter @CommonArgs | Get-CSDirectoryListing
    } else {
        $TrimmedPath = $DirectoryPath.TrimEnd('\')

        # The validation regex guarantees that $Path[0] will contain a drive letter
        $DriveLetter = $TrimmedPath[0]
        $NewPath = $TrimmedPath.Substring(2)

        $Filter = "Drive = '$($DriveLetter):' AND Path='$($NewPath.Replace('\', '\\'))\\'"

        $Arguments = @{
            ClassName = 'Win32_Directory'
            Filter = $Filter
        }

        if ($PSBoundParameters['FileName']) {
            $Arguments['Filter'] += " AND Name='$($TrimmedPath.Replace('\', '\\'))\\$FileName'"
        }

        # Get all directories present in the specified folder
        Get-CimInstance @CommonArgs @Arguments | ForEach-Object {
            $Object = $_
            $Object.PSObject.TypeNames.Insert(0, 'CimSweep.LogicalFile')
            Add-Member -InputObject $Object -MemberType NoteProperty -Name CimSession -Value $CimSession
            $Object

            if ($PSBoundParameters['Recurse']) {
                Get-CSDirectoryListing @CommonArgs -Recurse -DirectoryPath $Object.Name
            }
        }

        $Arguments['ClassName'] = 'CIM_DataFile'

        # Get all files present in the specified folder
        Get-CimInstance @CommonArgs @Arguments | ForEach-Object {
            $Object = $_
            $Object.PSObject.TypeNames.Insert(0, 'CimSweep.LogicalFile')
            Add-Member -InputObject $Object -MemberType NoteProperty -Name CimSession -Value $CimSession
            $Object
        }
    }
}

function Get-CSService {
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

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSProcess

.EXAMPLE

Get-CSProcess -Name chrome

.EXAMPLE

Get-CSProcess -ProcessID 4 -CimSession $CimSession

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