function Get-CSScheduledTaskFile {
<#
.SYNOPSIS

Lists file information associated with installed scheduled tasks.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

The ability to remotely query scheduled tasks was not introduced until Windows 8. Get-CSScheduledTaskFile offers the next best thing by simply scanning %SystemRoot%\Windows\Tasks.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSScheduledTaskFile accepts established CIM sessions over the pipeline.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [Switch]
        $NoProgressBar,

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
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Scheduled task file sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property SystemDirectory @CommonArgs

            if ($OSInfo.SystemDirectory) {
                # Root task directory: %SystemRoot%\System32\Tasks
                $TaskDir = $OSInfo.SystemDirectory + '\Tasks'

                if (-not $PSBoundParameters['NoProgressBar']) {
                    Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status $TaskDir
                }

                # List tasks in root directory
                Get-CSDirectoryListing -DirectoryPath $TaskDir -File @CommonArgs

                # Start by only retrieving directory info recursively. This is a performance enhancement
                Get-CSDirectoryListing -DirectoryPath $TaskDir -Recurse -Directory -DoNotDetectRecursiveDirs @CommonArgs | ForEach-Object {
                    if (-not $PSBoundParameters['NoProgressBar']) {
                        Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status ($_.Name)
                    }

                    # Get task file information for each subdirectory
                    $_ | Get-CSDirectoryListing -File @CommonArgs
                }
            } else {
                Write-Error "[$ComputerName] Unable to obtain scheduled task information because the system directory could not be retrieved."
            }
        }
    }
}

function Get-CSShellFolderPath {
<#
.SYNOPSIS

Obtains the full path to special shell folders.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.Description

Get-CSShellFolderPath is primarily a helper function used to correctly obtain the paths to special shell folders versus relying upon common hard-coded paths which can be redirected and cause false negatives.

.PARAMETER FolderName

Specifies the name of the special shell folder to get the path for.

.PARAMETER SystemFolder

Specifies that only system-level shell folders should be retrieved.

.PARAMETER UserFolder

Specifies that only user-specific shell folders should be retrieved.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSShellFolderPath

.EXAMPLE

Get-CSShellFolderPath -FolderName 'Common Start Menu'

.EXAMPLE

Get-CSShellFolderPath -FolderName 'Start Menu' -CimSession $CimSession

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSShellFolderPath accepts established CIM sessions over the pipeline.
#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
        [String]
        [ValidateSet(
            'Administrative Tools',
            'AppData',
            'Cache',
            'CD Burning',
            'Common Administrative Tools',
            'Common AppData',
            'Common Desktop',
            'Common Documents',
            'Common Programs',
            'Common Start Menu',
            'Common Startup',
            'Common Templates',
            'CommonMusic',
            'CommonPictures',
            'CommonVideo',
            'OEM Links',
            'Cookies',
            'Desktop',
            'Favorites',
            'Fonts',
            'History',
            'Local AppData',
            'My Music',
            'My Pictures',
            'My Video',
            'NetHood',
            'Personal',
            'PrintHood',
            'Programs',
            'Recent',
            'SendTo',
            'Start Menu',
            'Startup',
            'Templates'
        )]
        $FolderName,

        [Parameter(Mandatory = $True, ParameterSetName = 'System')]
        [Switch]
        $SystemFolder,

        [Parameter(Mandatory = $True, ParameterSetName = 'User')]
        [Switch]
        $UserFolder,

        [Switch]
        $NoProgressBar,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
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

        $ShellFolders = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            if (-not $PSBoundParameters['NoProgressBar']) {
                $ComputerName = $Session.ComputerName
                if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Shell folder path sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            # Get a precise registry value if a specific folder is specified. This is a performance enhancement.
            if ($PSBoundParameters['FolderName']) {
                if (($PSCmdlet.ParameterSetName -eq 'System') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    Get-CSRegistryValue -Hive HKLM -SubKey $ShellFolders -ValueName $FolderName -ValueType REG_SZ @CommonArgs |
                        Where-Object { $_.ValueContent }
                }

                if (($PSCmdlet.ParameterSetName -eq 'User') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    # Get the SIDS for each user in the registry
                    $HKUSIDs = Get-HKUSID @CommonArgs

                    # Iterate over each local user hive
                    foreach ($SID in $HKUSIDs) {
                        Get-CSRegistryValue -Hive HKU -SubKey "$SID\$ShellFolders" -ValueName $FolderName -ValueType REG_SZ @CommonArgs |
                            Where-Object { $_.ValueContent }
                    }
                }
            } else { # Otherwise, retrieve all shell folders
                if (($PSCmdlet.ParameterSetName -eq 'System') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    Get-CSRegistryValue -Hive HKLM -SubKey $ShellFolders -ValueNameOnly @CommonArgs | 
                        Where-Object { -not $_.ValueName.StartsWith('!') -and -not $_.ValueName.StartsWith('{') } |
                        Get-CSRegistryValue
                }

                if (($PSCmdlet.ParameterSetName -eq 'User') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                    # Get the SIDS for each user in the registry
                    $HKUSIDs = Get-HKUSID @CommonArgs

                    # Iterate over each local user hive
                    foreach ($SID in $HKUSIDs) {
                        Get-CSRegistryValue -Hive HKU -SubKey "$SID\$ShellFolders" -ValueNameOnly @CommonArgs | 
                            Where-Object { -not $_.ValueName.StartsWith('!') -and -not $_.ValueName.StartsWith('{') } |
                            Get-CSRegistryValue
                    }
                } 
            }
        }
    }
}

function Get-CSTempFile {
<#
.SYNOPSIS

Lists files present in all user and system temp paths.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER Extension

Specifies that only files of a certain extension should be returned. When specifying extensions, do not include a dot - e.g. 'exe', 'dll', 'sys'.

.PARAMETER SystemFolder

Specifies that only system-level temp directories should be retrieved.

.PARAMETER UserFolder

Specifies that only user-specific temp directories should be retrieved.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER DoNotRecurse

Only list files in the root directory.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSTempFile accepts established CIM sessions over the pipeline.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Extension,

        [Parameter(Mandatory = $True, ParameterSetName = 'System')]
        [Switch]
        $SystemFolder,

        [Parameter(Mandatory = $True, ParameterSetName = 'User')]
        [Switch]
        $UserFolder,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
        [Switch]
        $DoNotRecurse,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
        [Switch]
        $NoProgressBar,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'System')]
        [Parameter(ParameterSetName = 'User')]
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

        $TargetExtensions = @{}
        if ($PSBoundParameters['Extension']) { $TargetExtensions['Extension'] = $Extension }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Temp directory sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            if (($PSCmdlet.ParameterSetName -eq 'System') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                # Get system temp path from the registry
                $SystemTempPath = Get-CSEnvironmentVariable -SystemVariable -VariableName TEMP -NoProgressBar @CommonArgs

                if ($SystemTempPath.VariableValue) {
                    Write-Verbose "[$ComputerName] User temp directory: $($SystemTempPath.VariableValue)"

                    if (-not $PSBoundParameters['NoProgressBar']) {
                        Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status $SystemTempPath.VariableValue
                    }

                    # Display files in the root temp dir
                    Get-CSDirectoryListing -DirectoryPath $SystemTempPath.VariableValue -File @TargetExtensions @CommonArgs

                    if (-not $PSBoundParameters['DoNotRecurse']) {
                        Get-CSDirectoryListing -DirectoryPath $SystemTempPath.VariableValue -Directory -Recurse @CommonArgs | ForEach-Object {
                            if (-not $PSBoundParameters['NoProgressBar']) {
                                Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status ($_.Name)
                            }

                            $_ | Get-CSDirectoryListing -File @TargetExtensions
                        }
                    }
                } else {
                    Write-Error "[$ComputerName] Unable to obtain system temp files because the system temp directory could not be retrieved."
                }
            }

            if (($PSCmdlet.ParameterSetName -eq 'User') -or ($PSCmdlet.ParameterSetName -eq 'Default')) {
                # Get user %USERPROFILE% and validate the end of %TEMP%. The root path of %TEMP% is not often not resolved properly.
                $UserProfiles = Get-CSEnvironmentVariable -UserVariable -VariableName USERPROFILE -NoProgressBar @CommonArgs
                $TempVars = Get-CSEnvironmentVariable -UserVariable -VariableName TEMP -NoProgressBar @CommonArgs

                foreach ($UserProfile in $UserProfiles) {
                    $TempVars | Where-Object { $_.User -eq $UserProfile.User } | ForEach-Object {
                        $LegacyTemp = 'Local Settings\Temp'
                        $ModernTemp = 'AppData\Local\Temp'

                        $FullTempPath = $null
                        $ExpectedPathObtained = $True

                        if ($_.VariableValue.EndsWith($ModernTemp)) {
                            $FullTempPath = "$($UserProfile.VariableValue)\$($ModernTemp)"
                        } elseif ($_.VariableValue.EndsWith($LegacyTemp)) {
                            $FullTempPath = "$($UserProfile.VariableValue)\$($LegacyTemp)"
                        } else {
                            $ExpectedPathObtained = $False
                            Write-Error "[$ComputerName] Unable to obtain user temp directory. A non standard temp path was detected. Detected path: $($_.VariableValue)"
                        }

                        if ($ExpectedPathObtained) {
                            Write-Verbose "[$ComputerName] User temp directory: $FullTempPath"

                            if (-not $PSBoundParameters['NoProgressBar']) {
                                Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status $FullTempPath
                            }

                            # Display files in the root temp dir
                            Get-CSDirectoryListing -DirectoryPath $FullTempPath -File @TargetExtensions @CommonArgs

                            if (-not $PSBoundParameters['DoNotRecurse']) {
                                Get-CSDirectoryListing -DirectoryPath $FullTempPath -Directory -Recurse @CommonArgs | ForEach-Object {
                                    if (-not $PSBoundParameters['NoProgressBar']) {
                                        Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status ($_.Name)
                                    }

                                    $_ | Get-CSDirectoryListing -File @TargetExtensions
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

function Get-CSLowILPathFile {
<#
.SYNOPSIS

Lists executable files and scripts present in all user low integrity paths - %LOCALAPPDATA%Low

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER Extension

Specifies that only files of a certain extension should be returned. When specifying extensions, do not include a dot - e.g. 'exe', 'dll', 'sys'.

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER DoNotRecurse

Only list files in the root directory.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSLowILPathFile accepts established CIM sessions over the pipeline.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Extension,

        [Switch]
        $DoNotRecurse,

        [Switch]
        $NoProgressBar,

        [Parameter(ValueFromPipeline = $True)]
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

        $TargetExtensions = @{}
        if ($PSBoundParameters['Extension']) { $TargetExtensions['Extension'] = $Extension }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Low integrity level directory sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            Get-CSEnvironmentVariable -UserVariable -VariableName LOCALAPPDATA -NoProgressBar @CommonArgs | ForEach-Object {
                Write-Verbose "[$ComputerName] LocalAppData path: $($_.VariableValue)"

                if ($_.VariableValue) {
                    $LocalLowPath = "$($_.VariableValue)Low"

                    if (-not $PSBoundParameters['NoProgressBar']) {
                        Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status $LocalLowPath
                    }

                    # List all files in the root low IL dir
                    Get-CSDirectoryListing -DirectoryPath $LocalLowPath -File @TargetExtensions @CommonArgs

                    if (-not $PSBoundParameters['DoNotRecurse']) {
                        Get-CSDirectoryListing -DirectoryPath $LocalLowPath -Recurse -Directory @CommonArgs | ForEach-Object {
                            if (-not $PSBoundParameters['NoProgressBar']) {
                                Write-Progress -Id 2 -ParentId 1 -Activity "Current directory:" -Status ($_.Name)
                            }

                            $_ | Get-CSDirectoryListing -File @TargetExtensions
                        }
                    }
                }
            }
        }
    }
}
