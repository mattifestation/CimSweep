filter Get-CSScheduledTaskFile {
<#
.SYNOPSIS

Lists file information associated with installed scheduled tasks.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

The ability to remotely query scheduled tasks was not introduced until Windows 8. Get-CSScheduledTaskFile offers the next best thing by simply scanning %SystemRoot%\Windows\Tasks.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSScheduledTaskFile accepts established CIM sessions over the pipeline.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property SystemDirectory @CommonArgs

    if ($OSInfo.SystemDirectory) {
        $TaskDir = $OSInfo.SystemDirectory + '\Tasks'

        Get-CSDirectoryListing -DirectoryPath $TaskDir -Recurse @CommonArgs |
            Where-Object { $_.CimClass.CimClassName -ne 'Win32_Directory' }
    } else {
        Write-Error 'Unable to obtain system directory.'
    }
}

filter Get-CSShellFolderPath {
<#
.SYNOPSIS

Obtains the full path to special shell folders.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.Description

Get-CSShellFolderPath is primarily a helper function used to correctly obtain the paths to special shell folders versus relying upon common hard-coded paths which can be redirected and cause false negatives.

.PARAMETER FolderName

Specifies the name of the special shell folder to get the path for.

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

    param(
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
            'OEM Links',
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

        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}
    $RegistryArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }
    if ($PSBoundParameters['FolderName']) { $RegistryArgs['ValueName'] = $FolderName }

    $ShellFolders = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'

    # Get the SIDS for each user in the registry
    $HKUSIDs = Get-HKUSID @CommonArgs

    # Iterate over each local user hive
    foreach ($SID in $HKUSIDs) {
        Get-CSRegistryValue -Hive HKU -SubKey "$SID\$ShellFolders" -ValueNameOnly @CommonArgs @RegistryArgs | 
            ? { -not $_.ValueName.StartsWith('!') -and -not $_.ValueName.StartsWith('{') } |
            Get-CSRegistryValue
    }

    Get-CSRegistryValue -Hive HKLM -SubKey "$ShellFolders" -ValueNameOnly @CommonArgs @RegistryArgs | 
        ? { -not $_.ValueName.StartsWith('!') -and -not $_.ValueName.StartsWith('{') } |
        Get-CSRegistryValue
}

filter Get-CSStartMenuEntry {
<#
.SYNOPSIS

List user and common start menu items.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSStartMenuEntry accepts established CIM sessions over the pipeline.

.NOTES

If a shortcut is present in the start menu, an instance of a Win32_ShortcutFile is returned that has a Target property.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    Get-CSShellFolderPath -FolderName 'Startup' @CommonArgs | ForEach-Object {
        Get-CSDirectoryListing -DirectoryPath $_.ValueContent @CommonArgs | Where-Object {
            $_.FileName -ne 'desktop' -and $_.Extension -ne 'ini'
        }
    }

    Get-CSShellFolderPath -FolderName 'Common Startup' @CommonArgs | ForEach-Object {
        Get-CSDirectoryListing -DirectoryPath $_.ValueContent @CommonArgs | Where-Object {
            $_.FileName -ne 'desktop' -and $_.Extension -ne 'ini'
        }
    }
}

filter Get-CSTempPathPEAndScript {
<#
.SYNOPSIS

Lists executable files and scripts present in all temp paths.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSTempPathPEAndScript returns file information for all of the following file extensions present in all temp directories: EXE, DLL, SYS, PS1, BAT, VBS, JS.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSTempPathPEAndScript accepts established CIM sessions over the pipeline.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property SystemDrive @CommonArgs

    # Validate that a drive letter was returned
    if ($OSInfo.SystemDrive) {
        $TargetExtensions = @('exe', 'dll', 'sys', 'ps1', 'bat', 'vbs', 'js')

        $RootDir = $OSInfo.SystemDrive
        $UserRootDir = "$RootDir\Users"
        $UserRootDirClassic = "$RootDir\Documents and Settings"

        # Attempt to get all user directories
        $UserDirectories = Get-CSDirectoryListing -DirectoryPath $UserRootDir -DirectoryOnly @CommonArgs
        $UserTempLeafPath = 'AppData\Local\Temp'

        # Try to use the WinXP default temp path
        if (-not $UserDirectories) {
            $UserDirectories = Get-CSDirectoryListing -DirectoryPath $UserRootDirClassic -DirectoryOnly @CommonArgs
            $UserTempLeafPath = 'Local Settings\Temp'
        }

        if ($UserDirectories) {
            foreach ($UserDir in $UserDirectories) {
                $UserTempPath = "$($UserDir.Name)\$UserTempLeafPath"

                Get-CSDirectoryListing -DirectoryPath $UserTempPath -Recurse -Extension $TargetExtensions @CommonArgs
            }
        }

        $SystemTempDir = "$RootDir\Windows\Temp"
        Get-CSDirectoryListing -DirectoryPath $SystemTempDir -Recurse -Extension $TargetExtensions @CommonArgs
    } else {
        Write-Error 'Unable to obtain system drive.'
    }
}

filter Get-CSLowILPathPEAndScript {
<#
.SYNOPSIS

Lists executable files and scripts present in all user low integrity paths - %USERPROFILE%\AppData\LocalLow

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSLowILPathPEAndScript accepts established CIM sessions over the pipeline.
#>

    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property SystemDrive @CommonArgs

    # Validate that a drive letter was returned
    if ($OSInfo.SystemDrive) {
        $TargetExtensions = @('exe', 'dll', 'sys', 'ps1', 'bat', 'vbs', 'js')

        $RootDir = $OSInfo.SystemDrive
        $UserRootDir = "$RootDir\Users"

        # Attempt to get all user directories
        $UserDirectories = Get-CSDirectoryListing -DirectoryPath $UserRootDir -DirectoryOnly @CommonArgs

        if ($UserDirectories) {
            foreach ($UserDir in $UserDirectories) {
                $LowILPath = "$($UserDir.Name)\AppData\LocalLow"

                Get-CSDirectoryListing -DirectoryPath $LowILPath -Recurse -Extension $TargetExtensions @CommonArgs
            }
        }
    } else {
        Write-Error 'Unable to obtain system drive.'
    }
}
