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
        $UserRootDir = Join-Path $RootDir 'Users'
        $UserRootDirClassic = Join-Path $RootDir 'Documents and Settings'

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
                $UserTempPath = Join-Path $UserDir.Name $UserTempLeafPath

                Get-CSDirectoryListing -DirectoryPath $UserTempPath -Recurse -Extension $TargetExtensions @CommonArgs
            }
        }

        $SystemTempDir = Join-Path $RootDir 'Windows\Temp'
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
        $UserRootDir = Join-Path $RootDir 'Users'

        # Attempt to get all user directories
        $UserDirectories = Get-CSDirectoryListing -DirectoryPath $UserRootDir -DirectoryOnly @CommonArgs

        if ($UserDirectories) {
            foreach ($UserDir in $UserDirectories) {
                $LowILPath = Join-Path $UserDir.Name 'AppData\LocalLow'

                Get-CSDirectoryListing -DirectoryPath $LowILPath -Recurse -Extension $TargetExtensions @CommonArgs
            }
        }
    } else {
        Write-Error 'Unable to obtain system drive.'
    }
}
