function Copy-CSShadowCopyItem
{
<#    
.SYNOPSIS

Copies files from a shadow copy.

Author: Chris Ross (@xorrior)
License: BSD 3-Clause

.DESCRIPTION
Copy-CSShadowCopyItem copies files from a shadow copy to a local or remote destination. Useful for copying locked files, such as the SAM and SYSTEM hive files or NTDS.dit.

.PARAMETER SymlinkTempPath

The temporary path that will be used to create the symlink

.PARAMETER SourcePath

The full path to the file to copy.

.PARAMETER DestinationPath

The full path to where the file should be copied. 

.PARAMETER PassThru

Instructs Copy-CSShadowCopyItem to return a root/cimv2/CIM_LogicalFile instance representing the file that was copied from the volume shadow copy.

.PARAMETER Force

Bypasses confirmation dialogs.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

.EXAMPLE

Copy-CSShadowCopyItem -SourcePath 'C:\Windows\System32\SAM' -DestinationPath 'C:\SAM'

Copy the SAM hive file from a local shadow copy to a local location, using the default temporary symlink path.

.EXAMPLE

Copy-CSShadowCopyItem -SymlinkTempPath 'C:\Users\test\AppData' -SourcePath 'C:\Users\test\lockedfile.txt' -DestinationPath 'C:\lockedfile.txt'

Copy a locked file from a shadowcopy, using the specified temp symlinkpath, to the destination path.

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#root/cimv2/CIM_LogicalFile

If -PassThru is specified, Copy-CSShadowCopyItem returns a CIM_LogicalFile instance representing the file that was copied from the created volume shadow copy.
#>

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#root/cimv2/CIM_LogicalFile')]
    param
    (
        [ValidateNotNullOrEmpty()]
        [Alias('LinkPath')]
        [String]
        $SymLinkTempPath = 'C:\SC',

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z]:\\')]
        [String]
        $SourcePath,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('(^[a-zA-Z]:\\)')]
        [String]
        $DestinationPath,

        [Switch]
        $PassThru,

        [Switch]
        $Force,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN
    {
        if (-not $PSBoundParameters['CimSession'])
        {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        $ConfirmArg = @{}
        if ($PSBoundParameters['Force']) { $ConfirmArg['Confirm'] = $False }
    }

    PROCESS
    {
        foreach($Session in $CimSession)
        {
            $MethodArgs = @{
                ClassName = 'Win32_ShadowCopy'
                Namespace = 'root\cimv2'
                MethodName = 'Create'
            }

            $CommonArgs = @{}

            #check for CimSession
            if($Session.Id) {$CommonArgs['CimSession'] = $Session}

            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            $Drive = $SourcePath.Split('\')[0]
            $Drive += '\'

            $MethodArgs['Arguments'] = @{
                Context = 'ClientAccessible'
                Volume = $Drive + '\'
            }

            #create a shadow copy
            if ($Force -or $PSCmdlet.ShouldProcess($Drive, 'Create a shadow copy')) {
                $Result = Invoke-CimMethod @MethodArgs @CommonArgs @Timeout @ConfirmArg
            }

            if ($Result.ReturnValue -eq 0)
            {
                $ShadowID = $Result.ShadowID
            }
            else
            {
                if (-not $PSBoundParameters['WhatIf']) {
                    Write-Error "[$ComputerName] Unable to create shadow copy from the $Drive drive."
                    break
                }
            }

            $DeviceObject = (Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$ShadowID'" @CommonArgs @Timeout -ErrorAction SilentlyContinue).DeviceObject

            if ($DeviceObject -and (-not $PSBoundParameters['WhatIf'])) {
                Write-Error "[$ComputerName] Unable to retrive shadow copy instance for the following ShadowID: $ShadowID"
            }

            $Symlinkpath = $SymLinkTempPath + $SourcePath.Substring(2)
            $Symlinkpath = $Symlinkpath.Replace('\','\\')
            
            #create a Symlink to the shadowcopy's deviceobject path
            $Command = "cmd.exe /C MKLINK /D $SymLinkTempPath $DeviceObject\"

            $MethodArgs['ClassName'] = 'Win32_Process'
            $MethodArgs['Namespace'] = 'root\cimv2'
            $MethodArgs['MethodName'] = 'Create'
            $MethodArgs['Arguments'] = @{commandline = $command}

            if ($Force -or $PSCmdlet.ShouldProcess($ComputerName, $Command)) {
                $Result = Invoke-CimMethod @MethodArgs @CommonArgs @Timeout @ConfirmArg
            }

            if(($Result.ReturnValue -ne 0) -and (-not $PSBoundParameters['WhatIf']))
            {
                Write-Error "[$ComputerName] The following command did not execute: $command"
                break
            }

            $DestinationPath = $DestinationPath.Replace('\','\\')

            #Get an instance of the file to be copied and then copy it to the destinationPath
            $Instance = Get-CimInstance -ClassName CIM_LogicalFile -Namespace root/CIMV2 -Filter "Name=`'$symlinkPath`'" @CommonArgs @Timeout

            if ($Instance)
            {
                $Result = Invoke-CimMethod -InputObject $Instance -MethodName 'Copy' -Arguments @{Filename = $DestinationPath} @CommonArgs @Timeout
                
                if (($Result.ReturnValue -ne 0) -and (-not $PSBoundParameters['WhatIf']))
                {
                    Write-Error "[$ComputerName] Unable to copy file from $Symlinkpath to $DestinationPath"
                    break
                }
            }

            $Command = "cmd.exe /C rmdir $SymLinkTempPath"

            $MethodArgs['Arguments'] = @{commandline = $Command}

            if ($Force -or $PSCmdlet.ShouldProcess($ComputerName, $Command)) {
                $Result = Invoke-CimMethod @MethodArgs @CommonArgs @Timeout @ConfirmArg
            }

            if (($Result.ReturnValue -ne 0) -and (-not $PSBoundParameters['WhatIf']))
            {
                Write-Error "[$ComputerName] Unable to remove the symlink directory"
                break
            }

            #Cleanup the shadowcopy 
            $Instance = Get-CimInstance -ClassName Win32_ShadowCopy -Namespace root/CIMV2 -Filter "ID=`'$ShadowID`'" -ErrorAction SilentlyContinue @CommonArgs @Timeout
            
            if ($Instance)
            {
                Remove-CimInstance -InputObject $Instance @CommonArgs @Timeout
            } else {
                if (-not $PSBoundParameters['WhatIf']) {
                    Write-Error "[$ComputerName] Unable to retrive shadow copy instance for the following ShadowID: $ShadowID"
                }
            }
            
            if ($PassThru) {
                Get-CimInstance -ClassName CIM_LogicalFile -Namespace root/CIMV2 -Filter "Name=`'$DestinationPath`'" @CommonArgs @Timeout
            }
        }
    }
}