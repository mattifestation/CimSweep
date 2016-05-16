Function Get-CSAVInfo
{
    <#
    .SYNOPSIS
    This function enumerates the Anti Virus installed on a remote host and any helpful registry keys.

    .DESCRIPTION
    This function uses the AntiVirusProduct class to enumerate Anti Virus on a remote host. The name, executable, state, and registry keys are returned in a custom psobject. 

    .PARAMETER Session
    The CimSession to use for enumeration

    .EXAMPLE

    Get-CimAVInfo -Session $CimSession
    #>


    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True, ValueFromPipeline=$True)]
        [Alias("Session")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )


    BEGIN {}

    PROCESS 
    {
        foreach ($Computer in $Session)
        {
             $parameters = @{
                ClassName = 'AntiVirusProduct'
                CimSession = $Computer
             } 

            #Determine OS Version
            $OS = Get-CimInstance -ClassName CIM_OperatingSystem -CimSession $Computer
            [decimal]$Version = $OS.Version.Split('.')[0..1] -join '.'
            If($Version -ge 6.0) {$parameters['NameSpace'] = 'root/SecurityCenter2'}
            else {$parameters['NameSpace'] = 'root/SecurityCenter'}

            $AVInfo = Get-CimInstance @parameters 

            #Assign the properties to a new custom object
            if($AVInfo)
            {
                $props = [ordered] @{
                    Name = $AVInfo.displayName
                    ExecutablePath = $AVInfo.pathToSignedProductExe
                    ReportingExe = $AVInfo.pathToSignedReportingExe
                    CompurterName = $AVInfo.PSComputerName
                    GUID = $AVInfo.instanceGuid 
                }

                $state = '{0:X6}' -f $AVInfo.productState
                $provider = $state[0,1] -join '' -as [byte]
                $scanner = $state[2,3] -join '' -as [byte]
                $updated = $state[4,5] -join '' -as [byte]
                $enabled = $false

                if($scanner -ge (10 -as [byte]))
                {
                    $props['ScannerEnabled'] = $True
                }
                elseif($wscscanner -eq (00 -as [byte]) -or $wscscanner -eq (01 -as [byte]))
                {
                    $props['ScannerEnabled'] = $False
                }
                else
                {
                    $props['ScannerEnabled'] = '???'
                }

                #Determine if the AV definitions are up to date
                if($wscupdated -eq (00 -as [byte]))
                {
                    $props['Updated'] = $True
                }
                elseif($wscupdated -eq (10 -as [byte]))
                {
                    $props['Updated'] = $False 
                }
                else
                {
                    $props['Updated'] = '???'
                }

                #Grab the exclusion paths if available

                if($props.Name -match 'Windows Defender')
                {
                    $paths = @{
                        ExcludedPaths = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\'
                        ExcludedExtensions = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\'
                        ExcludedProcesses = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\'
                    }

                    $paths.GetEnumerator() | ForEach-Object {
                       $props[$_.Key] = $(Get-CSRegistryValue -Path $($_.Value) -Session $Computer).ValueContent 
                    }
                }
                elseif($props.Name -match 'McAfee')
                {
                    $paths = @{
                        Exclusions = 'HKLM:\SOFTWARE\McAfee\AVSolution\OAS\DEFAULT\'
                        EmailIncludedProcesses = 'HKLM:\SOFTWARE\McAfee\AVSolution\OAS\EMAIL\'
                        ProcessStartupExclusions = 'HKLM:\SOFTWARE\McAfee\AVSolution\HIP\'
                    }

                    $paths.GetEnumerator() | % {
                        $props[$_.Key] = $(Get-CSRegistryValue -Path $($_.Value) -Session $Computer).ValueContent
                    }
                }
                elseif(($props.Name -match 'SEP') -or ($props.Name -match 'Symantec'))
                {
                    #https://support.symantec.com/en_US/article.HOWTO75109.html
                    $paths = @{
                        PublicOpState = 'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\public-opstate'
                    }

                    $paths.GetEnumerator() | % {
                        $props[$_.Key] = $(Get-CSRegistryValue -Path $($_.Value) -Session $Computer).ValueContent
                    }
                }

                $props
            }
            


        }
    }

    END {} 

}