Function Get-CSAVInfo
{

    <#

    Author: Chris Ross (@xorrior)
    License: BSD 3-Clause
    
    .SYNOPSIS
    This function enumerates the Anti Virus installed on a remote host and any helpful registry keys.

    .DESCRIPTION
    This function uses the AntiVirusProduct class to enumerate Anti Virus on a remote host. The name, executable, state, and registry keys are returned in a custom psobject. 

    .PARAMETER Session
    The CimSession to use for Anti-Virus enumeration

    .EXAMPLE

    Get-CimAVInfo -Session $CimSession

    #>

    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Alias("Session")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )


    BEGIN 
    {
        if (-not $PSBoundParameters['CimSession'])
        {
            $CimSession = ''
        }
    }

    PROCESS
    {
        foreach ($Session in $CimSession)
        {
            
            $commonArgs = @{}
            $instanceArgs = @{}
            $instanceArgs['ClassName'] = 'AntiVirusProduct'
            
            #Check if a session was specified
            if ($Session.Id) {$commonArgs['CimSession'] = $Session}

            #Determine if the namespace exists
            if (Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name="SecurityCenter2"' @commonArgs) 
            {
                $instanceArgs['NameSpace'] = 'root/SecurityCenter2'
            }
            elseif (Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name="SecurityCenter"' @commonArgs) 
            {
                $instanceArgs['NameSpace'] = 'root/SecurityCenter'
            }
            else {Write-Verbose "[!] Unable to find SecurityCenter2 or SecurityCenter Namespace instance"; break}

            $AV = Get-CimInstance @instanceArgs @commonArgs

            if ($instanceArgs['NameSpace'] -eq 'root/SecurityCenter2')
            {
                $AntiVirus = [pscustomobject] [ordered]@{
                    Name = $AV.displayName
                    Executable = $AV.pathToSignedProductExe
                    InstanceGUID = $AV.instanceGuid
                    PSComputerName = $AV.PSComputerName
                }

                #Add localhost if PSComputerName is empty

                if($AntiVirus.PSComputerName -eq $null)
                {
                    $AntiVirus.PSComputerName = 'localhost'
                }
                #parse the byte value of productstate
                $state = '{0:X6}' -f $AV.productState
                $scanner = $state[2,3] -join '' -as [byte]
                $updated = $state[4,5] -join '' -as [byte]
                
                if($scanner -ge (10 -as [byte]))
                {
                    $AntiVirus | Add-Member -NotePropertyName 'ScannerEnabled' -NotePropertyValue $True
                }
                elseif($scanner -eq (00 -as [byte]) -or $scanner -eq (01 -as [byte]))
                {
                    $AntiVirus | Add-Member -NotePropertyName 'ScannerEnabled' -NotePropertyValue $False
                }
                else
                {
                    $AntiVirus | Add-Member -NotePropertyName 'ScannerEnabled' -NotePropertyValue '???'
                }

                #Determine if the AV definitions are up to date
                if($updated -eq (00 -as [byte]))
                {
                    $AntiVirus | Add-Member -NotePropertyName 'Updated' -NotePropertyValue $True
                }
                elseif($updated -eq (10 -as [byte]))
                {
                    $AntiVirus | Add-Member -NotePropertyName 'Updated' -NotePropertyValue $False
                }
                else
                {
                    $AntiVirus | Add-Member -NotePropertyName 'Updated' -NotePropertyValue '???'
                }   
            }
            else
            {
                $AntiVirus = [pscustomobject] [ordered]@{
                    Name = $AV.displayName
                    Executable = $AV.pathToEnableOnAccessUI
                    InstanceGUID =  $AV.instanceGuid
                    PSComputerName = $AV.PSComputerName
                }

                $AntiVirus | Add-Member -NotePropertyName 'ScannerEnabled' -NotePropertyValue $($AV.onAccessScanningEnabled)
                $AntiVirus | Add-Member -NotePropertyName 'Updated' -NotePropertyValue $($AV.productUptoDate) 
            }


            #Get the exclusions if available
            $defenderPaths = @{
                ExcludedPaths = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\'
                ExcludedExtensions = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\'
                ExcludedProcesses = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\'
            }

            $mcAfeePaths = @{
                Exclusions = 'HKLM:\SOFTWARE\McAfee\AVSolution\OAS\DEFAULT\'
                EmailIncludedProcesses = 'HKLM:\SOFTWARE\McAfee\AVSolution\OAS\EMAIL\'
                ProcessStartupExclusions = 'HKLM:\SOFTWARE\McAfee\AVSolution\HIP\'
            }

            if($AntiVirus.Name -match 'Windows Defender')
            {
                $exclusionInfo = [PSCustomObject] [Ordered]@{}
                $defenderPaths.GetEnumerator() | ForEach-Object {
                    $exclusionInfo | Add-Member -NotePropertyName $_.Key -NotePropertyValue $(Get-CSRegistryValue -Path $($_.Value) @commonArgs).ValueName
                }

            }
            elseif($AntiVirus.Name -match 'McAfee')
            {
                $exclusionInfo = [PSCustomObject] [Ordered]@{}
                $mcAfeePaths.GetEnumerator() | ForEach-Object {
                    $exclusionInfo | Add-Member -NotePropertyName $_.Key -NotePropertyValue $(Get-CSRegistryValue -Path $($_.Value) @commonArgs).ValueName
                }
            }


            $AntiVirus | Add-Member -NotePropertyName 'ExclusionInfo' -NotePropertyValue $exclusionInfo
            $AntiVirus
        }
    }
}