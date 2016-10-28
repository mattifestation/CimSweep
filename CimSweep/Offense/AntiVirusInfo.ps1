Function Get-CSAVInfo
{
<#    
.SYNOPSIS

This function enumerates the Anti Virus installed on a remote host and any helpful registry keys.

Author: Chris Ross (@xorrior)
License: BSD 3-Clause

.DESCRIPTION

Get-CSAVInfo uses the AntiVirusProduct WMI class to enumerate Anti Virus on a local or remote host. The name, executable, state, and registry keys are returned in a custom psobject. 

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

.EXAMPLE

Get-CimAVInfo

.EXAMPLE

Get-CimAVInfo -Session $CimSession

.OUTPUTS

CimSweep.AVInfo

Outputs custom objects representing the current AV configuration.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.AVInfo')]
    param
    (
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
    }

    PROCESS
    {
        foreach ($Session in $CimSession)
        {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            $CommonArgs = @{}
            $InstanceArgs = @{}
            $InstanceArgs['ClassName'] = 'AntiVirusProduct'
            
            #Check if a session was specified
            if ($Session.Id) {$CommonArgs['CimSession'] = $Session}

            #Determine if the namespace exists
            if (Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name="SecurityCenter2"' @CommonArgs @Timeout) 
            {
                $InstanceArgs['Namespace'] = 'root/SecurityCenter2'
            }
            elseif (Get-CimInstance -Namespace root -ClassName __NAMESPACE -Filter 'Name="SecurityCenter"' @CommonArgs @Timeout) 
            {
                $InstanceArgs['Namespace'] = 'root/SecurityCenter'
            }
            else {
                Write-Error "[$ComputerName] Neither the SecurityCenter2 nor the SecurityCenter namespaces do not exist."
                break    
            }

            $AV = Get-CimInstance @InstanceArgs @CommonArgs @Timeout

            if ($InstanceArgs['NameSpace'] -eq 'root/SecurityCenter2')
            {
                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.AVInfo'
                    Name = $AV.displayName
                    Executable = $AV.pathToSignedProductExe
                    InstanceGUID = $AV.instanceGuid
                    ScannerEnabled = $null
                    Updated = $null
                    ExclusionInfo = $null
                }

                #parse the byte value of productstate
                $state = '{0:X6}' -f $AV.productState
                $scanner = $state[2,3] -join '' -as [byte]
                $updated = $state[4,5] -join '' -as [byte]
                
                if($scanner -ge (10 -as [byte]))
                {
                    $ObjectProperties.ScannerEnabled = $True
                }
                elseif($scanner -eq (00 -as [byte]) -or $scanner -eq (01 -as [byte]))
                {
                    $ObjectProperties.ScannerEnabled = $False
                }

                #Determine if the AV definitions are up to date
                if($updated -eq (00 -as [byte]))
                {
                    $ObjectProperties.Updated = $True
                }
                elseif($updated -eq (10 -as [byte]))
                {
                    $ObjectProperties.Updated = $False
                }

                if ($Session.ComputerName) { $ObjectProperties['PSComputerName'] = $Session.ComputerName }

                $AntiVirus = [PSCustomObject] $ObjectProperties
            }
            else
            {
                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.AVInfo'
                    Name = $AV.displayName
                    Executable = $AV.pathToEnableOnAccessUI
                    InstanceGUID =  $AV.instanceGuid
                    ScannerEnabled = $AV.onAccessScanningEnabled
                    Updated = $AV.productUptoDate
                    ExclusionInfo = $null
                    PSComputerName = $Session.ComputerName
                }

                if ($Session.ComputerName) { $ObjectProperties['PSComputerName'] = $Session.ComputerName }

                $AntiVirus = [PSCustomObject] $ObjectProperties
            }


            #Get the exclusions if available
            $DefenderPaths = @{
                ExcludedPaths = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\'
                ExcludedExtensions = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\'
                ExcludedProcesses = 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\'
            }

            $McAfeePaths = @{
                Exclusions = 'SOFTWARE\McAfee\AVSolution\OAS\DEFAULT\'
                EmailIncludedProcesses = 'SOFTWARE\McAfee\AVSolution\OAS\EMAIL\'
                ProcessStartupExclusions = 'SOFTWARE\McAfee\AVSolution\HIP\'
            }

            if($AntiVirus.Name -match 'Windows Defender')
            {
                $ExclusionInfo = [PSCustomObject] @{}
                $DefenderPaths.GetEnumerator() | ForEach-Object {
                    $ExclusionInfo | Add-Member -NotePropertyName $_.Key -NotePropertyValue $(Get-CSRegistryValue -Hive HKLM -SubKey $($_.Value) @CommonArgs @Timeout).ValueName
                }

            }
            elseif($AntiVirus.Name -match 'McAfee')
            {
                $ExclusionInfo = [PSCustomObject] @{}
                $McAfeePaths.GetEnumerator() | ForEach-Object {
                    $ExclusionInfo | Add-Member -NotePropertyName $_.Key -NotePropertyValue $(Get-CSRegistryValue -Hive HKLM -SubKey $($_.Value) @CommonArgs @Timeout).ValueName
                }
            }

            $AntiVirus.ExclusionInfo = $ExclusionInfo

            $AntiVirus
        }
    }
}