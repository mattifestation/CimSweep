function Get-CSDeviceGuardStatus {
<#
.SYNOPSIS

Obtains Device Guard configuration status information

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSDeviceGuardStatus obtains information about available and configured Device Guard settings. This function will only work on systems where Device Guard is available - starting with Windows 10 Enterprise and Server 2016. It relies upon the ROOT\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard WMI class. While returning an instance of a Win32_DeviceGuard class would suffice, it returns numeric values for settings that are not human-readable.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSDeviceGuardStatus

Lists the available and configured Device Guard settings.

.OUTPUTS

CimSweep.DeviceGuardStatus

Outputs objects representing available and configured Device Guard settings.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.DeviceGuardStatus')]
    param(
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

        # Also applies to RequiredSecurityProperties
        $AvailableSecurityPropertiesTable = @{
            1 = 'BaseVirtualizationSupport'
            2 = 'SecureBoot'
            3 = 'DMAProtection'
            4 = 'SecureMemoryOverwrite'
            5 = 'UEFICodeReadOnly'
            6 = 'SMMSecurityMitigations1.0'
        }

        # Also applies to UsermodeCodeIntegrityPolicyEnforcementStatus
        $CodeIntegrityPolicyEnforcementStatusTable = @{
            0 = 'Off'
            1 = 'AuditMode'
            2 = 'EnforcementMode'
        }

        # Also applies to SecurityServicesRunning
        $SecurityServicesConfiguredTable = @{
            1 = 'CredentialGuard'
            2 = 'HypervisorEnforcedCodeIntegrity'
        }

        $VirtualizationBasedSecurityStatusTable = @{
            0 = 'Off'
            1 = 'Configured'
            2 = 'Running'
        }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Device Guard configuration sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
            
            $DeviceGuardStatus = Get-CimInstance -Namespace ROOT\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard @CommonArgs

            # An object will not be returned if the namespace/class do not exist
            # e.g. <= Win8 and Server 2012
            if ($DeviceGuardStatus) {
                # Map numeric settings values to human readable strings.

                # All of these properties are UInt32 values.
                # The currently defined values are safe to cast to Int32
                $AvailableSecurityProperties = $DeviceGuardStatus.AvailableSecurityProperties |
                    ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }

                $CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.CodeIntegrityPolicyEnforcementStatus]

                $RequiredSecurityProperties = $DeviceGuardStatus.RequiredSecurityProperties |
                    ForEach-Object { $AvailableSecurityPropertiesTable[[Int32] $_] }

                $SecurityServicesConfigured = $DeviceGuardStatus.SecurityServicesConfigured |
                    ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }

                $SecurityServicesRunning = $DeviceGuardStatus.SecurityServicesRunning |
                    ForEach-Object { $SecurityServicesConfiguredTable[[Int32] $_] }

                $UsermodeCodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatusTable[[Int32] $DeviceGuardStatus.UsermodeCodeIntegrityPolicyEnforcementStatus]

                $VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatusTable[[Int32] $DeviceGuardStatus.VirtualizationBasedSecurityStatus]
            
                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.DeviceGuardStatus'
                    AvailableSecurityProperties = $AvailableSecurityProperties
                    CodeIntegrityPolicyEnforcementStatus = $CodeIntegrityPolicyEnforcementStatus
                    InstanceIdentifier = $DeviceGuardStatus.InstanceIdentifier
                    RequiredSecurityProperties = $RequiredSecurityProperties
                    SecurityServicesConfigured = $SecurityServicesConfigured
                    SecurityServicesRunning = $SecurityServicesRunning
                    UsermodeCodeIntegrityPolicyEnforcementStatus = $UsermodeCodeIntegrityPolicyEnforcementStatus
                    Version = $DeviceGuardStatus.Version
                    VirtualizationBasedSecurityStatus = $VirtualizationBasedSecurityStatus
                }

                if ($DeviceGuardStatus.PSComputerName) {
                    $ObjectProperties['PSComputerName'] = $DeviceGuardStatus.PSComputerName
                }

                [PSCustomObject] $ObjectProperties
            }
        }
    }
}

Export-ModuleMember -Function Get-CSDeviceGuardStatus