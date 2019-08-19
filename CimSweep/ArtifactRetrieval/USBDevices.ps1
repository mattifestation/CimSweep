function Get-CSUsbStorageDevice {
<#
.SYNOPSIS

Lists storage devices that are attached to the USB port.

Author: Michael Hefele (@VRDSE)
License: BSD 3-Clause

.DESCRIPTION

Get-CSUsbStorageDevice queries the SYSTEM\CurrentControlSet\Enum\USBSTOR to receive the current attached USB storage devices.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSUsbStorageDevice

Retrieves all USB attached storage devices on the local system.

.EXAMPLE

Get-CSUsbStorageDevice -CimSession $CimSession

Retrieves all USB attached storage devices on a remote system.

.OUTPUTS

CimSweep.USBStorageDevice

Outputs information about a USB storage device.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.USBStorageDevice')]
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
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Attached USB devices' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $USBSTORKey = 'SYSTEM\CurrentControlSet\Enum\USBSTOR'
            $USBSTOR = Get-CSRegistryKey -Hive HKLM -SubKey $USBSTORKey @CommonArgs

            foreach ($Subkey in $USBSTOR) {
                $SplittedSubkey = $Subkey.SubKey -split "(.*)\\(.*)&Ven_(.*)&Prod_(.*)&Rev_(.*)"
                $ObjectProperties = [Ordered]@{
                    PSTypeName = 'CimSweep.USBStorageDevice'
                    Type       = $SplittedSubkey[2]
                    Vendor     = $SplittedSubkey[3]
                    Product    = $SplittedSubkey[4].Replace('_', ' ')
                    Version    = $SplittedSubkey[5]
                }
                
                $SubSubKey = Get-CSRegistryKey -Hive $Subkey.Hive -SubKey $Subkey.SubKey @CommonArgs
                
                foreach ($Key in $SubSubKey) {
                    $ObjectProperties['SerialNumber'] = (Split-Path -Leaf $Key.SubKey).Split('&')[0]
                    $SubSubKeyValues = Get-CSRegistryValue -Hive $Key.Hive -SubKey $Key.SubKey @CommonArgs
                    
                    $DeviceFriendlyName = ($SubSubKeyValues | Where-Object {$_.ValueName -eq 'FriendlyName'}).ValueContent
                    $Driver = ($SubSubKeyValues | Where-Object {$_.ValueName -eq 'Driver'}).ValueContent
                    $Mfg = ($SubSubKeyValues | Where-Object {$_.ValueName -eq 'Mfg'}).ValueContent

                    $ObjectProperties['DeviceFriendlyName'] = $DeviceFriendlyName
                    $ObjectProperties['Driver'] = $Driver
                    $ObjectProperties['Mfg'] = $Mfg
                    $ObjectProperties['PSComputerName'] = $ComputerName

                    [PSCustomObject]$ObjectProperties
                }
            }
        }
    }
}

Export-ModuleMember -Function Get-CSUsbStorageDevice
