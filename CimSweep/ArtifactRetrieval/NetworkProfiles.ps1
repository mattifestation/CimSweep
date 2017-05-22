function Get-CSNetworkProfile {
<#
.SYNOPSIS

Retrieves and parses entries from the AppCompatCache based on OS version.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause

.DESCRIPTION

Get-CSAppCompatCache parses entries from the Application Compatibility Cache stored in the registry.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSAppCompatCache

.EXAMPLE

Get-CSAppCompatCache -CimSession $CimSession

.OUTPUTS

CimSweep.AppCompatCacheEntry

Outputs objects consisting of the application's file path and that file's last modified time. Note: the LastModified property is a UTC datetime string in Round-trip format.

#>

    [CmdletBinding()]
    [OutputType('CimSweep.NetworkProfile')]
    param (
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )
    
    begin {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0
    }

    process {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Network Profiles sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
                
            $Parameters = @{
                Hive = 'HKLM'
                SubKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
            }
    
            Get-CSRegistryKey @Parameters @CommonArgs | ForEach-Object { 
                $Properties = @{}
                Get-CSRegistryValue -Hive $_.Hive -SubKey $_.SubKey @CommonArgs | ForEach-Object { 
                    if ($_.ValueName -like "Date*") {
                        $BinaryReader = New-Object IO.BinaryReader (New-Object IO.MemoryStream (,$_.ValueContent))
                        
                        $Year = $BinaryReader.ReadInt16()
                        $Month = $BinaryReader.ReadInt16()
                        $null = $BinaryReader.ReadInt16() # skip week day
                        $Day = $BinaryReader.ReadInt16()
                        $Hour = $BinaryReader.ReadInt16()
                        $Minute = $BinaryReader.ReadInt16()
                        $Second = $BinaryReader.ReadInt16()
                        $Millisecond = $BinaryReader.ReadInt16()
                        
                        $BinaryReader.BaseStream.Dispose()
                        $BinaryReader.Dispose()

                        $Properties.Add($_.ValueName, [datetime]::new($Year, $Month, $Day, $Hour, $Minute, $Second, $Millisecond, [DateTimeKind]::Utc).ToString('o'))
                    }
                    elseif ($_.ValueName  -eq 'NameType') { 
                        $Type = switch ($_.ValueContent) {
                             6 { 'Ethernet' }
                            23 { 'VPN' }
                            71 { 'WiFi' }
                        }
                        $Properties.Add('Type',$Type)
                    }
                    else { $Properties.Add($_.ValueName, $_.ValueContent) }
                }
                [PSCustomObject]$Properties 
            } 
        }
    }
    end {}
}