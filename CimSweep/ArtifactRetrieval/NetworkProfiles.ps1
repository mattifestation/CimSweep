function Get-CSNetworkProfile {
<#
.SYNOPSIS

Retrieves network profile information.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause

.DESCRIPTION

Get-CSNetworkProfile retrieves and parses network profile information stored in the registry.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSNetworkProfile

.EXAMPLE

Get-CSNetworkProfile -CimSession $CimSession

.OUTPUTS

CimSweep.NetworkProfile

Outputs objects consisting of relevant network profile information. Note: the timestamps of this object are a UTC datetime string in Round-trip format.

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
            Write-Progress -Id 1 -Activity 'CimSweep - Network Profile sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
            
            $Parameters = @{
                Hive = 'HKLM'
                SubKey = 'SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
                ValueName = 'TimeZoneKeyName'
                ValueType = 'REG_SZ'
            }

            $TimeZoneName = Get-CSRegistryValue @Parameters @CommonArgs

            # TimeZoneKeyName doesn't exist on XP, but CimSweep still returns an object as though it did
            # NetworkList also doesn't exist on XP, so might as well bail now.

            try { $TimeZoneInfo = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneName.ValueContent) }
            catch { break }

            $Parameters = @{
                Hive = 'HKLM'
                SubKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
            }
    
            Get-CSRegistryKey @Parameters @CommonArgs | ForEach-Object { 
                
                $ObjectProperties = [ordered] @{ PSTypeName = 'CimSweep.NetworkProfile' }

                Get-CSRegistryValue -Hive $_.Hive -SubKey $_.SubKey @CommonArgs | ForEach-Object { 
                    
                    $ValueName = $_.ValueName
                    $ValueContent = $_.ValueContent

                    switch ($ValueName) {
                        
                        { $_ -like "Date*" } {
                            $BinaryReader = New-Object IO.BinaryReader (New-Object IO.MemoryStream (,$ValueContent))
                        
                            $Year = $BinaryReader.ReadInt16()
                            $Month = $BinaryReader.ReadInt16()
                            $null = $BinaryReader.ReadInt16() # skip week day
                            $Day = $BinaryReader.ReadInt16()
                            $Hour = $BinaryReader.ReadInt16()
                            $Minute = $BinaryReader.ReadInt16()
                            $Second = $BinaryReader.ReadInt16()
                            $Millisecond = $BinaryReader.ReadInt16()
                        
                            $BinaryReader.Dispose()

                            # dates are stored in local timezone
                            $DateTime = New-Object datetime -ArgumentList @($Year, $Month, $Day, $Hour, $Minute, $Second, $Millisecond, 'Unspecified')
                            $CorrectedTime = [TimeZoneInfo]::ConvertTimeToUtc($DateTime, $TimeZoneInfo)

                            $ObjectProperties[$ValueName] =  $CorrectedTime.ToString('o')
                        }
                        
                        'NameType' { 
                            $ObjectProperties['Type'] = switch ($ValueContent) {
                                      6 { 'Wired' }
                                     23 { 'VPN' }
                                     71 { 'Wireless' }
                                default { $ValueContent }
                            }
                        }
                        
                        'Category' { 
                            $ObjectProperties['Category'] = switch ($ValueContent) {
                                0 { 'Public' }
                                1 { 'Private' }
                                2 { 'Domain' }
                            }
                        }
                        
                        'Managed' { $ObjectProperties['Managed'] = [bool]$ValueContent }
                          
                          default { $ObjectProperties[$ValueName] = $ValueContent }
                    }
                }
                if ($_.PSComputerName) { $ObjectProperties['PSComputerName'] = $_.PSComputerName }
                [PSCustomObject]$ObjectProperties
            } 
        }
    }
    end {}
}

Export-ModuleMember -Function Get-CSNetworkProfile