function Get-CSUserAssist {
<#
.SYNOPSIS

Retrieves and parses user assist entries.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause

.DESCRIPTION

Get-CSUserAssist retrieves and parses user assist entry information stored in the registry.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSUserAssist

.EXAMPLE

Get-CSUserAssist -CimSession $CimSession

.OUTPUTS

CimSweep.UserAssistEntry

Outputs objects consisting of relevant user assist information. Note: the LastExecutedTime of this object is a UTC datetime string in Round-trip format.

#>

    [CmdletBinding()]
    [OutputType('CimSweep.UserAssistEntry')]
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
            Write-Progress -Id 1 -Activity 'CimSweep - UserAssist sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
            
            $UserSids = Get-HKUSID @CommonArgs
            
            foreach ($Sid in $UserSids) {

                $Parameters = @{
                    Hive = 'HKU'
                    SubKey = "$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
                    Recurse = $true
                }
    
                Get-CSRegistryKey @Parameters @CommonArgs | Where-Object { $_.SubKey -like "*Count" } | Get-CSRegistryValue @CommonArgs | ForEach-Object {
                            
                    # Decrypt Rot13 from https://github.com/StackCrash/PoshCiphers
                    # truncated && streamlined algorithm a little

                    $PlainCharList = New-Object Collections.Generic.List[char]
                    foreach ($CipherChar in $_.ValueName.ToCharArray()) {
    
                        switch ($CipherChar) {
                            { $_ -ge 65 -and $_ -le 90 } { $PlainCharList.Add((((($_ - 65 - 13) % 26 + 26) % 26) + 65)) } # Uppercase characters
                            { $_ -ge 97 -and $_ -le 122 } { $PlainCharList.Add((((($_ - 97 - 13) % 26 + 26) % 26) + 97)) } # Lowercase characters
                            default { $PlainCharList.Add($CipherChar) } # Pass through symbols and numbers
                        }
                    }
                            
                    $ValueContent = $_.ValueContent

                    # Parse LastExecutedTime from binary data
                    $FileTime = switch ($ValueContent.Count) {
                              8 { [datetime]::FromFileTime(0) }
                             16 { [datetime]::FromFileTime([BitConverter]::ToInt64($ValueContent[8..15],0)) }
                        default { [datetime]::FromFileTime([BitConverter]::ToInt64($ValueContent[60..67],0)) }
                    }

                    $ObjectProperties = [ordered] @{ 
                        PSTypeName = 'CimSweep.UserAssistEntry'
                        Name = -join $PlainCharList
                        UserSid = $Sid
                        LastExecutedTime = $FileTime.ToUniversalTime().ToString('o')
                    }

                    if ($_.PSComputerName) { $ObjectProperties['PSComputerName'] = $_.PSComputerName }
                    [PSCustomObject]$ObjectProperties
                }
            } 
        }
    }
    end {}
}

Export-ModuleMember -Function Get-CSUserAssist