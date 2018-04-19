function Get-CSNetSessionEnumPermission {
    <#
.SYNOPSIS

Lists the users and groups, that are allowed to enumerate active file and printer sessions to a computer.

Author: Michael Hefele (@VRDSE)
License: BSD 3-Clause

.DESCRIPTION

Get-CSNetSessionEnumPermission shows all users and groups, that are allowed to enumerate active file and 
printer sessions. This information is stored in 
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\SrvsvcSessionInfo as a Binary Security 
Descriptor that is not human readable. This Cmdlet converts the value to an object wiht human readable 
values.
The information is useful for security audits. A list of all active sessions is useful for an attacker 
during reconaissance phase. The session enumeration might tell an attacker what user is logged on which 
computer (e.g. FileServerAdmin is logged on Workstation01). Therefore it makes sense from a security 
perspective to restrict the enumeration permission to, for instance, Administrators.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSNetSessionEnumPermission

Lists the file and printer session enumeration permissions on the local system.

.EXAMPLE

Get-CSNetSessionEnumPermission -CimSession $CimSession

Lists the file and printer session enumeration permissions on a remote system.

.OUTPUTS

CimSweep.NetSessionEnumPermission

Outputs file and printer session enumeration permssions.
#>

    [CmdletBinding()]
    [OutputType('System.Security.AccessControl.DirectorySecurity')]
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
        }
        else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Session Enumeration Permissions' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $RegistryValueArgs = @{
                Hive      = 'HKLM'
                SubKey    = 'SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\'
                ValueName = 'SrvsvcSessionInfo'
            }
            $SrvsvcSessionInfo = (Get-CSRegistryValue @RegistryValueArgs @CommonArgs).ValueContent

            $SrvsvcSessionInfoSD = New-Object Security.AccessControl.DirectorySecurity
            $SrvsvcSessionInfoSD.SetSecurityDescriptorBinaryForm($SrvsvcSessionInfo, 'All')

            $SrvsvcSessionInfoSD        
        }
    }
}

Export-ModuleMember -Function Get-CSNetSessionEnumPermission