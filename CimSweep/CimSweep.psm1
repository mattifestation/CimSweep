Get-ChildItem $PSScriptRoot -Directory |
    Where-Object { $_.Name -ne 'ps1xml' -and $_.Name -ne 'Tests' } |
    Get-ChildItem -Include '*.ps1' |
    ForEach-Object { . $_.FullName }

<#
Helper function used to explicitly set which object properties are displayed
This is used primarily to hide CimSession properties and to display PSComputerName
only if a function was performed against a remote computer.

Technique described here: https://poshoholic.com/2008/07/05/essential-powershell-define-default-properties-for-custom-objects/
Thanks Kirk Munro (@Poshoholic)!
#>
function Set-DefaultDisplayProperty {
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [Object]
        $InputObject,

        [Parameter(Mandatory = $True)]
        [String[]]
        $PropertyNames
    )

    $DefaultDisplayPropertySet = New-Object Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’, [String[]] $PropertyNames)
    $PSStandardMembers = [Management.Automation.PSMemberInfo[]]@($DefaultDisplayPropertySet)
    Add-Member -InputObject $InputObject -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers
}

function Get-HKUSID {
<#
.SYNOPSIS

Returns a hashtable mapping SIDs present in the HKU hive to account names.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-HKUSID is a helper function that returns user SIDs from the root of the HKU hive. Remotely querying HKU for each local user is ideal over querying HKCU.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.
#>

    [CmdletBinding()]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }
    if ($PSBoundParameters['OperationTimeoutSec']) { $CommonArgs['OperationTimeoutSec'] = $OperationTimeoutSec }

    Get-CSRegistryKey -Hive HKU @CommonArgs | ForEach-Object {
        # S-1-5-18 is equivalent to HKLM
        if (($_.SubKey -ne '.DEFAULT') -and ($_.SubKey -ne 'S-1-5-18') -and (-not $_.SubKey.EndsWith('_Classes'))) {
            $_.SubKey
        }
    }
}