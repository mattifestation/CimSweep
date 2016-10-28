Get-ChildItem $PSScriptRoot -Directory |
    Where-Object { $_.Name -ne 'ps1xml' -and $_.Name -ne 'Tests' } |
    Get-ChildItem -Include '*.ps1' |
    ForEach-Object { . $_.FullName }


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