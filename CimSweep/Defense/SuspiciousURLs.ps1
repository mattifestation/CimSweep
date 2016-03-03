function Get-CSTypedURL {
<#
.SYNOPSIS

Lists URLs typed into Internet Explorer URL bar.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER NoProgressBar

Do not display a progress bar. This parameter is designed to be used with wrapper functions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

#>

    [CmdletBinding()]
    param(
        [Switch]
        $NoProgressBar,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
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

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            if (-not $PSBoundParameters['NoProgressBar']) {
                # Display a progress activity for each CIM session
                Write-Progress -Id 1 -Activity 'CimSweep - Internet Explorer typed URL sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
                $CurrentCIMSession++
            }

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $TypedURLs = 'SOFTWARE\Microsoft\Internet Explorer\TypedURLs'

            # Get the SIDS for each user in the registry
            $HKUSIDs = Get-HKUSID @CommonArgs

            # Iterate over each local user hive
            foreach ($SID in $HKUSIDs) {
                Get-CSRegistryValue -Hive HKU -SubKey "$SID\$TypedURLs" @CommonArgs @Timeout
            }
        }
    }
}