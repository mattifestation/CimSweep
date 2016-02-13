filter Get-CSTypedURL {
<#
.SYNOPSIS

Lists URLs typed into Internet Explorer URL bar.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSTypedURL accepts established CIM sessions over the pipeline.
#>

    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    $TypedURLs = 'SOFTWARE\Microsoft\Internet Explorer\TypedURLs'

    # Get the SIDS for each user in the registry
    $HKUSIDs = Get-HKUSID @CommonArgs

    # Iterate over each local user hive
    foreach ($SID in $HKUSIDs.Keys) {
        Get-CSRegistryValue -Hive HKU -SubKey "$SID\$TypedURLs" @CommonArgs
    }
}