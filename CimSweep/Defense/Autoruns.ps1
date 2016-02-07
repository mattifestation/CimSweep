filter Get-CSRegistryAutoStart {
<#
.SYNOPSIS

List installed autostart execution points present in the registry.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CSRegistryAutoStart lists autorun points present in the registry locally or remotely.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSRegistryAutoStart accepts established CIM sessions over the pipeline.
#>

    [OutputType([PSObject])]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    $CommonArgs = @{}

    if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $CimSession }

    # Get the SIDS for each user in the registry
    $HKUSIDs = Get-HKUSID @CommonArgs

    $AutoStartPaths = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($AutoStartPath in $AutoStartPaths) {
        Get-CSRegistryValue @CommonArgs -Hive HKLM -SubKey $AutoStartPath

        # Iterate over each local user hive
        foreach ($SID in $HKUSIDs) {
            Get-CSRegistryValue @CommonArgs -Hive HKU -SubKey "$SID\$AutoStartPath"
        }
    }
}
