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

filter Get-CSWMIPersistence {
<#
.SYNOPSIS

List registered permanent WMI event subscriptions.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.INPUTS

Microsoft.Management.Infrastructure.CimSession

Get-CSWMIPersistence accepts established CIM sessions over the pipeline.
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

    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding @CommonArgs | ForEach-Object {
        $CreatorAccount = $null

        # Convert the binary SID representation to a Win32_Account instance
        if ($_.CreatorSID) {
            $SID = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList $_.CreatorSID, 0
            $CreatorAccount = Get-CimInstance -ClassName Win32_Account -Filter "SID=`"$($SID.Value)`"" @CommonArgs
        }

        $Filter = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name=`"$($_.Filter.Name)`"" @CommonArgs

        $ConsumerClass = $_.Consumer.PSObject.TypeNames[0].Split('/')[-1]
        $Consumer = Get-CimInstance -Namespace root/subscription -ClassName $ConsumerClass -Filter "Name=`"$($_.Consumer.Name)`"" @CommonArgs

        $WMIEventSubProperties = [Ordered] @{
            CreatorAccount = $CreatorAccount
            EventFilter = $Filter
            ConsumerClass = $ConsumerClass
            Consumer = $Consumer
            PSComputerName = $_.PSComputerName
        }

        New-Object -TypeName PSObject -Property $WMIEventSubProperties
    }
}