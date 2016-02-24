function Get-CSRegistryAutoStart {
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
        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $Logon,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $LSAProviders,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $ImageHijacks,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $AppInit,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $KnownDLLs,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $Winlogon,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN {
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $SessionCount = 1
        } else {
            $SessionCount = $CimSession.Count
        }

        $Current = 0

        filter New-AutoRunsEntry {
            Param (
                [Parameter(Position = 0, ValueFromPipelineByPropertyName = $True)]
                [String]
                $Hive,

                [Parameter(Position = 1, ValueFromPipelineByPropertyName = $True)]
                [String]
                $SubKey,

                [Parameter(Position = 2, ValueFromPipelineByPropertyName = $True)]
                [Alias('ValueName')]
                [String]
                $AutoRunEntry,

                [Parameter(Position = 3, ValueFromPipelineByPropertyName = $True)]
                [Alias('ValueContent')]
                [String]
                $ImagePath,

                [Parameter(Position = 4)]
                [String]
                $Category,

                [Parameter(Position = 5, ValueFromPipelineByPropertyName = $True)]
                [String]
                $PSComputerName
            )

            [PSCustomObject] @{
                Path = "$($Hive)\$($SubKey)"
                AutoRunEntry = $AutoRunEntry
                ImagePath = $ImagePath
                Category = $Category
                PSComputerName = $PSComputerName
            }
        }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            Write-Progress -Activity 'CimSweep - Registry autoruns sweep' -Status "($($Current+1)/$($SessionCount)) Current computer: $($Session.ComputerName)" -PercentComplete (($Current / $SessionCount) * 100)
            $Current++

            $CommonArgs = @{}

            if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $Session }

            # Get the SIDS for each user in the registry
            $HKUSIDs = Get-HKUSID @CommonArgs

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['Logon']) {
                $Category = 'Logon'

                $AutoStartPaths = @(
                    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
                    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
                    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
                    'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
                )

                foreach ($AutoStartPath in $AutoStartPaths) {
                    Get-CSRegistryValue -Hive HKLM -SubKey $AutoStartPath @CommonArgs |
                        New-AutoRunsEntry -Category $Category

                    # Iterate over each local user hive
                    foreach ($SID in $HKUSIDs.Keys) {
                        Get-CSRegistryValue -Hive HKU -SubKey "$SID\$AutoStartPath" @CommonArgs |
                            New-AutoRunsEntry -Category $Category
                    }
                }
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['LSAProviders']) {
                $Category = 'LSAProviders'

                $SecProviders = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders' @CommonArgs
                $SecProviders | New-AutoRunsEntry -ImagePath "$($SecProviders.ValueContent)" -Category $Category

                $AuthPackages = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'Authentication Packages' @CommonArgs
                $AuthPackages | New-AutoRunsEntry -ImagePath "$($AuthPackages.ValueContent)" -Category $Category

                $NotPackages =  Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'Notification Packages' @CommonArgs
                $NotPackages | New-AutoRunsEntry -ImagePath "$($NotPackages.ValueContent)" -Category $Category

                $SecPackages = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -ValueName 'Security Packages' @CommonArgs
                $SecPackages | New-AutoRunsEntry -ImagePath "$($SecPackages.ValueContent)" -Category $Category
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['ImageHijacks']) {
                $Category = 'ImageHijacks'

                $CommonKeys = @(
                    'SOFTWARE\Classes\htmlfile\shell\open\command',
                    'SOFTWARE\Classes\htafile\shell\open\command',
                    'SOFTWARE\Classes\batfile\shell\open\command',
                    'SOFTWARE\Classes\comfile\shell\open\command',
                    'SOFTWARE\Classes\piffile\shell\open\command',
                    'SOFTWARE\Classes\exefile\shell\open\command'
                )

                foreach ($CommonKey in $CommonKeys) {
                    Get-CSRegistryValue -Hive HKLM -SubKey $CommonKey -ValueName '' @CommonArgs |
                        New-AutoRunsEntry -AutoRunEntry $CommonKey.Split('\')[2] -Category $Category

                    # Iterate over each local user hive
                    foreach ($SID in $HKUSIDs.Keys) {
                        Get-CSRegistryValue -Hive HKU -SubKey "$SID\$CommonKey" -ValueName '' @CommonArgs |
                            New-AutoRunsEntry -AutoRunEntry $CommonKey.Split('\')[2] -Category $Category
                    }
                }

                Get-CSRegistryValue -Hive HKLM -SubKey SOFTWARE\Classes\exefile\shell\open\command -ValueName 'IsolatedCommand' @CommonArgs |
                    New-AutoRunsEntry -Category $Category

                $null,'Wow6432Node\' | ForEach-Object {
                    Get-CSRegistryKey -Hive HKLM -SubKey "SOFTWARE\$($_)Microsoft\Windows NT\CurrentVersion\Image File Execution Options" |
                        Get-CSRegistryValue -ValueName Debugger @CommonArgs | ForEach-Object {
                            $_ | New-AutoRunsEntry -AutoRunEntry $_.SubKey.Substring($_.SubKey.LastIndexOf('\') + 1) -Category $Category
                        }

                    Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\$($_)Microsoft\Command Processor" -ValueName 'Autorun' @CommonArgs |
                        New-AutoRunsEntry -Category $Category
                }

                $Class_exe = Get-CSRegistryValue -Hive HKLM -SubKey 'SOFTWARE\Classes\.exe' -ValueName '' -ValueType REG_SZ @CommonArgs

                if ($Class_exe.ValueContent) {
                    $OpenCommand = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\$($Class_exe.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs

                    if ($OpenCommand.ValueContent) {
                        $OpenCommand | New-AutoRunsEntry -Hive $Class_exe.Hive -SubKey $Class_exe.SubKey -AutoRunEntry $Class_exe.ValueContent -Category $Category
                    }
                }

                $Class_cmd = Get-CSRegistryValue -Hive HKLM -SubKey 'SOFTWARE\Classes\.cmd' -ValueName '' -ValueType REG_SZ @CommonArgs

                if ($Class_cmd.ValueContent) {
                    $OpenCommand = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\$($Class_cmd.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs

                    if ($OpenCommand.ValueContent) {
                        $OpenCommand | New-AutoRunsEntry -Hive $Class_cmd.Hive -SubKey $Class_cmd.SubKey -AutoRunEntry $Class_cmd.ValueContent -Category $Category
                    }
                }

                foreach ($SID in $HKUSIDs.Keys) {
                    Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Microsoft\Command Processor" -ValueName 'Autorun' @CommonArgs |
                        New-AutoRunsEntry -Category $Category

                    $Class_exe = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\.exe" -ValueName '' -ValueType REG_SZ @CommonArgs

                    if ($Class_exe.ValueContent) {
                        $OpenCommand = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\$($Class_exe.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs

                        if ($OpenCommand.ValueContent) {
                            $OpenCommand | New-AutoRunsEntry -Hive $Class_exe.Hive -SubKey $Class_exe.SubKey -AutoRunEntry $Class_exe.ValueContent -Category $Category
                        }
                    }

                    $Class_cmd = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\.cmd" -ValueName '' -ValueType REG_SZ @CommonArgs

                    if ($Class_cmd.ValueContent) {
                        $OpenCommand = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Classes\$($Class_cmd.ValueContent)\Shell\Open\Command" -ValueName '' -ValueType REG_SZ @CommonArgs

                        if ($OpenCommand.ValueContent) {
                            $OpenCommand | New-AutoRunsEntry -Hive $Class_cmd.Hive -SubKey $Class_cmd.SubKey -AutoRunEntry $Class_cmd.ValueContent -Category $Category
                        }
                    }
                }
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['AppInit']) {
                $Category = 'AppInit'

                $null,'Wow6432Node\' | ForEach-Object {
                    Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\$($_)Microsoft\Windows NT\CurrentVersion\Windows" -ValueName 'AppInit_DLLs' @CommonArgs |
                        New-AutoRunsEntry -Category $Category
                    Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\$($_)Microsoft\Command Processor" -ValueName 'Autorun' @CommonArgs |
                        New-AutoRunsEntry -Category $Category
                }

                Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' @CommonArgs |
                    New-AutoRunsEntry -Category $Category
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['KnownDLLs']) {
                $Category = 'KnownDLLs'

                Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' @CommonArgs |
                    New-AutoRunsEntry -Category $Category
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['Winlogon']) {
                $Category = 'Winlogon'

                $CmdLine = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\Setup' -ValueName 'CmdLine' @CommonArgs

                if ($CmdLine -and $CmdLine.ValueContent) {
                    $CmdLine | New-AutoRunsEntry -Category $Category
                }

                'Credential Providers', 'Credential Provider Filters', 'PLAP Providers' |
                    ForEach-Object { Get-CSRegistryKey -Hive HKLM -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\$_" @CommonArgs } | ForEach-Object {
                        $LastBSIndex = $_.SubKey.LastIndexOf('\')
                        $ParentKey = $_.SubKey.Substring(0, $LastBSIndex)
                        $Guid = $_.SubKey.Substring($LastBSIndex + 1)

                        if ($Guid -as [Guid]) {
                            $AutoRunEntry = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\CLSID\$Guid" -ValueName '' -ValueType REG_SZ @CommonArgs
                            $InprocServer32 = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Classes\CLSID\$Guid\InprocServer32" -ValueName '' -ValueType REG_EXPAND_SZ @CommonArgs

                            New-AutoRunsEntry $_.Hive $ParentKey $AutoRunEntry.ValueContent $InprocServer32.ValueContent $Category $_.PSComputerName
                        }
                    }

                $BootVer = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\BootVerificationProgram' -ValueName 'ImagePath' @CommonArgs

                if ($BootVer) {
                    $BootVer | New-AutoRunsEntry -Hive $BootVer.Hive -SubKey "$($BootVer.SubKey)\ImagePath"
                }

                foreach ($SID in $HKUSIDs.Keys) {
                    $Scrnsave = Get-CSRegistryValue -Hive HKU -SubKey "$SID\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName 'Scrnsave.exe' @CommonArgs
                    if ($Scrnsave) { $Scrnsave | New-AutoRunsEntry }

                    $Scrnsave = Get-CSRegistryValue -Hive HKU -SubKey "$SID\Control Panel\Desktop" -ValueName 'Scrnsave.exe' @CommonArgs
                    if ($Scrnsave) { $Scrnsave | New-AutoRunsEntry }
                }
            }
        }
    }
}

function Get-CSWmiPersistence {
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

    [CmdletBinding()]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN {
        if (-not $PSBoundParameters['CimSession']) {
            # i.e. Run the function locally
            $CimSession = ''
            # Trick the loop below into thinking there's at least one CimSession
            $SessionCount = 1
        } else {
            $SessionCount = $CimSession.Count
        }

        $Current = 0
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            Write-Progress -Activity 'CimSweep - WMI persistence sweep' -Status "($($Current+1)/$($SessionCount)) Current computer: $($Session.ComputerName)" -PercentComplete (($Current / $SessionCount) * 100)
            $Current++

            $CommonArgs = @{}

            if ($PSBoundParameters['CimSession']) { $CommonArgs['CimSession'] = $Session }

            Write-Verbose "[$($Session.ComputerName)] Retrieving __FilterToConsumerBinding instance."

            Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding @CommonArgs | ForEach-Object {
                Write-Verbose "[$($Session.ComputerName)] Correlating referenced __EventFilter instance."
                $Filter = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name=`"$($_.Filter.Name)`"" @CommonArgs

                $ConsumerClass = $_.Consumer.PSObject.TypeNames[0].Split('/')[-1]
                Write-Verbose "[$($Session.ComputerName)] Correlating referenced __EventConsumer instance."
                $Consumer = Get-CimInstance -Namespace root/subscription -ClassName $ConsumerClass -Filter "Name=`"$($_.Consumer.Name)`"" @CommonArgs

                [PSCustomObject] @{
                    Filter = $Filter
                    ConsumerClass = $ConsumerClass
                    Consumer = $Consumer
                    FilterToConsumerBinding = $_
                    PSComputerName = $_.PSComputerName
                }
            }
        }
    }
}