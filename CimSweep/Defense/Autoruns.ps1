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

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $Services,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $Drivers,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $PrintMonitors,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $NetworkProviders,

        [Parameter(ParameterSetName = 'SpecificCheck')]
        [Switch]
        $BootExecute,

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

                Get-CSRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd' -ValueName StartupPrograms @CommonArgs |
                    New-AutoRunsEntry -Category $Category

                Get-CSRegistryValue -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueNameOnly @CommonArgs |
                    Where-Object { ('VmApplet', 'Userinit', 'Shell', 'TaskMan', 'AppSetup') -contains $_.ValueName } | ForEach-Object {
                        $_ | Get-CSRegistryValue | New-AutoRunsEntry -Category $Category
                    }

                # Todo: implement on domain-joined system
                <#
                'Startup', 'Shutdown', 'Logon', 'Logoff' | ForEach-Object {
                    Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Policies\Microsoft\Windows\System\Scripts'
                }
                #>

                $GPExtensionKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'
                Get-CSRegistryKey -Hive HKLM -SubKey $GPExtensionKey @CommonArgs |
                    Get-CSRegistryValue -ValueName DllName |
                        ForEach-Object { $_ | New-AutoRunsEntry -SubKey $GPExtensionKey -AutoRunEntry $_.Subkey.Split('\')[-1] -Category $Category }

                $AlternateShell = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\SafeBoot' -ValueName AlternateShell @CommonArgs

                if ($AlternateShell) { $AlternateShell | New-AutoRunsEntry -AutoRunEntry $AlternateShell.ValueContent -Category $Category }

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

                $null, 'Wow6432Node\' | ForEach-Object {
                    $InstalledComponents = "SOFTWARE\$($_)Microsoft\Active Setup\Installed Components"
                    Get-CSRegistryKey -Hive HKLM -SubKey $InstalledComponents @CommonArgs
                } | Get-CSRegistryValue -ValueName StubPath | ForEach-Object {
                    $AutoRunEntry = $_ | Get-CSRegistryValue -ValueName '' -ValueType REG_SZ

                    if ($AutoRunEntry.ValueContent) { $AutoRunEntryName = $AutoRunEntry.ValueContent } else { $AutoRunEntryName = 'n/a' }

                    $_ | New-AutoRunsEntry -SubKey $InstalledComponents -AutoRunEntry $AutoRunEntryName -Category $Category
                }

                $IconLib = Get-CSRegistryValue -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ValueName IconServiceLib @CommonArgs

                if ($IconLib) { $IconLib | New-AutoRunsEntry -SubKey "$($IconLib.SubKey)\$($IconLib.ValueName)" -AutoRunEntry $IconLib.ValueContent -Category $Category }
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['BootExecute']) {
                $Category = 'BootExecute'

                Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager' -ValueNameOnly @CommonArgs |
                    Where-Object { ('BootExecute','SetupExecute','Execute','S0InitialCommand') -contains $_.ValueName } | ForEach-Object {
                        $_ | Get-CSRegistryValue | Where-Object { $_.ValueContent.Count } |
                            ForEach-Object { $_ | New-AutoRunsEntry -ImagePath "$($_.ValueContent)" -Category $Category }
                    }

                Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control' -ValueName ServiceControlManagerExtension @CommonArgs |
                    New-AutoRunsEntry -AutoRunEntry ServiceControlManagerExtension -Category $Category
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['PrintMonitors']) {
                $Category = 'PrintMonitors'

                Get-CSRegistryKey -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Print\Monitors' @CommonArgs | Get-CSRegistryValue -ValueName Driver | ForEach-Object {
                    $_ | New-AutoRunsEntry -SubKey 'SYSTEM\CurrentControlSet\Control\Print\Monitors' -AutoRunEntry $_.SubKey.Split('\')[-1] -Category $Category
                }
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['NetworkProviders']) {
                $Category = 'NetworkProviders'

                $NetworkOrder = Get-CSRegistryValue -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -ValueName ProviderOrder @CommonArgs

                if ($NetworkOrder.ValueContent) {
                    $NetworkOrder.ValueContent.Split(',') | ForEach-Object {
                        $NetworkOrder | New-AutoRunsEntry -AutoRunEntry $_ -ImagePath $_ -Category $Category
                    }
                }
            }

            if (($PSCmdlet.ParameterSetName -ne 'SpecificCheck') -or $PSBoundParameters['Services'] -or $PSBoundParameters['Drivers']) {
                $ServiceKeys = Get-CSRegistryKey -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Services' @CommonArgs

                $ServiceKeys | Get-CSRegistryValue -ValueName 'Type' @CommonArgs | ForEach {
                    $SERVICE_KERNEL_DRIVER = 1
                    $SERVICE_FILE_SYSTEM_DRIVER = 2
                    $SERVICE_WIN32_OWN_PROCESS = 0x10
                    $SERVICE_WIN32_SHARE_PROCESS = 0x20

                    $ServiceShortName = $_.SubKey.Split('\')[-1]

                    if ($PSBoundParameters['Drivers'] -and ($_.ValueContent -eq $SERVICE_KERNEL_DRIVER -or $_.ValueContent -eq $SERVICE_FILE_SYSTEM_DRIVER)) {
                        $Category = 'Drivers'

                        $ImagePath = ($_ | Get-CSRegistryValue -ValueName ImagePath @CommonArgs).ValueContent

                        New-AutoRunsEntry HKLM 'SYSTEM\CurrentControlSet\Services' $ServiceShortName $ImagePath $Category $_.PSComputerName
                    }

                    if ($PSBoundParameters['Services']) {
                        $Category = 'Services'

                        if ($_.ValueContent -eq $SERVICE_WIN32_OWN_PROCESS) {
                            $ImagePath = ($_ | Get-CSRegistryValue -ValueName ImagePath @CommonArgs).ValueContent

                            New-AutoRunsEntry HKLM 'SYSTEM\CurrentControlSet\Services' $ServiceShortName $ImagePath $Category $_.PSComputerName
                        }

                        if ($_.ValueContent -eq $SERVICE_WIN32_SHARE_PROCESS) {
                            $SubKey = "$($_.SubKey)\Parameters"

                            $ImagePath = ($_ | Get-CSRegistryValue -SubKey $SubKey -ValueName ServiceDll @CommonArgs).ValueContent

                            New-AutoRunsEntry HKLM 'SYSTEM\CurrentControlSet\Services' $ServiceShortName $ImagePath $Category $_.PSComputerName
                        }
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

                $null, 'Wow6432Node\' | ForEach-Object {
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