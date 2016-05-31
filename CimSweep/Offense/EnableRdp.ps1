Function Enable-CSRdp
{
<#
.SYNOPSIS

Enables RDP locally or via one or more remote CIM sessions.

Author: Chris Ross (@xorrior)
License: BSD 3-Clause

.DESCRIPTION

Enable-CSRdp uses the root\CIMV2\TerminalServices namespace to enable RDP locally or via one or more remote CIM sessions.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

.PARAMETER PassThru

Instructs Enable-CSRdp to return a root/CIMV2/TerminalServices/Win32_TerminalServiceSetting which can be used to confirm configured settings.

.PARAMETER Force

Bypasses confirmation dialogs.

.EXAMPLE

Enable-CSRdp

Enable RDP locally

.EXAMPLE

Enable-CSRdp -CimSession $RemoteSession

Enable RDP via a CimSession for a remote host

.OUTPUTS

Microsoft.Management.Infrastructure.CimInstance#root/CIMV2/TerminalServices/Win32_TerminalServiceSetting

If -PassThru is specified, Enable-CSRdp returns a Win32_TerminalServiceSetting instance which can be used to confirm configured settings.
#>

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#root/CIMV2/TerminalServices/Win32_TerminalServiceSetting')]
    param (
        [Switch]
        $PassThru,

        [Switch]
        $Force,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN 
    {
        if(-not $PSBoundParameters['CimSession'])
        {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }

        $ConfirmArg = @{}
        if ($PSBoundParameters['Force']) { $ConfirmArg['Confirm'] = $False }
    }

    PROCESS
    {
        Foreach ($Session in $CimSession)
        {
            $CommonArgs = @{}
            if ($Session.Id) {$CommonArgs['CimSession'] = $Session}

            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            $InstanceArgs = @{
                Namespace = 'root\CIMV2\TerminalServices'
                ClassName = 'Win32_TerminalServiceSetting'
            }
            
            $TsSettings = Get-CimInstance @InstanceArgs @CommonArgs @Timeout

            $MethodArgs = @{
                AllowTSConnections = [UInt32] 1
                ModifyFirewallException = [UInt32] 1
            }

            $MethodArgs = @{
                InputObject = $TsSettings
                MethodName = 'SetAllowTSConnections'
                Arguments = $MethodArgs
            }

            if ($Force -or $PSCmdlet.ShouldProcess($ComputerName, 'Modify Terminal Services firewall settings by calling SetAllowTSConnections')) {
                $Result = Invoke-CimMethod @MethodArgs @CommonArgs @Timeout @ConfirmArg
            }

            if($Result.ReturnValue -eq 0 -or $PSBoundParameters['WhatIf'])
            {
                $MethodArgs['Arguments'] = @{DisableForcibleLogoff = 1}
                $MethodArgs['MethodName'] = 'SetDisableForcibleLogoff'

                if ($Force -or $PSCmdlet.ShouldProcess($ComputerName, 'Disable forcible logoff by calling SetDisableForcibleLogoff')) {
                    $Result = Invoke-CimMethod @MethodArgs @CommonArgs @Timeout @ConfirmArg
                }

                if($Result.ReturnValue -eq 0)
                {
                    Write-Verbose "[$ComputerName] Enabled RDP and disabled forcible logoff"
                } else {
                    if (-not $PSBoundParameters['WhatIf']) {
                        Write-Error "[$ComputerName] SetDisableForcibleLogoff method invocation failed."
                    }
                }
            } else {
                Write-Error "[$ComputerName] SetAllowTSConnections method invocation failed."
            }

            if ($PassThru -and (-not $PSBoundParameters['WhatIf'])) {
                Get-CimInstance @InstanceArgs @CommonArgs @Timeout
            }
        }
    }
}