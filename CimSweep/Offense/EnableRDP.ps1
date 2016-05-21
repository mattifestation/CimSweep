Function Enable-RDP
{
    <#
    .SYNOPSIS
    This cmdlet uses the root\CIMV2\TerminalServices Namespace to Enable RDP through a Cim Session.

    Author: Chris Ross (@xorrior)

    .DESCRIPTION
    Enable RDP via an active Cim Session

    .PARAMETER CimSession
    The CIM session to use for this cmdlet

    .EXAMPLE

    Enable RDP locally

    Enable-Rdp 

    Enable RDP via a CimSession for a remote host

    Enable-Rdp -CimSession $RemoteSession
    #>

    [CmdletBinding()]
    param
    (
        [parameter(ValueFromPipeline = $True)]
        [Alias("Session")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession
    )

    BEGIN 
    {
        if(-not $PSBoundParameters['CimSession'])
        {
            $CimSession = ''
        }
    }

    PROCESS
    {
        Foreach ($Session in $CimSession)
        {
            $commonArgs = @{}

            $instanceArgs = @{
                NameSpace = 'root\CIMV2\TerminalServices'
                ClassName = 'Win32_TerminalServiceSetting'
            }

            $args = @{
                AllowTSConnections = [uint32]0x00000001
                ModifyFirewallException = [uint32]0x00000001
            }

            if ($Session.Id) {$commonArgs['CimSession'] = $Session}
            $TsSettings = Get-CimInstance @instanceArgs @commonArgs

            $methodArgs = @{
                InputObject = $TsSettings
                MethodName = 'SetAllowTSConnections'
                Arguments = $args
            }

            $result = Invoke-CimMethod @methodArgs
            if($result.ReturnValue -eq 0)
            {
                $methodArgs['Arguments'] = @{DisableForcibleLogoff = 1}
                $methodArgs['MethodName'] = 'SetDisableForcibleLogoff'
                $result = Invoke-CimMethod @methodArgs
                if($result.ReturnValue -eq 0)
                {
                    Write-Verbose "[+] Enabled RDP and disabled forcible logoff"
                }

                Write-Verbose "[+] Enabled RDP"
            }

            Get-CimInstance @instanceArgs @commonArgs
        }
    }
}