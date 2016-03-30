function Enable-Rdp 
{
    <#
    .SYNOPSIS
    This cmdlet uses the root\CIMV2\TerminalServices Namespace to Enable RDP through a Cim Session.

    Author: Chris Ross (@xorrior)

    .DESCRIPTION
    Enable RDP via an active Cim Session

    .PARAMETER CimSession
    The CIM session to use for this cmdlet
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [Alias("Session")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    Foreach($Computer in $CimSession)
    {
        $parameters = @{
            NameSpace = 'root\CIMV2\TerminalServices'
            ClassName = 'Win32_TerminalServiceSetting'
            CimSession = $Computer
        }

        $args = @{
            AllowTSConnections = 1
            ModifyFirewallException = 1
        }

        $TsInstance = Get-CimInstance @parameters

        $result = $TsInstance | Invoke-CimMethod -MethodName 'AllowTSConnections' -Arguments $args

        if($result.ReturnValue -eq 0)
        {
            $NoForcibleLogoff = $TsInstance | Invoke-CimMethod -MethodName 'SetDisableForcibleLogoff' -Arguments @{DisableForcibleLogoff = 1}
            if($NoForcibleLogoff.ReturnValue -eq 0)
            {
                Write-Host "Enabled RDP and disabled forcible logoff"
            }

            Write-Host "Enabled RDP"
        }
    }

}