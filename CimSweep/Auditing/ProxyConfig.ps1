Function Get-CSProxyConfig
{
<#    
.SYNOPSIS 
Enumerates a target host's proxy settings.

Author: Chris Ross (@xorrior)
License: BSD 3-Clause

.DESCRIPTION
Get-CSProxyConfig enumerates a target host's proxy settings. Provide a user name to enumerate the proxy settings through the HKU root key with the specified user's SID. 

.PARAMETER UserName

Specifies the user name to enumerate proxy settings for.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSProxyConfig -UserName bob

Enumerate the proxy settings for bob for the localhost

Get-CSProxyConfig -CimSession $Session

Enumerate the proxy settings, in the user context of the specified CimSession.

.OUTPUTS

CimSweep.ProxyConfig
#>

    [CmdletBinding()]
    [OutputType('CimSweep.ProxyConfig')]
    param
    (
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,

        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )

    BEGIN
    {
        if(-not $PSBoundParameters['CimSession'])
        {
            $CimSession = ''
        }

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS
    {
        foreach ($Session in $CimSession)
        {
            $CommonArgs = @{}
            #Set the CimSession common argument if set
            if($Session.Id) {$CommonArgs['CimSession'] = $Session}

            $InstanceArgs = @{
                NameSpace = 'root\cimv2'
                ClassName = 'Win32_Account'
                Property = 'Name', 'SID'
            }

            $Hive = 'HKCU'
            $SubKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
            
            #If a UserName was given, map the 
            if($PSBoundParameters['UserName'])
            {
                $InstanceArgs['Filter'] = "Name=`'$UserName`'"
                $SID = (Get-CimInstance @InstanceArgs @CommonArgs).SID 

                $Hive = 'HKU'
                $SubKey = "$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
            }

            $ProxyConfig = Get-CSRegistryValue -Hive $Hive -SubKey $SubKey -ValueName 'DefaultConnectionSettings' @CommonArgs

            if (-not $ProxyConfig) { break }

            $AutoDetectProxy = $False 
            
            #If the 5th byte is even, the AutoDetectProxySetting is most likely enabled
            if (($ProxyConfig.ValueContent[4] % 2) -eq 0) { $AutoDetectProxy = $True }

            $ObjectProperties = [Ordered] @{
                PSTypeName = 'CimSweep.ProxyConfig'
                AutoDetectProxy = $AutoDetectProxy
                InternetSettings = $null
            }

            if ($Session.ComputerName) { $ObjectProperties['PSComputerName'] = $Session.ComputerName }

            $ProxySettings = [PSCustomObject] $ObjectProperties

            #Get the current Internet Settings from the registry
            $SubKey = $SubKey.TrimEnd('Connections')
            $InternetSettings = [PSCustomObject] @{}

            Get-CSRegistryValue -Hive $Hive -SubKey $SubKey @CommonArgs | ForEach-Object {
                $InternetSettings | Add-Member -NotePropertyName $_.ValueName -NotePropertyValue $_.ValueContent
            }

            $ProxySettings.InternetSettings = $InternetSettings

            $ProxySettings
        }
    }
}

Export-ModuleMember -Function Get-CSProxyConfig