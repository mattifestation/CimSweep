Function Get-CSProxyConfig
{
    <#
    .SYNOPSIS 
    This cmdlet can be used to enumerate the target host's proxy settings.

    .DESCRIPTION
    This cmdlet can be used to enumerate the target host's proxy settings. Provide a UserName to enumerate the proxy settings through the HKU root key with the specified user's SID. 

    .PARAMETER CimSession
    CimSession to use for this function

    .PARAMETER UserName
    UserName to enumerate proxy settings for

    .EXAMPLE

    Get-CSProxyConfig -UserName bob

    Enumerate the proxy settings for bob for the localhost

    Get-CSProxyConfig -CimSession $Session

    Enumerate the proxy settings, in the user context of the specified CimSession. 
    #>

    [CmdletBinding()]
    param
    (
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("Session")]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$UserName
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
        foreach ($Session in $CimSession)
        {
            $commonArgs = @{}
            $instanceArgs = @{
                NameSpace = 'root\cimv2'
                ClassName = 'Win32_Account'
            }
            $KeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\"

            #Set the CimSession common argument if set
            if($Session.Id) {$commonArgs['CimSession'] = $Session}
            
            #If a UserName was given, map the 
            if($PSBoundParameters['UserName'])
            {
                $instanceArgs['Filter'] = "Name=`'$UserName`'"
                $SID = (Get-CimInstance @instanceArgs @commonArgs).SID 

                $KeyPath = "HKU:\$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\"
            }

            $ProxyConfig = Get-CSRegistryValue -Path $KeyPath -ValueName 'DefaultConnectionSettings' @commonArgs

            $AutoDetectProxy = $False 
            
            #If the 5th byte is even, the AutoDetectProxySetting is most likely enabled
            if ($([convert]::ToInt32($ProxyConfig.ValueContent[4], 10)) % 2 -eq 0)
            {
                $AutoDetectProxy = $True 
            }

            if($ProxyConfig.PSComputerName -eq $null) {$ProxyConfig.PSComputerName = 'localhost'}

            $ProxySettings = [PSCustomObject] [Ordered] @{
                PSComputerName = $ProxyConfig.PSComputerName
                AutoDetectProxy = $AutoDetectProxy
            }

            #Get the current Internet Settings from the registry
            $KeyPath = $KeyPath -replace "(Connections\\)",""
            $InternetSettings = [PSCustomObject] [Ordered]@{}
            Get-CSRegistryValue -Path $KeyPath @commonArgs | ForEach-Object {
                $InternetSettings | Add-Member -NotePropertyName $_.ValueName -NotePropertyValue $_.ValueContent
            }

            $ProxySettings | Add-Member -NotePropertyName "InternetSettings" -NotePropertyValue $InternetSettings

            $ProxySettings
        }
    }
}