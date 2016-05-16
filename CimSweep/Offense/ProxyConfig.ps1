Function Get-CSProxyConfig
{
    <##>
    [CmdletBinding()]
    param
    (
        [Parameter(mandatory = $True, ValueFromPipeline = $True)]
        [Alias("Session")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [Parameter(mandatory = $False, ParameterSetName = 'UserName')]
        [string]$UserName
    )

    BEGIN {}

    PROCESS 
    {
        foreach ($Computer in $CimSession)
        {
            $KeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\"

            if($PSBoundParameters['UserName'])
            {
                $parameters = @{
                    NameSpace = 'root\CIMV2'
                    ClassName = 'Win32_UserAccount'
                    Filter = "Name=`'$UserName`'"
                    CimSession = $Computer
                }

                $SID = $(Get-CimInstance @parameters).SID
                $KeyPath = "HKU:\$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\"
            }
               
            $ProxyConfig = Get-CSRegistryValue -Path $KeyPath -ValueName "DefaultConnectionSettings"

            if($ProxyConfig -and ($([convert]::ToInt32($ProxyConfig.ValueContent[4], 10) % 2) -eq 0))
            {
                $AutoDetectProxy = $True 
            }

            $returnObject = [PSCustomObject][ordered] @{
                ComputerName = $ProxyConfig.PSComputerName
                AutoDetectProxyConfig = $AutoDetectProxy
            }

            $KeyPath = $KeyPath -replace "(Connections\\)",""
            Get-CSRegistryValue -Path $KeyPath | ForEach-Object {
                Add-Member -NotePropertyName $_.ValueName -NotePropertyValue $_.ValueContent -InputObject $returnObject
            }

            $returnObject
        }
    }

    END {}

    
}