function Get-CSInstalledAppCompatShimDatabase {
<#
.SYNOPSIS

List installed application compatibility databases.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-InstalledAppCompatShimDatabase lists details about all installed application compatibility databases (SDB). While WMI is unable to parse installed SDBs, Get-InstalledAppCompatShimDatabase is useful for sweeping a large amount of systems for the purposes of identifying anomolous, installed databases.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSRegistryAutoStart

Lists all installed app compat databases.

.OUTPUTS

CimSweep.AppCompatDB

Outputs objects representing the relevant information regarding installed application compatibility databases. Note: the InstallDateTime property is a UTC datet
#>

    [CmdletBinding()]
    [OutputType('CimSweep.AppCompatDB')]
    param(
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        [UInt32]
        [Alias('OT')]
        $OperationTimeoutSec
    )

    BEGIN {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0

        $Timeout = @{}
        if ($PSBoundParameters['OperationTimeoutSec']) { $Timeout['OperationTimeoutSec'] = $OperationTimeoutSec }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Installed App Compat database sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            # Collect all of the GUIDs for which each shimmed executable is associated.
            $ShimmedExecutablesTable = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom' @CommonArgs @Timeout |
                Get-CSRegistryValue -ValueNameOnly | Group-Object -Property ValueName -AsHashTable

            $InstalledSdb = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSdb' @CommonArgs @Timeout
            $CurrentSdb = 0
            
            foreach ($Database in $InstalledSdb) {
                $GUID = $Database.SubKey.Split('\')[-1]

                Write-Progress -Id 2 -ParentId 1 -Activity "Current database:" -Status "($($CurrentSdb+1)/$($InstalledSdb.Count)) $GUID" -PercentComplete (($CurrentSdb / $InstalledSdb.Count) * 100)
                $CurrentSdb++

                $DatabaseDetails = $Database | Get-CSRegistryValue | Group-Object -Property ValueName -AsHashTable

                $DatabasePath = $DatabaseDetails['DatabasePath'].ValueContent
                $DatabasePathDir = Split-Path -Path $DatabasePath -Parent
                $DatabasePathFileName = Split-Path -Path $DatabasePath -Leaf
                $DatabaseFileInfo = Get-CSDirectoryListing -DirectoryPath $DatabasePathDir -FileName $DatabasePathFileName @CommonArgs @Timeout

                $ShimmedExecutables = $ShimmedExecutablesTable["$GUID.sdb"] | ForEach-Object { $_.Subkey.Split('\')[-1] }

                $IsPresentInAddRemovePrograms = $False

                $Result = Get-CSRegistryValue -Hive HKLM -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$GUID.sdb" -ValueNameOnly @CommonArgs @Timeout

                if ($Result) {
                    $IsPresentInAddRemovePrograms = $True
                }

                $ObjectProperties = [Ordered] @{
                    PSTypeName = 'CimSweep.AppCompatDB'
                    DatabaseGUID = $GUID
                    DatabaseName = $DatabaseDetails['DatabaseDescription'].ValueContent
                    DatabasePath = $DatabasePath
                    DatabaseType = $DatabaseDetails['DatabaseType'].ValueContent
                    InstallDateTime = [DateTime]::FromFileTimeUtc($DatabaseDetails['DatabaseInstallTimeStamp'].ValueContent)
                    ShimmedExecutables = $ShimmedExecutables
                    IsPresentInAddRemovePrograms = $IsPresentInAddRemovePrograms
                    FileInfo = $DatabaseFileInfo
                }

                $DefaultProperties = 'DatabaseGUID', 'DatabaseName', 'DatabasePath', 'DatabaseType', 'InstallDateTime', 'ShimmedExecutables', 'IsPresentInAddRemovePrograms', 'FileInfo' -as [Type] 'Collections.Generic.List[String]'

                if ($Database.PSComputerName) {
                    $ObjectProperties['PSComputerName'] = $_.PSComputerName
                    $DefaultProperties.Add('PSComputerName')
                } else {
                    $ObjectProperties['PSComputerName'] = $null
                }

                $InstalledDatabase = [PSCustomObject] $ObjectProperties

                Set-DefaultDisplayProperty -InputObject $InstalledDatabase -PropertyNames $DefaultProperties

                $InstalledDatabase
            }
        }
    }
}