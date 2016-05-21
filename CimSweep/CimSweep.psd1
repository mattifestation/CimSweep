@{
RootModule = 'CimSweep.psm1'

ModuleVersion = '0.4.1.0'

GUID = 'f347ef1c-d752-4d07-bf68-3197c0aa661a'

Author = 'Matthew Graeber'

Copyright = 'BSD 3-Clause'

Description = 'CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows. CIM/WMI obviates the need for the installation of a host-based agent. The WMI service is running by default on all versions of Windows.'

PowerShellVersion = '3.0'

# Functions to export from this module
FunctionsToExport = @(
    'Get-CSRegistryKey',
    'Get-CSRegistryValue',
    'Get-CSMountedVolumeDriveLetter',
    'Get-CSDirectoryListing',
    'Get-CSEventLog',
    'Get-CSEventLogEntry',
    'Get-CSService',
    'Get-CSProcess',
    'Get-CSEnvironmentVariable'
    'Get-CSRegistryAutoStart',
    'Get-CSScheduledTaskFile',
    'Get-CSTempFile',
    'Get-CSLowILPathFile',
    'Get-CSShellFolderPath',
    'Get-CSStartMenuEntry',
    'Get-CSTypedURL',
    'Get-CSWmiPersistence'
    'Get-CSProxyConfig'
    'Get-CSAVInfo'
    'Invoke-CSShadowCopy'
    'Enable-RDP'
)

PrivateData = @{

    PSData = @{
        Tags = @('security', 'DFIR', 'defense')

        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        ProjectUri = 'https://github.com/PowerShellMafia/CimSweep'

        ReleaseNotes = @'
0.4.1
-----
* Bigfix: Forgot to rename Set-DefaultDisplayProperty in Get-CSRegistryAutoStart.
* Enhancement: Addressed PSScriptAnalyzer warnings

0.4.0
-----
* Compatible PS Editions: Desktop, Core (i.e. Nano Server and Win 10 IoT)
* -IncludeAcl switch added to Get-CSRegistryKey and Get-CSDirectoryListing. Appending this argument will add an ACL parameter to each object returned.
* The output types of all functions are now fully and properly documented.
'@
    }

}

}
