@{
RootModule = 'CimSweep.psm1'

ModuleVersion = '0.1.0.0'

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
    'Get-CSRegistryAutoStart',
    'Get-CSScheduledTaskFile',
    'Get-CSTempPathPEAndScript',
    'Get-CSLowILPathPEAndScript',
    'Get-CSShellFolderPath',
    'Get-CSStartMenuEntry',
    'Get-CSTypedURL'
)

FormatsToProcess = @(
    'ps1xml\Registry.format.ps1xml',
    'ps1xml\LogicalFile.format.ps1xml',
    'ps1xml\EventLog.format.ps1xml'
)

PrivateData = @{

    PSData = @{
        Tags = @('security', 'incident response', 'defense')

        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        ProjectUri = 'https://github.com/PowerShellMafia/CimSweep'
    }

}

}
