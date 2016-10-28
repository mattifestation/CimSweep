@{
RootModule = 'CimSweep.psm1'

ModuleVersion = '0.6.0.0'

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
    'Get-CSWmiPersistence',
    'Get-CSWmiNamespace',
    'Get-CSVulnerableServicePermission',
    'Get-CSAVInfo',
    'Get-CSProxyConfig',
    'Get-CSInstalledAppCompatShimDatabase',
    'Get-CSBitlockerKeyProtector'
)

PrivateData = @{

    PSData = @{
        Tags = @('security', 'DFIR', 'defense')

        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        ProjectUri = 'https://github.com/PowerShellMafia/CimSweep'

        ReleaseNotes = @'
0.6.0
-----
Enhancements:
* Added Get-CSInstalledAppCompatShimDatabase
* Added Get-CSBitlockerKeyProtector

Removed:
* Removed the -NoProgressBar parameter from all functions since this is what $ProgressPreference is for.
* Removed Set-DefaultDisplayProperty helper function and all calls to it. It was creating unnecessary code complexity.
* Removed -OperationTimeoutSec param from all functions. Was creating unnecessary code complexity.

0.5.1
-----
Enhancements:
* Added Get-CSAVInfo (written by @xorrior)
* Added Get-CSProxyConfig (written by @xorrior)
* Added module-wide Pester tests to ensure consistency across functions.

Removed:
* Removed the -Path parameter from Get-CSRegistryKey and Get-CSRegistryValue. -Hive should be used.

0.5.0
-----
Enhancements:
* Added Get-CSWmiNamespace
* Added Get-CSVulnerableServicePermission
* -IncludeACL added to Get-CSRegistryKey, Get-CSDirectoryListing, Get-CSService, and Get-CSWmiNamespace.
* -IncludeFileInfo added to Get-CSService. The file info returned also includes the file ACL.
* Functions that accept exact datetimes now mask off milliseconds to enable more flexible time-based sweeps with second granularity.
* Added optional -UserModeServices and -Drivers switches to Get-CSService. This is helpful if you only want drivers or only want user-mode services.

Removed:
* Dropped -Drivers and -Services from Get-CSRegistryAutoStart. Get-CSService is the ideal means of obtaining service and driver information.

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
