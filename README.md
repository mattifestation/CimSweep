# CimSweep
CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows. CimSweep may also be used to engage in offensive reconnaisance without the need to drop any payload to disk. Windows Management Instrumentation has been installed and its respective service running by default since Windows XP and Windows 2000 and is fully supported in the latest versions of Windows including Windows 10, Nano Server, and Server 2016.

## Background

Agent-based defensive tools are extremely powerful but they also require deployment of the agent to each system. While agent-based solutions absolutely have a place in our industry, they tend to be very expensive and can be easily detected/thwarted by determined attackers. CimSweep enables the acquisition of time-sensitive data at scale all without needing to deploy an agent.

It is called CimSweep based upon the fact that it utilizes the extremely powerful CIM cmdlets in PowerShell. CIM cmdlets support the WSMan protocol by default but it may also fall back to using DCOM on systems that either cannot support or do not have the Windows Remote Management (WinRM) service enabled. More information on the CIM cmdlets may be found here:

* [Introduction to CIM Cmdlets](https://blogs.msdn.microsoft.com/powershell/2012/08/24/introduction-to-cim-cmdlets/)
* [What is CIM and Why Should I Use It in PowerShell?](https://blogs.technet.microsoft.com/heyscriptingguy/2014/01/27/what-is-cim-and-why-should-i-use-it-in-powershell/)

One of the greatest features of the CIM cmdlets is that they allow you to establish a CIM session which can survive reboots. CIM sessions speed up remote queries and they enable an analyst to establish a session once and then can be passed around to any function that supports a -CimSession parameter - which all CimSweep functions support by design.

## Requirements

#### Analyst system
1. PowerShell version 3 or above is required. The CIM cmdlets were introduced in PSv3.
2. Elevated credentials to the target hosts. By default, all remote WMI/CIM operations require credentials for users belonging to the Administrator's group.

#### Target hosts
1. Any Windows OS dating back to Windows XP or Windows 2000.
2. The WMI service (winmgmt) must be running. It is running by default.
3. Host and network firewalls must allow remote WMI/CIM management ports through.
  * [Connecting to WMI Remotely Starting with Windows Vista](https://msdn.microsoft.com/en-us/library/windows/desktop/aa822854)
4. For systems where the WSMan protocol is desired, the WinRM service must be running. If PowerShell remoting is already enabled, the WinRM service will already be running. WinRM can be enabled locally with PowerShell or remotely in an enterprise with GPO.
  * [Enable and configure Windows PowerShell Remoting using Group Policy](https://web.archive.org/web/20150514151313/http://blog.crayon.no/blogs/janegil/archive/2010/03/04/enable_2D00_and_2D00_configure_2D00_windows_2D00_powershell_2D00_remoting_2D00_using_2D00_group_2D00_policy.aspx)
  * [WSMan service configuration using domain GPO](https://greencircle.vmturbo.com/docs/DOC-1911)
  * [WSMan Provider](https://technet.microsoft.com/en-us/library/hh847813.aspx)

CimSweep is comprised of two components: core functionality and domain specific functionality.

## Core Functionality

At its core, CimSweep makes it easy to remotely obtain the following information from any Windows operating system:

* Registry keys, values, value types, and value content with optional recursion
* Directory and file listing with optional recursion
* Event log entries
* Services
* Processes

This core functionality was designed to facilitate the development of domain-specific functionality for incident responders, hunt operators, or anyone else needing to target information remotely over WMI.

## Domain-specific Functionality

Building upon the core set of functions in CimSweep, contributors can easily write functions that enable them to obtain highly targeted information. Examples of such information would include the following:

* Attacker persistence artifacts: Run keys, start menu items, WMI persistence, etc.
* Scan for presence of known bad artifacts: i.e. sweep for known bad files, known bad registry keys/values
* Use you imagination! CimSweep enables sweeping for a multitude of forensic artifacts. Consider tools like Sysinternals Autoruns and regripper. CimSweep enables contributors to reimplement these awesome tools all without requiring pushing any tools to a target system!

## Usage

CimSweep is a PowerShell module imported using the Import-Module cmdlet. For help on importing PowerShell modules, run `Get-Help Import-Module -Full` or refer to [Importing a PowerShell Module](https://msdn.microsoft.com/en-us/library/dd878284(v=vs.85).aspx).

Once imported, you may see the exported functions by running `Get-Command -Module CimSweep`.

Detailed documentation and usage examples for each function can be found by running `Get-Help FunctionName -Full`. For example, for detailed help on Get-CSDirectoryListing, run `Get-Help Get-CSDirectoryListing -Full`.

While CimSweep functions work fine locally, it was designed to run on remote systems using CIM sessions. The [New-CimSession](https://technet.microsoft.com/en-us/library/jj590760) cmdlet is used to create CIM sessions. For more information on establishing CIM sessions, [this post](https://blogs.msdn.microsoft.com/powershell/2013/08/19/cim-cmdlets-some-tips-tricks/) is recommended.

Here is an example of my common workflow when connecting to a couple machines in my test lab:

```powershell
# Create a CIM session to my Nano Server VM.
# It's listening on WinRM (port 5985) but I could validate
# that the WinRM service is running with the following:
Test-WSMan -ComputerName nanoserver

$CimSession_Nano = New-CimSession -ComputerName nanoserver -Credential Administrator

# Create a CIM session to my Windows XP VM.
# This VM doesn't have the Windows Management Framework
# installed so I'll need to revert to using DCOM.
$SessionOption = New-CimSessionOption -Protocol Dcom
$CimSession_Winxp = New-CimSession -ComputerName winxp -Credential Administrator -SessionOption $SessionOption

# Now I can start running CimSweep commands remotely!
Get-CSRegistryValue -Hive HKLM -SubKey SOFTWARE\Microsoft\Windows\CurrentVersion\Run -CimSession $CimSession_Nano, $CimSession_Winxp
```

## Contributions and function design

I can't do this by myself! I would love to get community contributions. The only requirement imposed on writing CimSweep functions is that they implement a -CimSession parameter in order to operate on one or more remote systems.

#### Additional design considerations
1. Never rely upon hard-coded paths. e.g. Don't assume that Windows\System32 is in C:. You can often obtain correct file paths from the registry or via other WMI classes. For example, the system directory can be obtained via the SystemDirectory property of the Win32_OperatingSystem class. Another example: if you're wanting the path to a user's start menu folder, use the following registry key to obtain it: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`.
2. Try to avoid using the -Recurse switch in Get-CSDirectoryListing and Get-CSRegistryKey. Functions should return high-fidelity information as quickly as possible. i.e. Don't cast a wide net.
3. When obtaining information for user-specific registry keys/values, don't use the HKCU hive. Instead, use the HKU hive and iterate over each user SID. The Get-HKUSID helper function is designed to obtain user SIDs in the HKU hive.
