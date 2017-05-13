#### Master
[![Build status](https://ci.appveyor.com/api/projects/status/58jy9aie7w6aac0y/branch/master?svg=true)](https://ci.appveyor.com/project/mattifestation/cimsweep/branch/master)
#### Dev
[![Build status](https://ci.appveyor.com/api/projects/status/58jy9aie7w6aac0y/branch/dev?svg=true)](https://ci.appveyor.com/project/mattifestation/cimsweep/branch/dev)

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

I can't do this by myself! I would love to get community contributions.

#### Contribution requirements
All of the following requirements will have an accompanying Pester test to ensure compliance.

1. All functions must have an OutputType attribute and an accompanying .OUTPUTS block in comment-based help. It is important to know the types of objects that a function outputs including with custom PowerShell objects. You can apply a type name to custom objects by including a PSTypeName property to each object. Custom object type names must start with CimSweep - e.g. CimSweep.RegistryKey.
2. All functions must support a -CimSession parameter along with respective .PARAMETER documentation.
3. All function names must have a "CS" noun prefix.
4. All functions must contain a .SYNOPSIS help block.
5. All functions must contain an author name in .SYNOPSIS.
6. All functions must contain a BSD license clause in .SYNOPSIS.
7. All functions must contain a .DESCRIPTION help block.
8. All functions must contain a .PARAMETER block for each defined parameter.
9. All functions must contain at lease one .EXAMPLE block.

#### Optional design considerations.
1. Your function should include a Pester test!!! How else can you be sure it works as designed and that it will be resiliant to refactoring? Without a Pester test, you'll just be left guessing as to whether or not your code will be stable in production.
2. All non-core functions should utilize Write-Progress. A progress bar can come in very handy when running a sweep across 1000 systems.
3. All error or verbose messages should include the computer name for the local or remote session. This is helpful when diagnosing issues on a large number of remote sessions.

#### Additional design considerations
1. Make as few calls to CimSweep functions/CIM cmdlets as possible! CimSweep functions must be scalable. Many of the core CimSweep functions have many parameters that can minimize WMI method calls so please utilize them. Also, if you find ways in which existing CimSweep functions can be more performant, please submit a pull request or an issue!
2. Always perform filtering prior to calling CimSweep functions/CIM cmdlets. In other words, when using CIM cmdlets, instead of filtering raw results, use the -Filter parameter to constrain WMI queries. Also, consider not returning full WMI objects if it makes sense to do so. The -Property parameter in Get-CimInstance is used to achieve this. For example, I've needed to obtain the Windows system and windows directory from Win32_OperatingSystem. So rather than getting the entire WMI object, you can run the following: `Get-CimInstance -ClassName Win32_OperatingSystem -Property SystemDirectory, WindowsDirectory`
3. Never rely upon hard-coded paths. e.g. Don't assume that Windows\System32 is in C:. You can often obtain correct file paths from the registry or via other WMI classes. For example, the system directory can be obtained via the SystemDirectory property of the Win32_OperatingSystem class. Another example: if you're wanting the path to a user's start menu folder, use the following registry key to obtain it: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`.
4. Try to avoid using the -Recurse switch in Get-CSDirectoryListing and Get-CSRegistryKey. Functions should return high-fidelity information as quickly as possible. i.e. Don't cast a wide net.
5. When obtaining information for user-specific registry keys/values, don't use the HKCU hive. Instead, use the HKU hive and iterate over each user SID. The Get-HKUSID helper function is designed to obtain user SIDs in the HKU hive.
6. Consider that there are some WMI classes/methods that don't exist in certain operating systems. For example, the GetSecurityDescriptor method present in many WMI classes does not exist in Windows XP. Also, there is a rather lengthy list of classes not yet present in Nano Server. Please consider testing across many OS versions. Ideally, CimSweep should be agnostic to operating system version. If a class or method is required that may not be available in a particular OS, perform validation using Get-CimClass in your function.
7. Don't write a CimSweep function if it's just a function wrapper for the equivalent of a one-liner. For example, if you want to get the configured time zone of a lot of systems, don't write a CimSweep function to accomplish that. Rather just run `Get-CimInstance -ClassName Win32_TimeZone`. CimSweep is designed to supplement individual calls to the CIM cmdlets.
