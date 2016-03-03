Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\CimSweep.psd1"

Remove-Module [C]imSweep
Import-Module $ModuleManifest -Force -ErrorAction Stop

$TestCimSession1 = New-CimSession -ComputerName localhost
$TestCimSession2 = New-CimSession -ComputerName localhost

$TestSessionArray = @( $TestCimSession1, $TestCimSession2 )

Describe 'Get-CSRegistryKey' {
    Context 'parameter validation' {
        It 'should throw upon not specifying a hive' {
            { Get-CSRegistryKey } | Should Throw
        }

        It 'should throw upon only specifying a CIM session' {
            { Get-CSRegistryKey -CimSession $TestCimSession1 } | Should Throw
        }

        It 'should accept a valid -Path' {
            { Get-CSRegistryKey -Path HKLM:\SOFTWARE\ } | Should Not Throw
            { Get-CSRegistryKey -Path HKLM:\SOFTWARE\ } | Should Not BeNullOrEmpty
        }

        It 'should not accept a invalid -Path' {
            { Get-CSRegistryKey -Path FOO:\SOFTWARE\ } | Should Throw
            { Get-CSRegistryKey -Path HKLM\SOFTWARE\ } | Should Throw
            { Get-CSRegistryKey -Path HKLM:SOFTWARE\ } | Should Throw
        }

        It 'should accept a valid hive and subkey' {
            { Get-CSRegistryKey -Hive HKLM -SubKey SOFTWARE } | Should Not Throw
            { Get-CSRegistryKey -Hive HKLM -SubKey SOFTWARE } | Should Not BeNullOrEmpty
        }

        It 'should not accept an unsupported hive' {
            { Get-CSRegistryKey -Hive FOO } | Should Throw
        }

        It 'should accept valid hives - HKLM, HKCU, HKU, HKCR, HKCC' {
            { Get-CSRegistryKey -Hive HKCC } | Should Not Throw
            { Get-CSRegistryKey -Hive HKCR } | Should Not Throw
            { Get-CSRegistryKey -Hive HKCU } | Should Not Throw
            { Get-CSRegistryKey -Hive HKLM } | Should Not Throw
            { Get-CSRegistryKey -Hive HKU } | Should Not Throw
        }

        It 'should accept one or more CIM sessions' {
            { Get-CSRegistryKey -Hive HKLM -CimSession $TestCimSession1 } | Should Not Throw
            { Get-CSRegistryKey -Hive HKLM -CimSession $TestSessionArray } | Should Not Throw
            { Get-CSRegistryKey -Hive HKLM -CimSession $TestCimSession1 } | Should Not BeNullOrEmpty
            { Get-CSRegistryKey -Hive HKLM -CimSession $TestSessionArray } | Should Not BeNullOrEmpty
        }

        It 'should accept -OperationTimeoutSec' {
            { Get-CSRegistryKey -Hive HKLM -OperationTimeoutSec 3 } | Should Not Throw
            { Get-CSRegistryKey -Hive HKLM -OperationTimeoutSec 3 -CimSession $TestCimSession1 } | Should Not Throw
        }
    }

    Context 'expected behavior' {
        It 'should recurse one subkey when piped to itself' {
            # Validate that there is a larger amount of results
            $RootKeys = Get-CSRegistryKey -Hive HKLM
            $RootKeyCount = $RootKeys.Count

            $SubKeys = $RootKeys | Get-CSRegistryKey

            $SubKeys.Count -gt $RootKeyCount | Should Be $True
        }

        It 'should recurse two subkeys when piped to itself twice' {
            # Validate that there is a larger amount of results
            $RootKeys = Get-CSRegistryKey -Hive HKLM
            $RootKeyCount = $RootKeys.Count

            $SubKeys1 = $RootKeys | Get-CSRegistryKey
            $SubKeys2 = $SubKeys1 | Get-CSRegistryKey

            $SubKeys1.Count -gt $RootKeyCount | Should Be $True
            $SubKeys2.Count -gt $SubKeys1.Count | Should Be $True
        }

        It 'should recurse with the -Recurse flag' {
            $Results = Get-CSRegistryKey -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Services' -Recurse |
                Select-Object -First 20

            $Results.Count -gt 1 | Should Be $True

            # Validate that a subkey was retrieved
            $Results[0].SubKey.EndsWith('Services') | Should Be $False
        }

        It 'should accept multiple CIM sessions' {
            $Results1 = Get-CSRegistryKey -Hive HKLM -CimSession $TestCimSession1
            $Results2 = Get-CSRegistryKey -Hive HKLM -CimSession $TestCimSession2
            $Results3 = Get-CSRegistryKey -Hive HKLM -CimSession $TestSessionArray

            $Results3.Count -eq ($Results1.Count + $Results2.Count) | Should Be $True
        }
    }

    Context 'return value validation' {
        It 'should return a properly typed PSObject - CimSweep.RegistryKey' {
            $Result = Get-CSRegistryKey -Hive HKLM
            
            $Result[0].PSObject.TypeNames[0] | Should BeExactly 'CimSweep.RegistryKey'
        }

        It 'should return a computer name when using a CIM session' {
            $Results = Get-CSRegistryKey -Hive HKLM -CimSession $TestCimSession1

            $UniqueComputerNames = @($Results.PSComputerName | Sort-Object -Unique)

            $UniqueComputerNames.Count | Should Be 1
            $UniqueComputerNames | Should BeExactly 'localhost'
        }

        It 'should not return a computer name when not using a CIM session' {
            $Results = Get-CSRegistryKey -Hive HKLM

            $UniqueComputerNames = @($Results.PSComputerName | Sort-Object -Unique)

            $UniqueComputerNames | Should BeNullOrEmpty
        }

        It 'should return nothing upon querying a nonexistent key' {
            Get-CSRegistryKey -Hive HKCU -SubKey 'nonexistentkey' | Should BeNullOrEmpty
        }

        It 'should return the same output for -SubKey and -Path' {
            $Result1 = Get-CSRegistryKey -Hive HKLM
            $Result2 = Get-CSRegistryKey -Path HKLM:\

            for ($i = 0; $i -lt $Result1.Count; $i++) {
                $Result1[$i].SubKey -eq $Result2[$i].SubKey | Should Be $True
            }
        }
    }
}

Describe 'Get-CSRegistryValue' {
    $CurrentVersionPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    Context 'parameter validation' {
        It 'should accept a valid -Path' {
            { Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" } | Should Not Throw
            { Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" } | Should Not BeNullOrEmpty
        }

        It 'should not accept a invalid -Path' {
            { Get-CSRegistryValue -Path "FOO:\$CurrentVersionPath" } | Should Throw
            { Get-CSRegistryValue -Path "HKLM\$CurrentVersionPath" } | Should Throw
            { Get-CSRegistryValue -Path "HKLM:$CurrentVersionPath" } | Should Throw
        }

        It 'should accept a valid hive and subkey' {
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath } | Should Not Throw
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath } | Should Not BeNullOrEmpty
        }

        It 'should not accept an unsupported hive' {
            { Get-CSRegistryValue -Hive FOO -SubKey $CurrentVersionPath } | Should Throw
        }

        It 'should accept one or more CIM sessions' {
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -CimSession $TestCimSession1 } | Should Not Throw
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -CimSession $TestSessionArray } | Should Not Throw
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -CimSession $TestCimSession1 } | Should Not BeNullOrEmpty
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -CimSession $TestSessionArray } | Should Not BeNullOrEmpty
        }

        It 'should accept -OperationTimeoutSec' {
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -OperationTimeoutSec 3 } | Should Not Throw
            { Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -OperationTimeoutSec 3 -CimSession $TestCimSession1 } | Should Not Throw
        }
    }

    Context 'expected behavior' {
        It 'should return value contents for an entire subkey: using -Hive and -SubKey w/ no CIM Session' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents for an entire subkey: using -Path w/ no CIM Session' {
            $Result = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath"

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents for an entire subkey: using -Hive and -SubKey w/ CIM Sessions' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -CimSession $TestCimSession1

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents for an entire subkey: using -Path w/ CIM Sessions' {
            $Result = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -CimSession $TestCimSession1

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents for a specific subkey value: using -Hive and -SubKey w/ no CIM Session' {
            $CurrentVersion = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueName CurrentVersion -ValueType REG_SZ

            $CurrentVersion | Should Not BeNullOrEmpty

            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents for a specific subkey value: using -Path w/ no CIM Session' {
            $CurrentVersion = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueName CurrentVersion -ValueType REG_SZ

            $CurrentVersion | Should Not BeNullOrEmpty

            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents for a specific subkey value: using -Hive and -SubKey w/ CIM Sessions' {
            $CurrentVersion = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueName CurrentVersion -ValueType REG_SZ -CimSession $TestCimSession1

            $CurrentVersion | Should Not BeNullOrEmpty

            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents for a specific subkey value: using -Path w/ CIM Sessions' {
            $CurrentVersion = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueName CurrentVersion -ValueType REG_SZ -CimSession $TestCimSession1

            $CurrentVersion | Should Not BeNullOrEmpty

            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return only value names for an entire subkey: using -Hive and -SubKey w/ no CIM Session' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueNameOnly

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return only value names for an entire subkey: using -Path w/ no CIM Session' {
            $Result = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueNameOnly

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return only value names for an entire subkey: using -Hive and -SubKey w/ CIM Sessions' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueNameOnly -CimSession $TestCimSession1

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return only value names for an entire subkey: using -Path w/ CIM Sessions' {
            $Result = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueNameOnly -CimSession $TestCimSession1

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving value names over the pipeline (from Get-CSRegistryValue) for an entire subkey: using -Hive and -SubKey w/ no CIM Session' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueNameOnly | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving value names over the pipeline (from Get-CSRegistryValue) for an entire subkey: using -Path w/ no CIM Session' {
            $Result = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueNameOnly | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving value names over the pipeline (from Get-CSRegistryValue) for an entire subkey: using -Hive and -SubKey w/ CIM Sessions' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueNameOnly -CimSession $TestCimSession1 | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving value names over the pipeline (from Get-CSRegistryValue) for an entire subkey: using -Path w/ CIM Sessions' {
            $Result = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueNameOnly -CimSession $TestCimSession1 | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving a value name over the pipeline (from Get-CSRegistryValue) for a specific subkey value: using -Hive and -SubKey w/ no CIM Session' {
            $CurrentVersion = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueName CurrentVersion | Get-CSRegistryValue

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving a value name over the pipeline (from Get-CSRegistryValue) for a specific subkey value: using -Path w/ no CIM Session' {
            $CurrentVersion = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueName CurrentVersion | Get-CSRegistryValue

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving a value name over the pipeline (from Get-CSRegistryValue) for a specific subkey value: using -Hive and -SubKey w/ CIM Sessions' {
            $CurrentVersion = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueName CurrentVersion -CimSession $TestCimSession1 | Get-CSRegistryValue

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving a value name over the pipeline (from Get-CSRegistryValue) for a specific subkey value: using -Path w/ CIM Sessions' {
            $CurrentVersion = Get-CSRegistryValue -Path "HKLM:\$CurrentVersionPath" -ValueName CurrentVersion -CimSession $TestCimSession1 | Get-CSRegistryValue

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Hive and -SubKey w/ no CIM Session' {
            $Result = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT' | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Path w/ no CIM Session' {
            $Result = Get-CSRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT' | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Hive and -SubKey w/ CIM Sessions' {
            $Result = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT' -CimSession $TestCimSession1 | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Path w/ CIM Sessions' {
            $Result = Get-CSRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT' -CimSession $TestCimSession1 | Get-CSRegistryValue

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for a specific subkey value: using -Hive and -SubKey w/ no CIM Session' {
            $CurrentVersion = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT' | Get-CSRegistryValue -ValueName CurrentVersion

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for a specific subkey value: using -Path w/ no CIM Session' {
            $CurrentVersion = Get-CSRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT' | Get-CSRegistryValue -ValueName CurrentVersion

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for a specific subkey value: using -Hive and -SubKey w/ CIM Sessions' {
            $CurrentVersion = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT' -CimSession $TestCimSession1 | Get-CSRegistryValue -ValueName CurrentVersion

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value contents via receiving subkeys over the pipeline (from Get-CSRegistryKey) for a specific subkey value: using -Path w/ CIM Sessions' {
            $CurrentVersion = Get-CSRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT' -CimSession $TestCimSession1 | Get-CSRegistryValue -ValueName CurrentVersion

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should Not BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value names only via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Hive and -SubKey w/ no CIM Session' {
            $Result = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT' | Get-CSRegistryValue -ValueNameOnly

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value names only via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Path w/ no CIM Session' {
            $Result = Get-CSRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT' | Get-CSRegistryValue -ValueNameOnly

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return value names only via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Hive and -SubKey w/ CIM Sessions' {
            $Result = Get-CSRegistryKey -Hive HKLM -SubKey 'SOFTWARE\Microsoft\Windows NT' -CimSession $TestCimSession1 | Get-CSRegistryValue -ValueNameOnly

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }

        It 'should return value names only via receiving subkeys over the pipeline (from Get-CSRegistryKey) for an entire subkey: using -Path w/ CIM Sessions' {
            $Result = Get-CSRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT' -CimSession $TestCimSession1 | Get-CSRegistryValue -ValueNameOnly

            $CurrentVersion = $Result | Where-Object { $_.ValueName -eq 'CurrentVersion' }

            $CurrentVersion | Should Not BeNullOrEmpty
            $CurrentVersion.ValueContent | Should BeNullOrEmpty

            $CurrentVersion.PSComputerName | Should BeExactly 'localhost'
        }
    }

    Context 'return value validation' {
        It 'should return a properly typed PSObject - CimSweep.RegistryValue' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueName CurrentVersion
            
            $Result[0].PSObject.TypeNames[0] | Should BeExactly 'CimSweep.RegistryValue'
        }

        It 'should return the expected output' {
            $Result = Get-CSRegistryValue -Hive HKLM -SubKey $CurrentVersionPath -ValueName CurrentVersion

            $Result.Hive | Should BeExactly 'HKLM'
            $Result.SubKey | Should BeExactly $CurrentVersionPath
            $Result.ValueName | Should BeExactly 'CurrentVersion'
            $Result.ValueContent | Should Not BeNullOrEmpty
            $Result.PSComputerName | Should BeNullOrEmpty
        }

        It 'should return no results when specifying a key that should not have any values' {
            Get-CSRegistryValue -Hive HKLM | Should BeNullOrEmpty
        }
    }
}

Describe 'Get-CSEventLog' {
    It 'should return output' {
        $Result = Get-CSEventLog -NoProgressBar | Select -First 1

        $Result.LogName | Should Not BeNullOrEmpty
        $Result.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return output with CIM sessions' {
        $Result = Get-CSEventLog -NoProgressBar -CimSession $TestSessionArray | Select -First 1

        $Result.LogName | Should Not BeNullOrEmpty
        $Result.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return output and accept -OperationTimeoutSec' {
        $Result = Get-CSEventLog -NoProgressBar -OperationTimeoutSec 3 | Select -First 1

        $Result.LogName | Should Not BeNullOrEmpty
        $Result.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return output with CIM sessions and accept -OperationTimeoutSec' {
        $Result = Get-CSEventLog -NoProgressBar -CimSession $TestSessionArray -OperationTimeoutSec 3 | Select -First 1

        $Result.LogName | Should Not BeNullOrEmpty
        $Result.PSComputerName | Should BeExactly 'localhost'
    }
}

Describe 'Get-CSEventLogEntry' {
    It 'should return nothing upon receiving an undefined entry type' {
        { Get-CSEventLogEntry -EntryType Undefined -NoProgressBar } | Should Throw
    }

    It 'should accept all valid event entry types' {
        { Get-CSEventLogEntry -EntryType Error -NoProgressBar | Select-Object -First 1 } | Should Not Throw
        { Get-CSEventLogEntry -EntryType Warning -CimSession $TestCimSession1 -NoProgressBar | Select-Object -First 1 } | Should Not Throw
    }

    It 'should return Win32_NtLogEvent instances' {
        $Event = Get-CSEventLogEntry -NoProgressBar | Select-Object -First 1
        $Event.PSObject.TypeNames[0].Contains('Win32_NTLogEvent') | Should Be $True
    }

    It 'should return nothing when it receives a non-existent LogName' {
        Get-CSEventLogEntry -LogName NonExistentLog -NoProgressBar | Should BeNullOrEmpty
    }

    It 'should return results when no LogName is specified (i.e. all logs implied)' {
        $SystemEvent = Get-CSEventLogEntry -NoProgressBar | Select-Object -First 1
        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should Not BeNullOrEmpty
        $SystemEvent.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return results when no LogName is specified (i.e. all logs implied) w/ CIM sessions' {
        $SystemEvent = Get-CSEventLogEntry -CimSession $TestCimSession1 -NoProgressBar | Select-Object -First 1
        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should Not BeNullOrEmpty
        $SystemEvent.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a System log entry' {
        $SystemEvent = Get-CSEventLogEntry -LogName System -NoProgressBar | Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should BeExactly 'System'
        $SystemEvent.PSComputerName | Should BeNullOrEmpty
    }

    It 'should accept output from Get-CSEventLog' {
        $SystemEvent = Get-CSEventLog -NoProgressBar |
            Where-Object { $_.LogName -eq 'System' } |
                Get-CSEventLogEntry -NoProgressBar | Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should BeExactly 'System'
        $SystemEvent.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a System log entry w/ CIM sessions' {
        $SystemEvent = Get-CSEventLogEntry -LogName System -CimSession $TestCimSession1 -NoProgressBar |
            Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should BeExactly 'System'
        $SystemEvent.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should accept output from Get-CSEventLog w/ CIM sessions' {
        $SystemEvent = Get-CSEventLog -CimSession $TestCimSession1 -NoProgressBar |
            Where-Object { $_.LogName -eq 'System' } |
                Get-CSEventLogEntry -NoProgressBar | Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should BeExactly 'System'
        $SystemEvent.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a System log entry with stripped properties when -LimitOutput is provided' {
        $SystemEvent = Get-CSEventLogEntry -LogName System -LimitOutput -NoProgressBar |
            Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should BeExactly 'System'
        $SystemEvent.Message | Should Not BeNullOrEmpty
        $SystemEvent.TimeWritten | Should BeNullOrEmpty
        $SystemEvent.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a log entry with only the LogFile property present' {
        $SystemEvent = Get-CSEventLogEntry -Property Logfile -NoProgressBar |
            Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should Not BeNullOrEmpty
        $SystemEvent.Message | Should BeNullOrEmpty
        $SystemEvent.TimeWritten | Should BeNullOrEmpty
        $SystemEvent.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a log entry with only the LogFile property present w/ CIM sessions' {
        $SystemEvent = Get-CSEventLogEntry -Property Logfile -CimSession $TestCimSession1 -NoProgressBar |
            Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should Not BeNullOrEmpty
        $SystemEvent.Message | Should BeNullOrEmpty
        $SystemEvent.TimeWritten | Should BeNullOrEmpty
        $SystemEvent.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a System log entry with stripped properties when -LimitOutput is provided w/ CIM sessions' {
        $SystemEvent = Get-CSEventLogEntry -LogName System -CimSession $TestCimSession1 -LimitOutput -NoProgressBar |
            Select-Object -First 1

        $SystemEvent | Should Not BeNullOrEmpty
        $SystemEvent.LogFile | Should BeExactly 'System'
        $SystemEvent.Message | Should Not BeNullOrEmpty
        $SystemEvent.TimeWritten | Should BeNullOrEmpty
        $SystemEvent.PSComputerName | Should BeExactly 'localhost'
    }
}

Describe 'Get-CSMountedVolumeDriveLetter' {
    It 'should return at least one mounted partition' {
        $Drive = Get-CSMountedVolumeDriveLetter | Select-Object -First 1

        $Drive | Should Not BeNullOrEmpty
        $Drive.DriveLetter | Should Match '^[A-Z]$'
        $Drive.DirectoryPath | Should Match "^$($Drive.DriveLetter):\\`$"
        $Drive.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return at least one mounted partition w/ CIM sessions' {
        $Drive = Get-CSMountedVolumeDriveLetter -CimSession $TestCimSession1 | Select-Object -First 1

        $Drive | Should Not BeNullOrEmpty
        $Drive.DriveLetter | Should Match '^[A-Z]$'
        $Drive.DirectoryPath | Should Match "^$($Drive.DriveLetter):\\`$"
        $Drive.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should accept -OperationTimeoutSec' {
        $Drive = Get-CSMountedVolumeDriveLetter -OperationTimeoutSec 3 | Select-Object -First 1

        $Drive | Should Not BeNullOrEmpty
        $Drive.DriveLetter | Should Match '^[A-Z]$'
        $Drive.DirectoryPath | Should Match "^$($Drive.DriveLetter):\\`$"
        $Drive.PSComputerName | Should BeNullOrEmpty
    }
}

Describe 'Get-CSDirectoryListing' {
    $WMIBaseType = 'Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/CIM_LogicalFile'
    $DirectoryType = 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Directory'
    $FileType = 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/CIM_DataFile'

    # Don't assume that C: exists.
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property SystemDirectory, WindowsDirectory
    $SystemDirectory = $OSInfo.SystemDirectory
    # e.g. C:\WINDOWS -> C:\
    $BootPartitionRoot = $OSInfo.WindowsDirectory.Substring(0, $OSInfo.WindowsDirectory.IndexOf('\')+1)

    It 'should perform a file/directory listing of all mounted partitions with no arguments provided' {
        $Listing = Get-CSDirectoryListing | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should perform a file/directory listing of all mounted partitions with no arguments provided w/ CIM sessions' {
        $Listing = Get-CSDirectoryListing -CimSession $TestCimSession1 | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should accept input from Get-CSMountedVolumeDriveLetter' {
        $Listing = Get-CSMountedVolumeDriveLetter | Get-CSDirectoryListing | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should accept input from Get-CSMountedVolumeDriveLetter w/ CIM sessions' {
        $Listing = Get-CSMountedVolumeDriveLetter -CimSession $TestCimSession1 | Get-CSDirectoryListing | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should list files/directories from the primary boot partition' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $BootPartitionRoot | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should list files/directories from the primary boot partition w/ CIM sessions' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $BootPartitionRoot -CimSession $TestCimSession1 | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should list only directories from the primary boot partition' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $BootPartitionRoot -Directory | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $DirectoryType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should list only directories from the primary boot partition w/ CIM sessions' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $BootPartitionRoot -CimSession $TestCimSession1 -Directory | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $DirectoryType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should recurse one folder deep by piping output to itself' {
        $ConfigDir = Get-CSDirectoryListing -DirectoryPath $SystemDirectory -Directory | Where-Object { $_.Name -eq "$SystemDirectory\config" }
        $ConfigDirListing = $ConfigDir | Get-CSDirectoryListing | Select-Object -First 1

        $ConfigDirListing | Should Not BeNullOrEmpty
        $ConfigDirListing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $ConfigDirListing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should recurse one folder deep by piping output to itself w/ CIM sessions' {
        $ConfigDir = Get-CSDirectoryListing -DirectoryPath $SystemDirectory -Directory -CimSession $TestCimSession1 | Where-Object { $_.Name -eq "$SystemDirectory\config" }
        $ConfigDirListing = $ConfigDir | Get-CSDirectoryListing | Select-Object -First 1

        $ConfigDirListing | Should Not BeNullOrEmpty
        $ConfigDirListing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $ConfigDirListing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should recurse' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $BootPartitionRoot -Recurse | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should recurse w/ CIM sessions' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $BootPartitionRoot -Recurse -CimSession $TestCimSession1 | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $WMIBaseType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should list files of the specified extension' {
        $Listing = Get-CSDirectoryListing $SystemDirectory -Extension dll | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.Extension | Should BeExactly 'dll'
        $Listing.PSObject.TypeNames -contains $FileType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should list files of the specified extension w/ CIM sessions' {
        $Listing = Get-CSDirectoryListing $SystemDirectory -Extension dll -CimSession $TestCimSession1 | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.Extension | Should BeExactly 'dll'
        $Listing.PSObject.TypeNames -contains $FileType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return output for a known DLL - ntdll.dll' {
        $Listing = Get-CSDirectoryListing $SystemDirectory -FileName ntdll.dll
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $FileType | Should Be $True
        $Listing.Extension | Should BeExactly 'dll'
        $Listing.FileName | Should BeExactly 'ntdll'
        $Listing.Name.ToLower() | Should BeExactly "$SystemDirectory\ntdll.dll".ToLower()
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return output for a known DLL - ntdll.dll w/ CIM sessions' {
        $Listing = Get-CSDirectoryListing $SystemDirectory -FileName ntdll.dll -CimSession $TestCimSession1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $FileType | Should Be $True
        $Listing.Extension | Should BeExactly 'dll'
        $Listing.FileName | Should BeExactly 'ntdll'
        $Listing.Name.ToLower() | Should BeExactly "$SystemDirectory\ntdll.dll".ToLower()
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return only files with -File' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $SystemDirectory -File | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $FileType | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return only files with -File w\ CIM sessions' {
        $Listing = Get-CSDirectoryListing -DirectoryPath $SystemDirectory -File -CimSession $TestCimSession1 | Select-Object -First 1
        $Listing | Should Not BeNullOrEmpty
        $Listing.PSObject.TypeNames -contains $FileType | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should match on exact and bounded creation times' {
        $TempFile = [IO.Path]::GetTempFileName().ToLower()
        'test' | Out-File $TempFile

        $TempFileDir = Split-Path $TempFile -Parent
        $TempFileName = Split-Path $TempFile -Leaf

        $TempFileDetails = Get-ChildItem $TempFile

        $TempFile | Should Exist

        # Exact time match
        $Listing = Get-CSDirectoryListing -DirectoryPath $TempFileDir -FileName $TempFileName -CreationDate $TempFileDetails.CreationTime
        $Listing | Should Not BeNullOrEmpty
        $Listing.Name.ToLower() | Should BeExactly $TempFile
        # For some reason, I have found there to be a single tick discrepancy. :/
        $Listing.CreationDate.DateTime -eq $TempFileDetails.CreationTime.DateTime | Should Be $True
        $Listing.PSComputerName | Should BeNullOrEmpty

        # Bounded time match
        $Creation1SecBefore = $TempFileDetails.CreationTime.AddSeconds(-1)
        $Creation1SecAfter = $TempFileDetails.CreationTime.AddSeconds(1)
        $Listing = Get-CSDirectoryListing -DirectoryPath $TempFileDir -FileName $TempFileName -CreationDateBefore $Creation1SecAfter -CreationDateAfter $Creation1SecBefore
        $Listing | Should Not BeNullOrEmpty
        $Listing.Name.ToLower() | Should BeExactly $TempFile
        $Listing.PSComputerName | Should BeNullOrEmpty

        Remove-Item -Path $TempFile
    }

    It 'should match on an exact file size' {
        $TempFile = [IO.Path]::GetTempFileName().ToLower()
        $FileBytes = @(0x41, 0x41, 0x41, 0x41)
        [IO.File]::WriteAllBytes($TempFile, $FileBytes)

        $TempFileDir = Split-Path $TempFile -Parent
        $TempFileName = Split-Path $TempFile -Leaf

        $TempFileDetails = Get-ChildItem $TempFile

        $TempFile | Should Exist
        $FileContents = Get-Content $TempFile
        $FileContents | Should BeExactly ([Text.Encoding]::ASCII.GetString($FileBytes))

        # Exact file size
        $Listing = Get-CSDirectoryListing -DirectoryPath $TempFileDir -FileName $TempFileName -FileSize $FileBytes.Length
        $Listing | Should Not BeNullOrEmpty
        $Listing.Name.ToLower() | Should BeExactly $TempFile
        $Listing.FileSize | Should BeExactly $FileBytes.Length
        $Listing.PSComputerName | Should BeNullOrEmpty

        Remove-Item -Path $TempFile
    }

    It 'should match on exact and bounded creation times w/ CIM sessions' {
        $TempFile = [IO.Path]::GetTempFileName().ToLower()
        'test' | Out-File $TempFile

        $TempFileDir = Split-Path $TempFile -Parent
        $TempFileName = Split-Path $TempFile -Leaf

        $TempFileDetails = Get-ChildItem $TempFile

        $TempFile | Should Exist

        # Exact time match
        $Listing = Get-CSDirectoryListing -DirectoryPath $TempFileDir -FileName $TempFileName -CreationDate $TempFileDetails.CreationTime -CimSession $TestCimSession1
        $Listing | Should Not BeNullOrEmpty
        $Listing.Name.ToLower() | Should BeExactly $TempFile
        # For some reason, I have found there to be a single tick discrepancy. :/
        $Listing.CreationDate.DateTime -eq $TempFileDetails.CreationTime.DateTime | Should Be $True
        $Listing.PSComputerName | Should BeExactly 'localhost'

        # Bounded time match
        $Creation1SecBefore = $TempFileDetails.CreationTime.AddSeconds(-1)
        $Creation1SecAfter = $TempFileDetails.CreationTime.AddSeconds(1)
        $Listing = Get-CSDirectoryListing -DirectoryPath $TempFileDir -FileName $TempFileName -CreationDateBefore $Creation1SecAfter -CreationDateAfter $Creation1SecBefore -CimSession $TestCimSession1
        $Listing | Should Not BeNullOrEmpty
        $Listing.Name.ToLower() | Should BeExactly $TempFile
        $Listing.PSComputerName | Should BeExactly 'localhost'

        Remove-Item -Path $TempFile
    }

    It 'should match on an exact file size w/ CIM sessions' {
        $TempFile = [IO.Path]::GetTempFileName().ToLower()
        $FileBytes = @(0x41, 0x41, 0x41, 0x41)
        [IO.File]::WriteAllBytes($TempFile, $FileBytes)

        $TempFileDir = Split-Path $TempFile -Parent
        $TempFileName = Split-Path $TempFile -Leaf

        $TempFileDetails = Get-ChildItem $TempFile

        $TempFile | Should Exist
        $FileContents = Get-Content $TempFile
        $FileContents | Should BeExactly ([Text.Encoding]::ASCII.GetString($FileBytes))

        # Exact file size
        $Listing = Get-CSDirectoryListing -DirectoryPath $TempFileDir -FileName $TempFileName -FileSize $FileBytes.Length -CimSession $TestCimSession1
        $Listing | Should Not BeNullOrEmpty
        $Listing.Name.ToLower() | Should BeExactly $TempFile
        $Listing.FileSize | Should BeExactly $FileBytes.Length
        $Listing.PSComputerName | Should BeExactly 'localhost'

        Remove-Item -Path $TempFile
    }
}

Describe 'Get-CSService' {
    $BaseServiceWMIType = 'Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/Win32_BaseService'
    $Win32ServiceType = 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Service'
    $Win32SystemDriverType = 'Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_SystemDriver'

    It 'should return Win32_BaseService instances' {
        $Service = Get-CSService -NoProgressBar | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return Win32_BaseService instances w/ CIM sessions' {
        $Service = Get-CSService -NoProgressBar -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return kernel driver instances' {
        $Service = Get-CSService -NoProgressBar -ServiceType 'Kernel Driver' | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $Win32SystemDriverType | Should Be $True
        $Service.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return kernel driver instances w/ CIM sessions' {
        $Service = Get-CSService -NoProgressBar -ServiceType 'Kernel Driver' -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $Win32SystemDriverType | Should Be $True
        $Service.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return user mode service instances' {
        $Service = Get-CSService -NoProgressBar -ServiceType 'Share Process' | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $Win32ServiceType | Should Be $True
        $Service.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return user mode service instances w/ CIM sessions' {
        $Service = Get-CSService -NoProgressBar -ServiceType 'Share Process' -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $Win32ServiceType | Should Be $True
        $Service.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a running service' {
        $Service = Get-CSService -NoProgressBar -State Running | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.State | Should BeExactly 'Running'
        $Service.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a running service w/ CIM sessions' {
        $Service = Get-CSService -NoProgressBar -State Running -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.State | Should BeExactly 'Running'
        $Service.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should limit the output of its properties to a default set' {
        $Service = Get-CSService -NoProgressBar -LimitOutput | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.StartMode | Should BeNullOrEmpty
        $Service.PSComputerName | Should BeNullOrEmpty

        $Service = Get-CSService -NoProgressBar | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.StartMode | Should Not BeNullOrEmpty
        $Service.PSComputerName | Should BeNullOrEmpty
    }

    It 'should limit the output of its properties to a default set w/ CIM sessions' {
        $Service = Get-CSService -NoProgressBar -LimitOutput -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.StartMode | Should BeNullOrEmpty
        $Service.PSComputerName | Should BeExactly 'localhost'

        $Service = Get-CSService -NoProgressBar -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.StartMode | Should Not BeNullOrEmpty
        $Service.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should only include the specified property' {
        $Service = Get-CSService -NoProgressBar -Property Name | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.Name | Should Not BeNullOrEmpty
        $Service.StartMode | Should BeNullOrEmpty
        $Service.PSComputerName | Should BeNullOrEmpty
    }

    It 'should only include the specified property w/ CIM sessions' {
        $Service = Get-CSService -NoProgressBar -Property Name -CimSession $TestCimSession1 | Select-Object -First 1
        $Service | Should Not BeNullOrEmpty
        $Service.PSObject.TypeNames -contains $BaseServiceWMIType | Should Be $True
        $Service.Name | Should Not BeNullOrEmpty
        $Service.StartMode | Should BeNullOrEmpty
        $Service.PSComputerName | Should BeExactly 'localhost'
    }
}

Describe 'Get-CSProcess' {
    $ProcessWMIType = 'Microsoft.Management.Infrastructure.CimInstance#ROOT/cimv2/Win32_Process'

    It 'should return nothing when a nonexistent process name is specified' {
        Get-CSProcess -Name nonexistentprocess | Should BeNullOrEmpty
    }

    It 'should return nothing when a nonexistent process name is specified w/ CIM sessions' {
        Get-CSProcess -Name nonexistentprocess -CimSession $TestCimSession1 | Should BeNullOrEmpty
    }

    It 'should return the system process' {
        $Process = Get-CSProcess -NoProgressBar -Name System -ProcessID 4 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.Name | Should BeExactly 'System'
        $Process.ProcessId | Should BeExactly 4
        $Process.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return the system process w/ CIM sessions' {
        $Process = Get-CSProcess -NoProgressBar -Name System -ProcessID 4 -CimSession $TestCimSession1 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.Name | Should BeExactly 'System'
        $Process.ProcessId | Should BeExactly 4
        $Process.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a child process of the system process' {
        # This should always be smss.exe
        $Process = Get-CSProcess -NoProgressBar -ParentProcessId 4 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a child process of the system process w/ CIM sessions' {
        # This should always be smss.exe
        $Process = Get-CSProcess -NoProgressBar -ParentProcessId 4 -CimSession $TestCimSession1 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a process instance' {
        $Process = Get-CSProcess -NoProgressBar | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a process instance w/ CIM sessions' {
        $Process = Get-CSProcess -NoProgressBar -CimSession $TestCimSession1 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should limit the output of its properties to a default set' {
        $Process = Get-CSProcess -NoProgressBar -LimitOutput | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.VM | Should BeNullOrEmpty
        $Process.Name | Should Not BeNullOrEmpty
        $Process.PSComputerName | Should BeNullOrEmpty

        $Process = Get-CSProcess -NoProgressBar | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.VM | Should Not BeNullOrEmpty
        $Process.Name | Should Not BeNullOrEmpty
        $Process.PSComputerName | Should BeNullOrEmpty
    }

    It 'should limit the output of its properties to a default set w/ CIM sessions' {
        $Process = Get-CSProcess -NoProgressBar -LimitOutput -CimSession $TestCimSession1 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.VM | Should BeNullOrEmpty
        $Process.Name | Should Not BeNullOrEmpty
        $Process.PSComputerName | Should BeExactly 'localhost'

        $Process = Get-CSProcess -NoProgressBar -CimSession $TestCimSession1 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.VM | Should Not BeNullOrEmpty
        $Process.Name | Should Not BeNullOrEmpty
        $Process.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should only include the specified property' {
        $Process = Get-CSProcess -NoProgressBar -Property Name | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.VM | Should BeNullOrEmpty
        $Process.Name | Should Not BeNullOrEmpty
        $Process.PSComputerName | Should BeNullOrEmpty
    }

    It 'should only include the specified property w/ CIM sessions' {
        $Process = Get-CSProcess -NoProgressBar -Property Name -CimSession $TestCimSession1 | Select-Object -First 1
        $Process | Should Not BeNullOrEmpty
        $Process.PSObject.TypeNames -contains $ProcessWMIType | Should Be $True
        $Process.VM | Should BeNullOrEmpty
        $Process.Name | Should Not BeNullOrEmpty
        $Process.PSComputerName | Should BeExactly 'localhost'
    }
}

Describe 'Get-CSEnvironmentVariable' {
    It 'should return a populated environment variable' {
        $EnvVar = Get-CSEnvironmentVariable | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should Not BeNullOrEmpty
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a populated environment variable w/ CIM sessions' {
        $EnvVar = Get-CSEnvironmentVariable -CimSession $TestCimSession1 | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should Not BeNullOrEmpty
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a populated system environment variable' {
        $EnvVar = Get-CSEnvironmentVariable -SystemVariable | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should Not BeNullOrEmpty
        $EnvVar.User | Should BeExactly '<SYSTEM>'
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a populated system environment variable w/ CIM sessions' {
        $EnvVar = Get-CSEnvironmentVariable -SystemVariable -CimSession $TestCimSession1 | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should Not BeNullOrEmpty
        $EnvVar.User | Should BeExactly '<SYSTEM>'
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a populated user environment variable' {
        $EnvVar = Get-CSEnvironmentVariable -UserVariable | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should Not BeNullOrEmpty
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.User -eq '<SYSTEM>' | Should Be $False
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a populated user environment variable w/ CIM sessions' {
        $EnvVar = Get-CSEnvironmentVariable -UserVariable -CimSession $TestCimSession1 | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should Not BeNullOrEmpty
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.User -eq '<SYSTEM>' | Should Be $False
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a named environment variable' {
        $EnvVar = Get-CSEnvironmentVariable -VariableName TEMP | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should BeExactly 'TEMP'
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a named environment variable w/ CIM sessions' {
        $EnvVar = Get-CSEnvironmentVariable -VariableName TEMP -CimSession $TestCimSession1 | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should BeExactly 'TEMP'
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a named system environment variable' {
        $EnvVar = Get-CSEnvironmentVariable -SystemVariable -VariableName TEMP | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should BeExactly 'TEMP'
        $EnvVar.User | Should BeExactly '<SYSTEM>'
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a named system environment variable w/ CIM sessions' {
        $EnvVar = Get-CSEnvironmentVariable -SystemVariable -VariableName TEMP -CimSession $TestCimSession1 | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should BeExactly 'TEMP'
        $EnvVar.User | Should BeExactly '<SYSTEM>'
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeExactly 'localhost'
    }

    It 'should return a named user environment variable' {
        $EnvVar = Get-CSEnvironmentVariable -UserVariable -VariableName TEMP | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should BeExactly 'TEMP'
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.User -eq '<SYSTEM>' | Should Be $False
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeNullOrEmpty
    }

    It 'should return a named user environment variable w/ CIM sessions' {
        $EnvVar = Get-CSEnvironmentVariable -UserVariable -VariableName TEMP -CimSession $TestCimSession1 | Select-Object -First 1
        $EnvVar | Should Not BeNullOrEmpty
        $EnvVar.Name | Should BeExactly 'TEMP'
        $EnvVar.User | Should Not BeNullOrEmpty
        $EnvVar.User -eq '<SYSTEM>' | Should Be $False
        $EnvVar.VariableValue | Should Not BeNullOrEmpty
        $EnvVar.PSComputerName | Should BeExactly 'localhost'
    }
}

$TestSessionArray | Remove-CimSession