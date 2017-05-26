function Get-CSAppCompatCache {
<#
.SYNOPSIS

Retrieves and parses entries from the AppCompatCache based on OS version.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause

.DESCRIPTION

Get-CSAppCompatCache parses entries from the Application Compatibility Cache stored in the registry.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.EXAMPLE

Get-CSAppCompatCache

.EXAMPLE

Get-CSAppCompatCache -CimSession $CimSession

.OUTPUTS

CimSweep.AppCompatCacheEntry

Outputs objects consisting of the application's file path and that file's last modified time. Note: the LastModified property is a UTC datetime string in Round-trip format.

#>

    [CmdletBinding()]
    [OutputType('CimSweep.AppCompatCacheEntry')]
    param (
        [Alias('Session')]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )
    
    begin {
        # If a CIM session is not provided, trick the function into thinking there is one.
        if (-not $PSBoundParameters['CimSession']) {
            $CimSession = ''
            $CIMSessionCount = 1
        } else {
            $CIMSessionCount = $CimSession.Count
        }

        $CurrentCIMSession = 0
    }

    process {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - AppCompatCache sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}

            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }

            $OS = Get-CimInstance -ClassName Win32_OperatingSystem @CommonArgs
            
            if ($OS.Version -like "5.1*") { 
                $Parameters = @{
                    Hive = 'HKLM'
                    SubKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility'
                }
            }
            else {
                $Parameters = @{
                    Hive = 'HKLM'
                    SubKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
                    ValueName = 'AppCompatCache'
                }
            }
            
            $AppCompatCacheValue = Get-CSRegistryValue @Parameters @CommonArgs
            ConvertFrom-ByteArray -CacheValue $AppCompatCacheValue -OSVersion $OS.Version -OSArchitecture $OS.OSArchitecture
        }
    }
    end {}
}


function ConvertFrom-ByteArray {
<#
.SYNOPSIS

Converts bytes from the AppCompatCache registry key into objects.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause

Thanks to @ericrzimmerman for these test files https://github.com/EricZimmerman/AppCompatCacheParser/tree/master/AppCompatCacheParserTest/TestFiles

.DESCRIPTION

ConvertFrom-ByteArray converts bytes from the AppCompatCache registry key into objects.

.PARAMETER CacheValue

Byte array from the AppCompatCache registry key.

.PARAMETER OSVersion

Specifies the operating system version from which the AppCompatCache bytes were retrieved.

.PARAMETER OSArchitecture

Specifies the bitness of the operating system from which the AppCompatCache bytes were retrieved.

.EXAMPLE

ConvertFrom-ByteArray -CacheBytes $AppCompatCacheKeyBytes -OSVersion 6.1 -OSArchitecture 32-bit 
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Object]
        $CacheValue,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OSVersion,
        
        [Parameter()]
        [string]
        $OSArchitecture
    )

    $BinaryReader = New-Object IO.BinaryReader (New-Object IO.MemoryStream (,$CacheValue.ValueContent))

    $ASCIIEncoding = [Text.Encoding]::ASCII
    $UnicodeEncoding = [Text.Encoding]::Unicode

    switch ($OSVersion) {
        
        { $_ -like '10.*' } { # Windows 10
            
            $null = $BinaryReader.BaseStream.Seek(48, [IO.SeekOrigin]::Begin)
            
            # check for magic
            if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts') { 
                $null = $BinaryReader.BaseStream.Seek(52, [IO.SeekOrigin]::Begin) # offset shifted in creators update
                if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4))  -ne '10ts') { throw 'Not Windows 10' }
            }

            do { # parse entries
                $null = $BinaryReader.BaseStream.Seek(8, [IO.SeekOrigin]::Current) # padding between entries
                
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($BinaryReader.ReadUInt16()))
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                
                $null = $BinaryReader.ReadBytes($BinaryReader.ReadInt32()) # skip some bytes

                $ObjectProperties = @{
                    PSTypeName = 'CimSweep.AppCompatCacheEntry'
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                }

                if ($CacheValue.PSComputerName) { $ObjectProperties['PSComputerName'] = $CacheValue.PSComputerName }
                if ($CacheValue.CimSession) { $ObjectProperties['CimSession'] = $CacheValue.CimSession }
                
                [PSCustomObject]$ObjectProperties

            } until ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts')
        }

        { $_ -like '6.3*' } { # Windows 8.1 / Server 2012 R2

            $null = $BinaryReader.BaseStream.Seek(128, [IO.SeekOrigin]::Begin)

            # check for magic
            if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts') { throw 'Not windows 8.1/2012r2' }
            
            do { # parse entries
                $null = $BinaryReader.BaseStream.Seek(8, [IO.SeekOrigin]::Current) # padding & datasize
                
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($BinaryReader.ReadUInt16()))

                $null = $BinaryReader.ReadBytes(10) # skip insertion/shim flags & padding
                
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                
                $null = $BinaryReader.ReadBytes($BinaryReader.ReadInt32()) # skip some bytes
                 
                $ObjectProperties = @{
                    PSTypeName = 'CimSweep.AppCompatCacheEntry'
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                }

                if ($CacheValue.PSComputerName) { $ObjectProperties['PSComputerName'] = $CacheValue.PSComputerName }
                if ($CacheValue.CimSession) { $ObjectProperties['CimSession'] = $CacheValue.CimSession }
                
                [PSCustomObject]$ObjectProperties

            } until ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '10ts')
        }

        { $_ -like '6.2*' } { # Windows 8.0 / Server 2012

            # check for magic
            $null = $BinaryReader.BaseStream.Seek(128, [IO.SeekOrigin]::Begin)
            if ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '00ts') { throw 'Not Windows 8/2012' }

            do { # parse entries
                $null = $BinaryReader.BaseStream.Seek(8, [IO.SeekOrigin]::Current) # padding & datasize
                
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($BinaryReader.ReadUInt16()))

                $null = $BinaryReader.BaseStream.Seek(10, [IO.SeekOrigin]::Current) # skip insertion/shim flags & padding
                
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                
                $null = $BinaryReader.ReadBytes($BinaryReader.ReadInt32()) # skip some bytes
                
                $ObjectProperties = @{
                    PSTypeName = 'CimSweep.AppCompatCacheEntry'
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                }

                if ($CacheValue.PSComputerName) { $ObjectProperties['PSComputerName'] = $CacheValue.PSComputerName }
                if ($CacheValue.CimSession) { $ObjectProperties['CimSession'] = $CacheValue.CimSession }
                
                [PSCustomObject]$ObjectProperties

            } until ($ASCIIEncoding.GetString($BinaryReader.ReadBytes(4)) -ne '00ts')
        }
        
        { $_ -like '6.1*' } { # Windows 7 / Server 2008 R2
            
            # check for magic
            if ([BitConverter]::ToString($BinaryReader.ReadBytes(4)[3..0]) -ne 'BA-DC-0F-EE') { throw 'Not Windows 7/2008R2'}
            
            $NumberOfEntries = $BinaryReader.ReadInt32()

            $null = $BinaryReader.BaseStream.Seek(128, [IO.SeekOrigin]::Begin) # skip padding

            if ($OSArchitecture -eq '32-bit') {
                
                do {
                    $EntryPosition++
                    
                    $PathSize = $BinaryReader.ReadUInt16()
                    
                    $null = $BinaryReader.ReadUInt16() # MaxPathSize
                    
                    $PathOffset = $BinaryReader.ReadInt32()
                    
                    $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                    
                    $null = $BinaryReader.BaseStream.Seek(16, [IO.SeekOrigin]::Current)
                    
                    $Position = $BinaryReader.BaseStream.Position
                    
                    $null = $BinaryReader.BaseStream.Seek($PathOffset, [IO.SeekOrigin]::Begin)
                    
                    $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($PathSize))

                    $null = $BinaryReader.BaseStream.Seek($Position, [IO.SeekOrigin]::Begin)
                    
                    $ObjectProperties = @{
                        PSTypeName = 'CimSweep.AppCompatCacheEntry'
                        Path = $Path
                        LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                    }

                    if ($CacheValue.PSComputerName) { $ObjectProperties['PSComputerName'] = $CacheValue.PSComputerName }
                    if ($CacheValue.CimSession) { $ObjectProperties['CimSession'] = $CacheValue.CimSession }
                
                    [PSCustomObject]$ObjectProperties

                } until ($EntryPosition -eq $NumberOfEntries)
            }

            else { # 64-bit

                do {
                    $EntryPosition++
                    
                    $PathSize = $BinaryReader.ReadUInt16()
                    
                    # Padding
                    $null = $BinaryReader.BaseStream.Seek(6, [IO.SeekOrigin]::Current)
                    
                    $PathOffset = $BinaryReader.ReadInt64()
                    $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                    
                    $null = $BinaryReader.BaseStream.Seek(24, [IO.SeekOrigin]::Current)
                    
                    $Position = $BinaryReader.BaseStream.Position
                    
                    $null = $BinaryReader.BaseStream.Seek($PathOffset, [IO.SeekOrigin]::Begin)
                    
                    $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes($PathSize))

                    $null = $BinaryReader.BaseStream.Seek($Position, [IO.SeekOrigin]::Begin)
                    
                    $ObjectProperties = @{
                        PSTypeName = 'CimSweep.AppCompatCacheEntry'
                        Path = $Path
                        LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                    }

                    if ($CacheValue.PSComputerName) { $ObjectProperties['PSComputerName'] = $CacheValue.PSComputerName }
                    if ($CacheValue.CimSession) { $ObjectProperties['CimSession'] = $CacheValue.CimSession }
                
                    [PSCustomObject]$ObjectProperties

                } until ($EntryPosition -eq $NumberOfEntries)
            }
        }
        
        { $_ -like '6.0*' } { <# Windows Vista / Server 2008 #> }
        
        { $_ -like '5.2*' } { <# Windows XP Pro 64-bit / Server 2003 (R2) #> }
        
        { $_ -like '5.1*' } { # Windows XP 32-bit
         
            # check for magic
            if ([BitConverter]::ToString($BinaryReader.ReadBytes(4)[3..0]) -ne 'DE-AD-BE-EF') { throw 'Not Windows XP 32-bit'}
            
            $NumberOfEntries = $BinaryReader.ReadInt32() # this is always 96, even if there aren't 96 entries

            $null = $BinaryReader.BaseStream.Seek(400, [IO.SeekOrigin]::Begin) # skip padding

            do { # parse entries
                $EntryPosition++
                $Path = $UnicodeEncoding.GetString($BinaryReader.ReadBytes(528)).TrimEnd("`0") # 528 == MAX_PATH + 4 unicode chars
                $LastModifiedTime = [DateTimeOffset]::FromFileTime($BinaryReader.ReadInt64()).DateTime
                
                if (($LastModifiedTime.Year -eq 1600) -and !$Path) { break } # empty entries == end

                $null = $BinaryReader.BaseStream.Seek(16, [IO.SeekOrigin]::Current) # skip some bytes
                
                $ObjectProperties = @{
                    PSTypeName = 'CimSweep.AppCompatCacheEntry'
                    Path = $Path
                    LastModifiedTime = $LastModifiedTime.ToUniversalTime().ToString('o')
                }

                if ($CacheValue.PSComputerName) { $ObjectProperties['PSComputerName'] = $CacheValue.PSComputerName }
                if ($CacheValue.CimSession) { $ObjectProperties['CimSession'] = $CacheValue.CimSession }
                
                [PSCustomObject]$ObjectProperties

            } until ($EntryPosition -eq $NumberOfEntries)
        }
    }
    $BinaryReader.BaseStream.Dispose()
    $BinaryReader.Dispose()
}

Export-ModuleMember -Function Get-CSAppCompatCache