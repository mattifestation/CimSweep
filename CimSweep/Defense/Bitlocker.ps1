function Get-CSBitlockerKeyProtector {
<#
.SYNOPSIS

Obtains Bitlocker volume key material.

Author: Matthew Graeber (@mattifestation)
Inspiration/Motivation: Jared Atkinson (@jaredcatkinson), Brian Reitz
License: BSD 3-Clause

.DESCRIPTION

Get-CSBitlockerKeyProtector retrieves key material for BitLocker volumes. This function is used for the purposes of remotely decrypting and mounting Bitlocker volumes. Depending on the Bitlocker key protector used, Get-CSBitlockerKeyProtector will return any combination of the NumericalPassword, ExternalKey, KeyPackage, or Certificate.

.PARAMETER DriveLetter

Specifies the drive letter for the volume you want to obtain key Bitlocker key material from. If DriveLetter is not specified, key material for all encryptable volumes will be returned.

.PARAMETER CimSession

Specifies the CIM session to use for this cmdlet. Enter a variable that contains the CIM session or a command that creates or gets the CIM session, such as the New-CimSession or Get-CimSession cmdlets. For more information, see about_CimSessions.

.PARAMETER OperationTimeoutSec

Specifies the amount of time that the cmdlet waits for a response from the computer.

By default, the value of this parameter is 0, which means that the cmdlet uses the default timeout value for the server.

If the OperationTimeoutSec parameter is set to a value less than the robust connection retry timeout of 3 minutes, network failures that last more than the value of the OperationTimeoutSec parameter are not recoverable, because the operation on the server times out before the client can reconnect.

.EXAMPLE

Get-CSBitlockerKeyProtector

List all recoverable Bitlocker key material for each encryptable volume.

.EXAMPLE

Get-CSBitlockerKeyProtector -DriveLetter C:

List all recoverable Bitlocker key material for the C: volume.

.OUTPUTS

CimSweep.BitlockerKeyProtector

Outputs objects representing Bitlocker volume key material.
#>

    [CmdletBinding()]
    [OutputType('CimSweep.BitlockerKeyProtector')]
    param(
        [ValidatePattern('^[A-Z]:?$')]
        [String]
        $DriveLetter,

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

        $KeyProtectorTypes = @{
            0 = 'Unknown or other protector type'
            1 = 'Trusted Platform Module (TPM)'
            2 = 'External key'
            3 = 'Numerical password'
            4 = 'TPM And PIN'
            5 = 'TPM And Startup Key'
            6 = 'TPM And PIN And Startup Key'
            7 = 'Public Key'
            8 = 'Passphrase'
            9 = 'TPM Certificate'
            10 = 'CryptoAPI Next Generation (CNG) Protector'
        }
    }

    PROCESS {
        foreach ($Session in $CimSession) {
            $ComputerName = $Session.ComputerName
            if (-not $Session.ComputerName) { $ComputerName = 'localhost' }

            # Display a progress activity for each CIM session
            Write-Progress -Id 1 -Activity 'CimSweep - Bitlocker key protector sweep' -Status "($($CurrentCIMSession+1)/$($CIMSessionCount)) Current computer: $ComputerName" -PercentComplete (($CurrentCIMSession / $CIMSessionCount) * 100)
            $CurrentCIMSession++

            $CommonArgs = @{}
            if ($Session.Id) { $CommonArgs['CimSession'] = $Session }
            if ($OperationTimeoutSec) { $CommonArgs['OperationTimeoutSec'] = $OperationTimeoutSec }

            $VolumeArgs = @{
                Namespace = 'root/cimv2/security/microsoftvolumeencryption'
                ClassName = 'Win32_EncryptableVolume'
                Property = 'ProtectionStatus', 'DriveLetter', 'DeviceID'
            }

            if ($DriveLetter) { $VolumeArgs['Filter'] = "DriveLetter='$($DriveLetter[0]):'" }

            $Volumes = @(Get-CimInstance @CommonArgs @VolumeArgs)

            $VolCount = 0

            foreach ($CurrentVolume in $Volumes) {
                Write-Progress -Id 2 -ParentId 1 -Activity "Current volume:" -Status "($($VolCount+1)/$($Volumes.Count)) $($CurrentVolume.DriveLetter)" -PercentComplete (($VolCount / $Volumes.Count) * 100)
                $VolCount++

                if ($CurrentVolume.ProtectionStatus -ne 1) {
                    Write-Warning "[$ComputerName] Drive letter $($CurrentVolume.DriveLetter) is not Bitlocker protected."
                    continue
                }

                $Result = Invoke-CimMethod -CimInstance $CurrentVolume -MethodName GetKeyProtectors @CommonArgs

                if ($Result.ReturnValue) {
                    Write-Error "[$ComputerName] Unable to obtain key protectors from drive letter: $($CurrentVolume.DriveLetter)"
                    continue
                }

                $ProtectorCount = 0
                $KeyProtectorIDs = @($Result.VolumeKeyProtectorID)

                foreach ($ProtectorID in $KeyProtectorIDs) {
                    Write-Progress -Id 3 -ParentId 2 -Activity "Current key protector ID:" -Status "($($ProtectorCount+1)/$($KeyProtectorIDs.Count)) $ProtectorID" -PercentComplete (($ProtectorCount / $KeyProtectorIDs.Count) * 100)
                    $ProtectorCount++

                    $MethodArgs = @{
                        CimInstance = $CurrentVolume
                        Arguments = @{ VolumeKeyProtectorID = $ProtectorID }
                    }

                    $Result = Invoke-CimMethod -MethodName GetKeyProtectorType @CommonArgs @MethodArgs

                    if ($Result.ReturnValue) {
                        Write-Error "[$ComputerName] Unable to obtain key protector type for drive letter: $($CurrentVolume.DriveLetter), VolumeKeyProtectorID: $ProtectorID"
                        continue
                    }

                    $KeyProtectorFriendlyName = $KeyProtectorTypes[[Int] $Result.KeyProtectorType]

                    $ExternalKeyFileName = $null
                    $ExternalKeyBytes = $null
                    $NumericalPassword = $null
                    $KeyPackage = $null
                    $KeyProtectorCertificate = $null

                    $ErrorTemplate = "for drive letter: $($CurrentVolume.DriveLetter), VolumeKeyProtectorID: $ProtectorID"

                    switch ($KeyProtectorFriendlyName) {
                        'External key' {
                            $Result = Invoke-CimMethod -MethodName GetExternalKeyFileName @CommonArgs @MethodArgs
                            
                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain external key file name $ErrorTemplate"
                                continue
                            }

                            $ExternalKeyFileName = $Result.FileName

                            $Result = Invoke-CimMethod -MethodName GetKeyProtectorExternalKey @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain external key bytes $ErrorTemplate"
                                continue
                            }

                            $ExternalKeyBytes = $Result.ExternalKey

                            $Result = Invoke-CimMethod -MethodName GetKeyPackage @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain key package $ErrorTemplate"
                                continue
                            }

                            $KeyPackage = $Result.KeyPackage
                        }

                        'Numerical password' {
                            $Result = Invoke-CimMethod -MethodName GetKeyProtectorNumericalPassword @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain numerical password $ErrorTemplate"
                                continue
                            }

                            $NumericalPassword = $Result.NumericalPassword

                            $Result = Invoke-CimMethod -MethodName GetKeyPackage @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain key package $ErrorTemplate"
                                continue
                            }

                            $KeyPackage = $Result.KeyPackage
                        }

                        'TPM And Startup Key' {
                            $Result = Invoke-CimMethod -MethodName GetExternalKeyFileName @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain external key file name $ErrorTemplate"
                                continue
                            }
        
                            $ExternalKeyFileName = $Result.FileName

                            $Result = Invoke-CimMethod -MethodName GetKeyProtectorExternalKey @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain external key bytes $ErrorTemplate"
                                continue
                            }

                            $ExternalKeyBytes = $Result.ExternalKey
                        }

                        'TPM And PIN And Startup Key' {
                            $Result = Invoke-CimMethod -MethodName GetExternalKeyFileName @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain external key file name $ErrorTemplate"
                                continue
                            }
        
                            $ExternalKeyFileName = $Result.FileName

                            $Result = Invoke-CimMethod -MethodName GetKeyProtectorExternalKey @CommonArgs @MethodArgs

                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain external key bytes $ErrorTemplate"
                                continue
                            }

                            $ExternalKeyBytes = $Result.ExternalKey
                        }

                        'Public Key' {
                            $Result = Invoke-CimMethod -CimInstance $CurrentVolume -MethodName GetKeyProtectorCertificate -Arguments @{ VolumeKeyProtectorID = $ProtectorID } @CommonArgs
        
                            if ($Result.ReturnValue) {
                                Write-Error "[$ComputerName] Unable to obtain protector certificate $ErrorTemplate"
                                continue
                            }

                            $KeyProtectorCertificate = [PSCustomObject] @{
                                PSTypeName = 'CimSweep.KeyProtector.BitlockerKeyProtector'
                                PublicKey = $Result.PublicKey
                                CertThumbprint = $Result.CertThumbprint
                                CertType = if ($Result.CertType -eq 1) { 'DataRecoveryAgent' } else { 'UserCertificate' }
                            }
                        }
                    }

                    $ProtectorProperties = [Ordered] @{
                        PSTypeName = 'CimSweep.BitlockerKeyProtector'
                        DriveLetter = $CurrentVolume.DriveLetter
                        DeviceID = $CurrentVolume.DeviceID
                        KeyProtectorID = $ProtectorID
                        KeyProtectorFriendlyName = $KeyProtectorFriendlyName
                        NumericalPassword = $NumericalPassword
                        ExternalKeyFileName = $ExternalKeyFileName
                        ExternalKeyBytes = $ExternalKeyBytes
                        KeyPackage = $KeyPackage
                        Certificate = $KeyProtectorCertificate
                    }

                    if ($CurrentVolume.PSComputerName) {
                        $ProtectorProperties['PSComputerName'] = $CurrentVolume.PSComputerName
                    }

                    [PSCustomObject] $ProtectorProperties
                }
            }
        }
    }
}