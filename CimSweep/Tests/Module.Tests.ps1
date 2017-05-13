Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\CimSweep.psd1"

Remove-Module [C]imSweep
$Module = Import-Module $ModuleManifest -Force -ErrorAction Stop -PassThru

Describe 'Module-wide tests' -Tags 'Module' {
    $FunctionsList = $Module.ExportedCommands.Keys
    
    foreach ($Function in $FunctionsList)
    {
        # Retrieve the Help of the function
        $Help = Get-Help -Name $Function -Full
        
        # Parse the function using AST
        $AST = [Management.Automation.Language.Parser]::ParseInput((Get-Content function:$Function), [ref]$null, [ref]$null)
        
        Context "Exported command parameters for $Function" {
            It 'should have have an OutputType attribute' {
                $OutputTypeAttribute = $AST.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'OutputType' }
                $OutputTypeAttribute | Should Not BeNullOrEmpty
                $OutputTypeAttribute.TypeName.Name | Should BeExactly 'OutputType'
                $OutputTypeAttribute.PositionalArguments | Should Not BeNullOrEmpty
            }

            It 'should have a -CimSession parameter with proper capitalization and is of type Microsoft.Management.Infrastructure.CimSession[]' {
                $CimSessionParam = $AST.ParamBlock.Parameters | Where-Object { $_.Name.Extent.Text -eq '$CimSession' }
                $CimSessionParam | Should Not BeNullOrEmpty
                $CimSessionParam.Name.Extent.Text | Should BeExactly '$CimSession'
                $CimSessionParam.StaticType.FullName | Should BeExactly 'Microsoft.Management.Infrastructure.CimSession[]'
            }
        }

        Context "Required exported command naming scheme for $Function" {
            It 'should have a "CS" noun prefix' {
                $Module.ExportedCommands[$Function].Noun.Substring(0, 2) | Should BeExactly 'CS'
            }
        }

        # Comment-based help tests derived from:
        # http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
        Context "Comment-based help for: $Function"{
            It 'should contain a .SYNOPSIS block' {
                $Help.Synopsis | Should Not BeNullOrEmpty
            }

            It 'should have an author listed' {
                $Help.Synopsis.Contains('Author:') | Should Be $True
            }

            It 'should contain a BSD license in the synopsis' {
                $Help.Synopsis.Contains('License: BSD 3-Clause') | Should Be $True
            }

            It 'should contain a .DESCRIPTION block' {
                $Help.Description | Should Not BeNullOrEmpty
            }
            
            # Get the parameters declared in the Comment Based Help
            $HelpParameters = @($Help.Parameters.Parameter)
            
            # Get the parameters declared in the AST PARAM() Block
            $ASTParameters = @($AST.ParamBlock.Parameters.Name.Variablepath.Userpath)
            
            It 'should contain a matching number of .PARAMETER blocks for all defined parameters' {
                $NamedArgs = try { $AST.ParamBlock.Attributes.NamedArguments } catch { $null }

                if ($NamedArgs -and $NamedArgs.ArgumentName -contains 'SupportsShouldProcess') {
                    $Count = $ASTParameters.Count + 2 # Accounting for -WhatIf and -Confirm
                } else {
                    $Count = $ASTParameters.Count
                }

                $HelpParameters.Count | Should Be $Count
            }
            
            # Parameter Description
            $Help.Parameters.Parameter | ForEach-Object {
                if ($ASTParameters -contains $_.Name) {
                    It "should contain a .PARAMETER block for the following parameter: $($_.Name)"{
                        $_.Description | Should Not BeNullOrEmpty
                    }
                }
            }
            
            # Examples
            It 'should contain at least one .EXAMPLE block' {
                @($Help.Examples.Example.Code).Count | Should BeGreaterThan 0
            }
        }
    }
}