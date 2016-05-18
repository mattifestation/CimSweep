Get-ChildItem $PSScriptRoot -Directory |
    Where-Object { $_.Name -ne 'ps1xml' -and $_.Name -ne 'Tests' } |
    Get-ChildItem -Include '*.ps1' |
    ForEach-Object { . $_.FullName }

<#
Helper function used to explicitly set which object properties are displayed
This is used primarily to hide CimSession properties and to display PSComputerName
only if a function was performed against a remote computer.

Technique described here: https://poshoholic.com/2008/07/05/essential-powershell-define-default-properties-for-custom-objects/
Thanks Kirk Munro (@Poshoholic)!
#>
function Set-DefaultDisplayProperty {
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [Object]
        $InputObject,

        [Parameter(Mandatory = $True)]
        [String[]]
        $PropertyNames
    )

    $DefaultDisplayPropertySet = New-Object Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’, [String[]] $PropertyNames)
    $PSStandardMembers = [Management.Automation.PSMemberInfo[]]@($DefaultDisplayPropertySet)
    Add-Member -InputObject $InputObject -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers
}
