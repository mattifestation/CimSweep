Get-ChildItem $PSScriptRoot -Directory |
    Where-Object { $_.Name -ne 'ps1xml' -and $_.Name -ne 'Tests' } |
    Get-ChildItem -Include '*.ps1' |
    ForEach-Object { . $_.FullName }