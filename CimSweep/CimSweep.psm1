Get-ChildItem $PSScriptRoot -Directory |
    ? {$_.Name -ne 'ps1xml' -and $_.Name -ne 'Tests'} |
    Get-ChildItem -Include '*.ps1' |
    % {. $_.FullName}