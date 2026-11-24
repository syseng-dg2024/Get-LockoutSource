$script:ModuleRoot = $PSScriptRoot
# Only the two command files define functions; the other Public files are parts of Get-LockoutSource, loaded when it runs.
. (Join-Path $PSScriptRoot 'Public\Get-LockoutSource.ps1')
. (Join-Path $PSScriptRoot 'Public\Invoke-KerbCorrelator.ps1')
Export-ModuleMember -Function Get-LockoutSource, Invoke-KerbCorrelator
