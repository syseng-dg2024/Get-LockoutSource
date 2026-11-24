@{
    RootModule        = 'Get-LockoutSource.psm1'
    ModuleVersion     = '1.6.0'
    GUID              = '7b1f3c2e-5d4a-4e8b-9a61-2c0f7e9d4b13'
    Author            = 'Systems Engineering'
    Description       = 'Account lockout source analysis with live Kerberos ETW correlation.'
    PowerShellVersion = '5.1'
    RequiredModules   = @('ActiveDirectory')
    FunctionsToExport = @('Get-LockoutSource','Invoke-KerbCorrelator')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
