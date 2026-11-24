# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  AD Query
# ==============================================================================
try {
    $ADDomain          = Get-ADDomain
    $DNSZone           = $ADDomain.DNSRoot
    $DomainDNSServer   = $ADDomain.PDCEmulator   # Used for PTR lookups
    $DomainControllers = (Get-ADDomainController -Filter *).HostName
    $AllServers        = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Windows Server*' } |
                             Select-Object -ExpandProperty Name
    Write-Host "DNS Zone:         $DNSZone"
    Write-Host "PTR DNS Server:   $DomainDNSServer"
    Write-Host "DCs:              $($DomainControllers -join ', ')"
    Write-Host "Server count:     $($AllServers.Count)"
} catch {
    Write-Warning "AD query failed: $($_.Exception.Message)"
    $LockoutAbort = $true; return
}

