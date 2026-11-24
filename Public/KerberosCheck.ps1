# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 2b: Live Kerberos correlation (only for DC-local failures that are still happening)
# ==============================================================================
if (-not $ActiveLockout) {
    $HintEv = @($AllDCEvents | Where-Object { $_.EventId -in 4625,4771,4776 -and $_.IpAddress -in @('::1','127.0.0.1','::ffff:127.0.0.1','-','') })
    if ($HintEv.Count) { Write-Host "`n[Phase 2b] $($HintEv.Count) failures come from a DC itself. If the lockout is still happening, re-run with -ActiveLockout (or tick the box) to trace the caller." -ForegroundColor DarkYellow }
}
if ($ActiveLockout) {
    Write-Host "`n[Phase 2b] Active lockout flagged - checking for DC-local failures to trace..." -ForegroundColor Cyan
    $DcLocalIps = @('::1','127.0.0.1','::ffff:127.0.0.1','-','')
    $LocalEv = @($AllDCEvents | Where-Object {
        $_.EventId -in 4625,4771,4776 -and
        ($_.IpAddress -in $DcLocalIps -or
         ($_.WorkstationName -and $_.WorkstationName.TrimEnd('$').ToUpper() -in $DCShortNames)) })
    $KerbDCs = @($LocalEv | ForEach-Object { "$($_.SourceDC)".Split('.')[0].ToUpper() } | Where-Object { $_ } | Select-Object -Unique)

    foreach ($KDC in $KerbDCs) {
        $Recent = @(Get-WinEvent -ComputerName $KDC -FilterHashtable @{LogName='Security';Id=4771,4625,4776;StartTime=(Get-Date).AddMinutes(-$KerbRecentMinutes)} -EA SilentlyContinue |
                    Where-Object { "$($_.Properties[0].Value)" -eq $UserName })
        if (-not $Recent.Count) {
            Write-Warning "  $KDC : DC-local failures found but none in the last $KerbRecentMinutes min. Run Invoke-KerbCorrelator on $KDC during the next burst."
            continue
        }
        if ($KDC -ne $env:COMPUTERNAME.ToUpper()) {
            Write-Warning "  $KDC : $($Recent.Count) recent DC-local failures. The correlator must run on that DC: Invoke-KerbCorrelator -User $UserName -Seconds $KerbSeconds"
            continue
        }
        Write-Host "`n[Phase 2b] $($Recent.Count) DC-local failures in the last $KerbRecentMinutes min on $KDC - running Kerberos correlator ($KerbSeconds s)..." -ForegroundColor Yellow
        $Kc = Invoke-KerbCorrelator -User $UserName -Seconds $KerbSeconds -OutDir $TempPath -NoOpen
        $KerbResults.Add($Kc)
        if ($Kc.TopCaller -and $Kc.TopCaller.Score -ge 40) {
            $n = if ($Kc.TopCaller.Hostname) { $Kc.TopCaller.Hostname.TrimEnd('.').Split('.')[0].ToUpper() } else { $Kc.TopCaller.IP }
            if (-not $TargetComputers.Contains($n)) { Write-Host "  + (Kerberos correlator) $n"; $TargetComputers.Add($n) }
        }
        Write-Host "  Correlator verdict: $($Kc.Verdict)"
    }
}

