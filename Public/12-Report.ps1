# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 7: Combined HTML Report
#  TOP:    Unified activity table (DC Security Events + NPS entries)
#  BOTTOM: Per-device scan (AD user details, services, tasks, startup, etc.)
# ==============================================================================
Write-Host "`n[Phase 7] Generating HTML report..."
$ReportDate = Get-Date -Format 'MM/dd/yyyy hh:mm:ss tt'

$HtmlHeader = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Lockout Report - $UserName</title>
<style>
  body       { font-family:Segoe UI,Arial,sans-serif; margin:20px; background:#f4f4f4; color:#222; }
  h1         { background:#003366; color:white; padding:15px; border-radius:5px; }
  h2         { background:#0066cc; color:white; padding:8px 12px; border-radius:4px; margin-top:30px; }
  h3         { color:#003366; border-bottom:2px solid #0066cc; padding-bottom:5px; }
  table      { border-collapse:collapse; width:100%; margin-bottom:15px; background:white; }
  th         { background:#003366; color:white; padding:8px; text-align:left; font-size:12px; }
  td         { padding:5px 8px; border:1px solid #ddd; font-size:12px; }
  tr:nth-child(even) { background:#f0f0f0; }
  .section   { background:white; padding:15px; margin-bottom:20px; border-radius:5px; box-shadow:0 1px 3px rgba(0,0,0,.1); }
  pre        { background:#eee; padding:10px; border-radius:4px; overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }
  .fail      { background:#cc0000; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .ok        { background:#006600; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .nps       { background:#b36200; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .warn      { background:#cc7700; color:white; padding:2px 7px; border-radius:10px; font-size:11px; }
  .divider   { border:none; border-top:4px solid #003366; margin:40px 0; }
  .hint      { font-style:italic; color:#555; font-size:12px; margin-bottom:8px; }
</style></head><body>
<h1>Lockout Report - $UserName</h1>
<div class='section'>
  <p><strong>Username:</strong> $UserName</p>
  <p><strong>Generated:</strong> $ReportDate</p>
  <p><strong>Window:</strong> $($StartDate.ToString('MM/dd/yyyy hh:mm:ss tt')) to $($EndDate.ToString('MM/dd/yyyy hh:mm:ss tt'))</p>
  <p><strong>Target Computers:</strong> $($TargetComputers -join ', ')</p>
  <p><strong>DC Events:</strong> $($AllDCEvents.Count) |
     <strong>NPS Entries:</strong> $($AllNPSRaw.Count) |
     <strong>Device Events:</strong> $($AllDeviceEvents.Count) |
     <strong>Unified Rows:</strong> $($UnifiedRows.Count)</p>
  <p class='hint'>Event activity tables are at the top. Device scan results are below the divider.</p>
</div>
"@

$HtmlBody = ''

# ── UNIFIED ACTIVITY TABLE ────────────────────────────────────────────────────
$HtmlBody += "<h2>Unified Event Activity ($($UnifiedRows.Count) rows)</h2>`n<div class='section'>`n"

if ($UnifiedRows.Count -gt 0) {
    $HtmlBody += "<table>`n"
    $HtmlBody += "<tr><th>Time</th><th>Source</th><th>EventId / Packet</th><th>Description</th>"
    $HtmlBody += "<th>Server</th><th>User</th><th>Workstation / Caller</th><th>IP Address</th>"
    $HtmlBody += "<th>Logon Type</th><th>Auth Method</th><th>Result</th>"
    $HtmlBody += "<th>Status</th><th>SubStatus</th><th>Failure Reason</th><th>AP / Policy</th></tr>`n"

    foreach ($Row in ($UnifiedRows | Sort-Object Timestamp -Descending)) {
        $eid  = "$($Row.EventId)"
        $src  = "$($Row.Source)"
        $lt   = "$($Row.LogonType)"
        $pt   = "$($Row.PacketType)"
        $ts   = if ($Row.Timestamp)         { ([datetime]$Row.Timestamp).ToString('MM/dd/yyyy hh:mm:ss tt') } else { '' }
        $desc = if ($Row.EventDescription)  { $Row.EventDescription } elseif ($pt) { $pt } else { '' }
        $ltn  = if ($Row.LogonTypeName)     { $Row.LogonTypeName }    elseif ($lt) { $lt } else { '' }
        $sts  = if ($Row.StatusDesc)        { $Row.StatusDesc }       elseif ($Row.Status) { $Row.Status } else { '' }
        $ssts = if ($Row.SubStatusDesc)     { $Row.SubStatusDesc }    elseif ($Row.SubStatus) { $Row.SubStatus } else { '' }
        $frd  = if ($Row.FailureReasonDesc) { $Row.FailureReasonDesc } elseif ($Row.FailureReason) { $Row.FailureReason } else { '' }
        $wkst = if ($Row.WorkstationName)   { $Row.WorkstationName }  elseif ($Row.CallerComputer) { $Row.CallerComputer } else { '' }
        $ap   = if ($Row.PolicyName)        { $Row.PolicyName }       else { '' }

        $badge = if ($src -eq 'NPS') {
            "<span class='nps'>NPS</span>"
        } elseif ($eid -in @('4740','4625','4771','4776','5816','5817')) {
            "<span class='fail'>$eid</span>"
        } elseif ($eid -in @('4624','4634','4647','4672','4778','4800','4801')) {
            "<span class='ok'>$eid</span>"
        } else {
            "<span class='warn'>$eid</span>"
        }

        $HtmlBody += "<tr>"
        $HtmlBody += "<td>$ts</td><td>$src</td><td>$badge</td><td>$desc</td>"
        $HtmlBody += "<td>$($Row.SourceServer)</td><td>$($Row.UserName)</td><td>$wkst</td><td>$($Row.IpAddress)</td>"
        $HtmlBody += "<td>$ltn</td><td>$($Row.AuthMethod)</td><td>$($Row.Result)</td>"
        $HtmlBody += "<td>$sts</td><td>$ssts</td><td>$frd</td><td>$ap</td>"
        $HtmlBody += "</tr>`n"
    }
    $HtmlBody += "</table>`n"
} else {
    $HtmlBody += "<p>No unified rows found. Verify Phase 1 DC scan ran and events exist in the time window.</p>`n"
}
$HtmlBody += "</div>`n"


# ── KERBEROS CORRELATOR ──────────────────────────────────────────────────────
if ($KerbResults.Count) {
    $HtmlBody += "<h2>Kerberos Correlator (live trace)</h2>`n<div class='section'><table><tr><th>User</th><th>Failures traced</th><th>Top caller</th><th>Top process</th><th>Verdict</th><th>Report</th></tr>`n"
    foreach ($K in $KerbResults) {
        $tc = if ($K.TopCaller) { "$($K.TopCaller.IP) $($K.TopCaller.Hostname) (score $($K.TopCaller.Score))" } else { 'none' }
        $tp = if ($K.TopProcess) { "$($K.TopProcess.Process) PID $($K.TopProcess.PID) (score $($K.TopProcess.Score))" } else { 'none' }
        $HtmlBody += "<tr><td>$($K.User)</td><td>$($K.Failures)</td><td>$tc</td><td>$tp</td><td>$([System.Net.WebUtility]::HtmlEncode($K.Verdict))</td><td>$($K.ReportPath)</td></tr>`n"
    }
    $HtmlBody += "</table></div>`n"
}

# ── DEVICE SECURITY EVENTS ────────────────────────────────────────────────────
if ($AllDeviceEvents.Count -gt 0) {
    $HtmlBody += "<h2>Security Events on Target Devices ($($AllDeviceEvents.Count))</h2>`n<div class='section'><table>`n"
    $HtmlBody += "<tr><th>Time</th><th>EventId</th><th>Description</th><th>Computer</th>"
    $HtmlBody += "<th>User</th><th>Workstation</th><th>IP</th><th>Logon Type</th>"
    $HtmlBody += "<th>Auth Package</th><th>Failure Reason</th><th>Status</th><th>SubStatus</th></tr>`n"

    foreach ($Ev in ($AllDeviceEvents | Sort-Object TimeCreated -Descending)) {
        $eid  = [int]$Ev.EventId
        $lt   = "$($Ev.LogonType)"
        $fr   = "$($Ev.FailureReason)"
        $st   = Normalize-HexStatus "$($Ev.Status)"
        $sst  = Normalize-HexStatus "$($Ev.SubStatus)"
        $bc   = if ($eid -in @(4625,4740,4771,4776)) { 'fail' } else { 'ok' }
        $sts  = if ($StatusDescriptions[$st])  { $StatusDescriptions[$st] }  else { $st }
        $ssts = if ($StatusDescriptions[$sst]) { $StatusDescriptions[$sst] } else { $sst }
        $frd  = if ($FailureReasons[$fr])      { $FailureReasons[$fr] }      else { $fr }
        $ltn  = if ($LogonTypes[$lt])          { $LogonTypes[$lt] }          else { $lt }

        $HtmlBody += "<tr>"
        $HtmlBody += "<td>$($Ev.TimeCreated.ToString('MM/dd/yyyy hh:mm:ss tt'))</td>"
        $HtmlBody += "<td><span class='$bc'>$eid</span></td>"
        $HtmlBody += "<td>$(if ($EventDescriptions[$eid]) { $EventDescriptions[$eid] })</td>"
        $HtmlBody += "<td>$($Ev.SourceComputer)</td><td>$($Ev.TargetUserName)</td>"
        $HtmlBody += "<td>$($Ev.WorkstationName)</td><td>$($Ev.IpAddress)</td>"
        $HtmlBody += "<td>$ltn</td><td>$($Ev.AuthPackage)</td>"
        $HtmlBody += "<td>$frd</td><td>$sts</td><td>$ssts</td>"
        $HtmlBody += "</tr>`n"
    }
    $HtmlBody += "</table></div>`n"
} else {
    $HtmlBody += "<h2>Security Events on Target Devices</h2><div class='section'><p>No device security events found.</p></div>`n"
}

# ── DIVIDER + DEVICE SCAN RESULTS ────────────────────────────────────────────
$HtmlBody += "<hr class='divider'>`n"
$HtmlBody += "<h2>Device Scan Results</h2>`n"

if ($DeviceDetails -and $DeviceDetails.Count -gt 0) {
    foreach ($Detail in $DeviceDetails) {
        $HtmlBody += "<h2>$($Detail.ComputerName)</h2>`n"

        foreach ($Sec in @(
            [PSCustomObject]@{ Title='AD User Details';          Content=$Detail.ADUserDetails }
            [PSCustomObject]@{ Title='Services Running as User'; Content=$Detail.Services }
            [PSCustomObject]@{ Title='Mapped Network Drives';    Content=$Detail.MappedDrives }
            [PSCustomObject]@{ Title='Cached Credentials';       Content=$Detail.CachedCredentials }
            [PSCustomObject]@{ Title='Saved WiFi Profiles';      Content=$Detail.SavedWifi }
            [PSCustomObject]@{ Title='Scheduled Tasks';          Content=$Detail.ScheduledTasks }
            [PSCustomObject]@{ Title='Startup Items';            Content=$Detail.StartupItems }
            [PSCustomObject]@{ Title='LSA Logon Sessions (klist)'; Content = $Detail.LogonSessions }
        )) {
            if (-not $Sec.Content -and
                $Sec.Title -like 'LSA*') { continue }
            $body = if ($Sec.Content) { $Sec.Content } else { "<p class='hint'>No data returned.</p>" }
            $HtmlBody += "<div class='section'><h3>$($Sec.Title)</h3>$body</div>`n"
        }
    }
} else {
    $HtmlBody += "<div class='section'><p>No device details collected.</p></div>`n"
}

($HtmlHeader + $HtmlBody + '</body></html>') |
    Out-File -FilePath $DeviceOutputPath -Encoding UTF8 -Force
Write-Host "  HTML report: $DeviceOutputPath"

$ScriptEnd = Get-Date
Write-Host "`nDone: $($ScriptEnd.ToString('MM/dd/yyyy hh:mm:ss tt'))  |  Elapsed: $($ScriptEnd - $ScriptStart)"
#Write-Host "Unified CSV:   $UnifiedOutputPath"
Write-Host "HTML Report:   $DeviceOutputPath"

