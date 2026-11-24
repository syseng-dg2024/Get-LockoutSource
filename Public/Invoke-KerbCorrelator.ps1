function Invoke-KerbCorrelator {
    <#
    .SYNOPSIS
      Kerberos Failure Correlator. Traces the KDC, Kerberos, AD DS and LDAP-client ETW providers
      (manifest providers, decodable without Microsoft TMF files), decodes every failure for one
      account, ranks the processes active around each failure against a random baseline, and
      writes a self-contained HTML report plus a CSV.
    .EXAMPLE
      .\Invoke-KerbCorrelator.ps1 -User sysengadmin -Seconds 180
    .EXAMPLE
      .\Invoke-KerbCorrelator.ps1 -User sysengadmin -EtlPath C:\Windows\Temp\kerbman-20261120-114708.etl
    #>
    [CmdletBinding()]
    param(
        [string]$User = 'sysengadmin',
        [int]   $LeadMs   = 500,
        [int]   $Seconds  = 180,
        [string]$EtlPath,
        [int]   $WindowMs = 2000,
        [string]$OutDir   = 'C:\Windows\Temp',
        [switch]$NoOpen
    )

    $Stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Html   = Join-Path $OutDir "KerbCorrelator-$User-$Stamp.html"
    $CsvOut = Join-Path $OutDir "KerbCorrelator-$User-$Stamp.csv"
    $UserRx = [regex]::Escape($User)

    # ---------- Status code decoding (Kerberos decimal/hex and NTSTATUS) ----------
    $Codes = @{
      '0x0'='OK'; '0x6'='C_PRINCIPAL_UNKNOWN - account not found'; '0x7'='S_PRINCIPAL_UNKNOWN - SPN not found'
      '0xC'='POLICY - logon restriction'; '0xE'='ETYPE_NOSUPP - encryption type not supported'
      '0x12'='CLIENT_REVOKED - account disabled, locked out or expired'; '0x17'='KEY_EXPIRED - password expired'
      '0x18'='PREAUTH_FAILED - wrong password'; '0x19'='PREAUTH_REQUIRED - normal first step'
      '0x1F'='BAD_INTEGRITY'; '0x20'='TKT_EXPIRED'; '0x25'='SKEW - clock skew'; '0x44'='WRONG_REALM'
      '0xC000006A'='Wrong password'; '0xC000006D'='Logon failure'; '0xC0000064'='No such user'
      '0xC0000234'='Account locked out'; '0xC0000072'='Account disabled'; '0xC0000071'='Password expired'
      '0xC0000193'='Account expired'; '0xC000006F'='Outside logon hours'; '0xC0000070'='Workstation restriction'
    }
    function Get-Code($v) {
        $s = "$v".Trim(); if (-not $s) { return $null }
        try {
            if ($s -match '^0x') { $n = [Convert]::ToInt64($s.Substring(2),16) } else { $n = [int64]$s }
            return ('0x{0:X}' -f $n)
        } catch { return $s }
    }
    function Get-CodeText($v) {
        $c = Get-Code $v; if (-not $c) { return '' }
        $t = $Codes[$c]; if (-not $t) { $t = 'unknown' }
        "$c  $t"
    }
    function E($s) { [System.Net.WebUtility]::HtmlEncode("$s") }

    # ---------- Process / service map (sampled during capture so short-lived PIDs are kept) ----------
    $script:Procs = @{}
    function Update-ProcMap {
        $svc = @{}
        Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object { $_.ProcessId } |
            ForEach-Object { $svc[[int]$_.ProcessId] += @($_.Name) }
        foreach ($p in Get-CimInstance Win32_Process -EA SilentlyContinue) {
            $id = [int]$p.ProcessId
            if (-not $script:Procs.ContainsKey($id)) {
                $script:Procs[$id] = [pscustomobject]@{
                    Name = $p.Name; Path = $p.ExecutablePath; CommandLine = $p.CommandLine
                    Services = (@($svc[$id]) -join ', '); Started = $p.CreationDate }
            }
        }
    }

    # ---------- Capture ----------
    $Providers = 'Microsoft-Windows-Security-Kerberos','Microsoft-Windows-Kerberos-Key-Distribution-Center',
                 'Microsoft-Windows-ActiveDirectory_DomainService','Microsoft-Windows-LDAP-Client',
                 'Microsoft-Windows-Kernel-Network','Microsoft-Windows-Winsock-AFD','Microsoft-Windows-Schannel-Events',
                 'Microsoft-Windows-SMBServer','Microsoft-Windows-RPC'
    $NetRx = 'Kernel-Network|Winsock-AFD|Schannel|SMBServer|^RPC'
    if (-not $EtlPath) {
        $EtlPath = Join-Path $OutDir "KerbCorrelator-$Stamp.etl"
        $S  = 'KerbCorrelator'
        $KP = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
        if (-not (Test-Path $KP)) { New-Item $KP -Force | Out-Null }
        $OldLvl = (Get-ItemProperty $KP -EA SilentlyContinue).LogLevel
        cmd /c "logman stop $S -ets >nul 2>&1"
        logman create trace $S -o $EtlPath -ets -nb 128 512 -bs 1024 -max 1024 | Out-Null
        foreach ($P in $Providers) {
            if (Get-WinEvent -ListProvider $P -EA SilentlyContinue) {
                logman update trace $S -p $P 0xffffffffffffffff 0xff -ets | Out-Null; Write-Host "  + $P" -ForegroundColor Green
            } else { Write-Host "  - not on this OS: $P" -ForegroundColor DarkGray }
        }
        $T0 = Get-Date
        try {
            Update-ProcMap
            $End = $T0.AddSeconds($Seconds)
            while ((Get-Date) -lt $End) {
                $left = [int]($End - (Get-Date)).TotalSeconds
                Write-Progress -Activity "Kerberos Correlator: tracing $User" -Status "$left s left" -PercentComplete (100 - 100*$left/$Seconds)
                Start-Sleep 5; Update-ProcMap
            }
        } finally {
            Write-Progress -Activity 'Kerberos Correlator' -Completed
            cmd /c "logman stop $S -ets >nul 2>&1"
            if ($null -eq $OldLvl) { Remove-ItemProperty $KP LogLevel -EA SilentlyContinue } else { Set-ItemProperty $KP LogLevel $OldLvl }
            Write-Host 'Trace stopped, logging settings restored.' -ForegroundColor Cyan
        }
    } else { Update-ProcMap }

    # ---------- Parse ETL (filtered: core providers fully, network providers only for lsass) ----------
    function ConvertTo-Row($Ev) {
        $x = [xml]$Ev.ToXml(); $d = [ordered]@{}
        foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
        [pscustomobject]@{
            Time = $Ev.TimeCreated; Provider = ($Ev.ProviderName -replace '^Microsoft-Windows-','')
            Id = $Ev.Id; PID = [int]$Ev.ProcessId; TID = [int]$Ev.ThreadId; Data = $d
            Flat = (($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' | '); Ips = @() }
    }
    $NetProv  = @($Providers | Where-Object { $_ -match 'Kernel-Network|Winsock-AFD|Schannel|SMBServer|Windows-RPC$' })
    $CoreProv = @($Providers | Where-Object { $NetProv -notcontains $_ })
    $CoreQ = ($CoreProv | ForEach-Object { "@Name='$_'" }) -join ' or '

    Write-Host 'Decoding Kerberos / KDC / AD DS / LDAP events...'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Core = @(Get-WinEvent -Path $EtlPath -Oldest -FilterXPath "*[System[Provider[$CoreQ]]]" -EA SilentlyContinue | ForEach-Object { ConvertTo-Row $_ })
    Write-Host "  $($Core.Count) events in $([int]$sw.Elapsed.TotalSeconds) s"
    if (-not $Core) { Write-Warning "No decodable events in $EtlPath"; return [pscustomobject]@{ User=$User; Failures=0; Verdict='No decodable events'; Tone='warn'; TopCaller=$null; TopProcess=$null; ReportPath=$null; CsvPath=$null } }
    $T0 = $Core[0].Time; $T1 = $Core[-1].Time

    # Failures for the account (non-zero status, excluding the normal PREAUTH_REQUIRED step)
    $Fails = @($Core | Where-Object {
        $_.Flat -match $UserRx -and $_.Data.Contains('Status') -and ((Get-Code $_.Data['Status']) -notin '0x0','0x19') })
    $KdcPids = @($Fails | ForEach-Object { $_.PID } | Select-Object -Unique)
    if (-not $KdcPids) { $KdcPids = @((Get-Process lsass -EA SilentlyContinue).Id) }

    $LocalIps = @('0.0.0.0','127.0.0.1','::1','::') + @(Get-NetIPAddress -EA 0 | ForEach-Object { $_.IPAddress })
    $Net = @()
    if ($NetProv -and $KdcPids) {
        Write-Host "Decoding network events for KDC process $($KdcPids -join ', ') only..."
        $sw.Restart()
        $NetQ = ($NetProv | ForEach-Object { "@Name='$_'" }) -join ' or '
        $PidQ = ($KdcPids | ForEach-Object { "Execution[@ProcessID=$_]" }) -join ' or '
        $DPidQ = ($KdcPids | ForEach-Object { "Data[@Name='PID']=$_" }) -join ' or '
        $Xp = "*[System[Provider[$NetQ]] and (System[$PidQ] or EventData[$DPidQ])]"
        $Net = @(Get-WinEvent -Path $EtlPath -Oldest -FilterXPath $Xp -EA SilentlyContinue | ForEach-Object {
            $r = ConvertTo-Row $_
            $r.Ips = @([regex]::Matches($r.Flat, '\b(?:\d{1,3}\.){3}\d{1,3}\b') | ForEach-Object { $_.Value } |
                       Where-Object { $_ -notin $LocalIps -and $_ -notmatch '^(0|255)\.' } | Select-Object -Unique)
            $r })
        Write-Host "  $($Net.Count) events in $([int]$sw.Elapsed.TotalSeconds) s"
    }
    $Rows = @($Core + $Net | Sort-Object Time)

    # ---------- Security log for the same window ----------
    $Sec = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768,4769,4771,4776,4625,4648,4740;
              StartTime=$T0.AddSeconds(-5);EndTime=$T1.AddSeconds(5)} -EA SilentlyContinue |
        Where-Object { $_.Message -match $UserRx } | ForEach-Object {
            $x = [xml]$_.ToXml(); $d = @{}
            foreach ($n in @($x.Event.EventData.Data)) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
            $st = @($d['SubStatus'],$d['Status'],$d['FailureCode'] | Where-Object { $_ -and $_ -ne '0x0' })[0]
            [pscustomobject]@{
                Time = $_.TimeCreated; Id = $_.Id; Status = (Get-CodeText $st)
                Address = (@($d['IpAddress'],$d['IpPort']) -join ':').Trim(':')
                Process = $d['ProcessName']; Workstation = (@($d['WorkstationName'],$d['Workstation'],$d['CallerComputerName'] | Where-Object { $_ })[0]) }
        })

    # ---------- Correlation ----------
    function Get-Near($times, $points) {
        $n = 0
        foreach ($p in $points) { foreach ($t in $times) { if ([math]::Abs(($t - $p).TotalMilliseconds) -le $WindowMs) { $n++; break } } }
        $n
    }
    $Rand = New-Object System.Random 42
    $Span = ($T1 - $T0).TotalMilliseconds
    $Ctrl = @(1..([math]::Max(20, $Fails.Count * 5)) | ForEach-Object { $T0.AddMilliseconds($Rand.NextDouble() * $Span) })
    $FailTimes = @($Fails | ForEach-Object { $_.Time })
    $Suspects = @(foreach ($g in ($Rows | Where-Object { $Fails -notcontains $_ -and $_.Provider -notmatch $NetRx } | Group-Object PID)) {
        $times = @($g.Group | ForEach-Object { $_.Time })
        $fh = if ($FailTimes) { Get-Near $times $FailTimes } else { 0 }
        $ch = Get-Near $times $Ctrl
        $fp = if ($FailTimes) { [math]::Round(100*$fh/$FailTimes.Count) } else { 0 }
        $cp = [math]::Round(100*$ch/$Ctrl.Count)
        $pi = $script:Procs[[int]$g.Name]
        [pscustomobject]@{
            PID = [int]$g.Name; Process = $(if ($pi) { $pi.Name } else { '(exited / unknown)' })
            Services = $(if ($pi) { $pi.Services }); Path = $(if ($pi) { $pi.Path })
            Events = $g.Count; Providers = (($g.Group.Provider | Select-Object -Unique) -join ', ')
            FailHits = $fh; FailPct = $fp; RandomPct = $cp; Score = $fp - $cp
            Note = $(if ($KdcPids -contains [int]$g.Name) { 'Same process as the KDC (lsass)' }) }
    }) | Sort-Object @{e={[bool]$_.Note}}, @{e='Score';Descending=$true}, @{e='FailPct';Descending=$true}

    $Ips = @($Rows | Where-Object { $_.Flat -match $UserRx } | ForEach-Object {
        [regex]::Matches($_.Flat, '\b(?:\d{1,3}\.){3}\d{1,3}\b') | ForEach-Object { $_.Value } } |
        Where-Object { $_ -notin '0.0.0.0','127.0.0.1' } | Select-Object -Unique)

    # ---------- Caller address (network events in the KDC process just before each failure) ----------
    function Get-NetIps($row) { $row.Ips }
    function Test-KdcNet($row) { $true }   # network rows are already filtered to the KDC process
    $CallerHits = @{}; $CallerTid = @{}; $CallerProv = @{}; $FailCaller = @{}
    foreach ($f in $Fails) {
        $lead = @($Net | Where-Object { $d = ($f.Time - $_.Time).TotalMilliseconds; $d -ge -50 -and $d -le $LeadMs -and (Test-KdcNet $_) })
        $seen = @{}
        foreach ($n in $lead) { foreach ($ip in (Get-NetIps $n)) {
            if (-not $seen[$ip]) { $seen[$ip] = 1; $CallerHits[$ip] = 1 + [int]$CallerHits[$ip] }
            if ($n.TID -eq $f.TID) { $CallerTid[$ip] = 1 + [int]$CallerTid[$ip] }
            $CallerProv[$ip] = @(@($CallerProv[$ip]) + $n.Provider | Where-Object { $_ } | Select-Object -Unique)
        } }
        $FailCaller[$f] = @($seen.Keys)
    }
    $Callers = @(foreach ($ip in $CallerHits.Keys) {
        $ctl = 0
        foreach ($c in $Ctrl) { if ($Net | Where-Object { $d = ($c - $_.Time).TotalMilliseconds; $d -ge -50 -and $d -le $LeadMs -and (Test-KdcNet $_) -and ((Get-NetIps $_) -contains $ip) } | Select-Object -First 1) { $ctl++ } }
        $fp = [math]::Round(100*$CallerHits[$ip]/[math]::Max(1,$Fails.Count)); $cp = [math]::Round(100*$ctl/$Ctrl.Count)
        $hn = $null; try { $hn = (Resolve-DnsName $ip -EA Stop | Select-Object -First 1).NameHost } catch {}
        [pscustomobject]@{ IP=$ip; Hostname=$hn; FailHits=$CallerHits[$ip]; FailPct=$fp; RandomPct=$cp; Score=$fp-$cp
            SameTid=[int]$CallerTid[$ip]; Via=(($CallerProv[$ip] | ForEach-Object { $_ -replace '-Events$','' }) -join ', ') }
    }) | Sort-Object Score -Descending
    $TopCaller = $Callers | Select-Object -First 1
    $NoNetFails = @($Fails | Where-Object { -not $FailCaller[$_] }).Count

    # ---------- Verdict ----------
    $Top = $Suspects | Where-Object { -not $_.Note } | Select-Object -First 1
    $StatusMix = $Fails | Group-Object { Get-CodeText $_.Data['Status'] } | Sort-Object Count -Descending
    if (-not $Fails) {
        $Verdict = "No failures for $User were captured. Trace longer, or during a burst."; $Tone = 'warn'
    } elseif ($Ips) {
        $Verdict = "The failing requests carry client address(es) $($Ips -join ', '). Investigate those hosts."; $Tone = 'bad'
    } elseif ($TopCaller -and $TopCaller.FailPct -ge 80 -and $TopCaller.Score -ge 40) {
        $Verdict = "Caller found: $($TopCaller.IP)$(if($TopCaller.Hostname){' (' + $TopCaller.Hostname + ')'}) reaches lsass via $($TopCaller.Via) within $LeadMs ms before $($TopCaller.FailHits) of $($Fails.Count) failures ($($TopCaller.FailPct)% vs $($TopCaller.RandomPct)% at random moments; same thread $($TopCaller.SameTid) times). Update the credential on that host."; $Tone = 'bad'
    } elseif ($Top -and $Top.FailPct -ge 80 -and $Top.Score -ge 40) {
        $Verdict = "PID $($Top.PID) ($($Top.Process)$(if($Top.Services){' / ' + $Top.Services})) is active around $($Top.FailPct)% of failures vs $($Top.RandomPct)% of random moments. Strong local suspect."; $Tone = 'bad'
    } else {
        $Verdict = "No process correlates with the failures and the requests carry no client address. The KDC in lsass is validating a credential on behalf of an in-process caller (for example an encrypted LDAP bind or another lsass-hosted service). Decoding the WPP Kerberos trace (Microsoft) or a controlled account-disable test is required to name it.$(if($Net.Count -and $NoNetFails -eq $Fails.Count){' No lsass network activity preceded any failure, so the request most likely starts inside this DC.'})"; $Tone = 'warn'
    }

    # ---------- CSV ----------
    $Suspects | Export-Csv $CsvOut -NoTypeInformation
    $Callers | Export-Csv ($CsvOut -replace '\.csv$','-callers.csv') -NoTypeInformation

    # ---------- HTML ----------
    $sb = New-Object System.Text.StringBuilder
    function A($s) { [void]$sb.AppendLine($s) }
    $css = @'
    :root{--bg:#0f1420;--card:#171e2d;--line:#263047;--tx:#e6ebf5;--mu:#8b97b0;--ac:#5aa9ff;--bad:#ff6b6b;--warn:#f7b955;--ok:#4cd4a0}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 Segoe UI,Arial,sans-serif}
    .wrap{max-width:1280px;margin:0 auto;padding:28px}h1{margin:0;font-size:24px}h2{font-size:16px;margin:28px 0 10px;color:var(--ac);text-transform:uppercase;letter-spacing:.06em}
    .sub{color:var(--mu)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:18px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.big{font-size:28px;font-weight:600}.lbl{color:var(--mu);font-size:12px;text-transform:uppercase}
    .verdict{border-left:5px solid var(--warn);margin-top:18px}.verdict.bad{border-left-color:var(--bad)}.verdict.ok{border-left-color:var(--ok)}
    table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
    th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:#1d2638;color:var(--mu);font-weight:600;font-size:12px;text-transform:uppercase}
    tr.hit td{background:#3a1f26}code,.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
    .bar{height:8px;background:#26314a;border-radius:4px;min-width:120px}.bar i{display:block;height:8px;border-radius:4px;background:var(--ac)}
    .pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;background:#26314a}.pill.bad{background:#5a2730;color:#ffb3b3}
    details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:8px 12px}summary{cursor:pointer;font-weight:600}
    '@
    A "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Kerberos Correlator - $(E $User)</title><style>$css</style></head><body><div class='wrap'>"
    A "<h1>Kerberos Failure Correlator</h1><div class='sub'>Account <b>$(E $User)</b> on <b>$(E $env:COMPUTERNAME)</b> &middot; $(E $T0.ToString('yyyy-MM-dd HH:mm:ss')) to $(E $T1.ToString('HH:mm:ss')) &middot; window &plusmn;$WindowMs ms</div>"
    A "<div class='grid'>"
    A "<div class='card'><div class='lbl'>Failures captured</div><div class='big'>$($Fails.Count)</div></div>"
    A "<div class='card'><div class='lbl'>Events decoded</div><div class='big'>$($Rows.Count)</div></div>"
    A "<div class='card'><div class='lbl'>Security events (account)</div><div class='big'>$($Sec.Count)</div></div>"
    A "<div class='card'><div class='lbl'>Client addresses in failures</div><div class='big'>$(if($Ips){E ($Ips -join ', ')}else{'none'})</div></div>"
    A "</div>"
    A "<div class='card verdict $Tone'><div class='lbl'>Verdict</div>$(E $Verdict)</div>"

    A "<h2>Failure status codes</h2><table><tr><th>Status</th><th>Count</th></tr>"
    foreach ($s in $StatusMix) { A "<tr><td class='mono'>$(E $s.Name)</td><td>$($s.Count)</td></tr>" }
    A "</table>"

    A "<h2>Caller address</h2><p class='sub'>Remote IPs seen in lsass network events (Kernel-Network, AFD, Schannel, SMB, RPC) up to $LeadMs ms before each failure. $($Net.Count) network events decoded; $NoNetFails of $($Fails.Count) failures had none.</p><table><tr><th>IP</th><th>Hostname</th><th>Near failures</th><th>Random baseline</th><th>Score</th><th>Same TID</th><th>Via</th></tr>"
    foreach ($c in ($Callers | Select-Object -First 15)) {
        $w = [math]::Max(0,[math]::Min(100,$c.Score))
        A "<tr><td class='mono'><b>$(E $c.IP)</b></td><td>$(E $c.Hostname)</td><td>$($c.FailHits) / $($Fails.Count) ($($c.FailPct)%)</td><td>$($c.RandomPct)%</td><td><div class='bar'><i style='width:$w%'></i></div>$($c.Score)</td><td>$($c.SameTid)</td><td class='sub'>$(E $c.Via)</td></tr>"
    }
    if (-not $Callers) { A "<tr><td colspan='7' class='sub'>No remote address in lsass network events before any failure.</td></tr>" }
    A "</table>"

    A "<h2>Process ranking</h2><table><tr><th>PID</th><th>Process / service</th><th>Near failures</th><th>Random baseline</th><th>Score</th><th>Events</th><th>Providers</th></tr>"
    foreach ($s in ($Suspects | Select-Object -First 15)) {
        $w = [math]::Max(0,[math]::Min(100,$s.Score))
        A "<tr><td>$($s.PID)</td><td><b>$(E $s.Process)</b> $(if($s.Services){"<span class='pill'>$(E $s.Services)</span>"}) $(if($s.Note){"<span class='pill bad'>$(E $s.Note)</span>"})<div class='mono sub'>$(E $s.Path)</div></td><td>$($s.FailHits) / $($FailTimes.Count) ($($s.FailPct)%)</td><td>$($s.RandomPct)%</td><td><div class='bar'><i style='width:$w%'></i></div>$($s.Score)</td><td>$($s.Events)</td><td class='sub'>$(E $s.Providers)</td></tr>"
    }
    A "</table>"

    A "<h2>Failure timeline</h2><table><tr><th>Time</th><th>Source</th><th>PID / TID</th><th>Status</th><th>Service</th><th>Client address</th><th>Caller IP (network)</th></tr>"
    foreach ($f in $Fails) {
        $addr = @($f.Data['IpAddress'],$f.Data['ClientAddress'] | Where-Object { $_ })[0]
        A "<tr><td class='mono'>$(E $f.Time.ToString('HH:mm:ss.fff'))</td><td>$(E $f.Provider) $($f.Id)</td><td>$($f.PID) / $($f.TID)</td><td class='mono'>$(E (Get-CodeText $f.Data['Status']))</td><td class='mono'>$(E $f.Data['ServiceName'])</td><td class='mono'>$(if($addr){E $addr}else{'<span class=sub>none</span>'})</td><td class='mono'>$(if($FailCaller[$f]){E ($FailCaller[$f] -join ', ')}else{'<span class=sub>none</span>'})</td></tr>"
    }
    A "</table>"

    A "<h2>Context around each failure</h2>"
    foreach ($f in $Fails) {
        $near = $Rows | Where-Object { [math]::Abs(($_.Time - $f.Time).TotalMilliseconds) -le $WindowMs } | Select-Object -First 60
        A "<details><summary>$(E $f.Time.ToString('HH:mm:ss.fff')) &middot; $(E (Get-CodeText $f.Data['Status'])) &middot; $(@($near).Count) events in window</summary><table><tr><th>&Delta; ms</th><th>Provider / Id</th><th>PID / TID</th><th>Process</th><th>Data</th></tr>"
        foreach ($n in $near) {
            $dt = [math]::Round(($n.Time - $f.Time).TotalMilliseconds); $pi = $script:Procs[$n.PID]
            $cls = if ($n -eq $f) { " class='hit'" } else { '' }
            A "<tr$cls><td>$dt</td><td>$(E $n.Provider) $($n.Id)</td><td>$($n.PID) / $($n.TID)</td><td>$(if($pi){E $pi.Name})</td><td class='mono'>$(E $n.Flat)</td></tr>"
        }
        A "</table></details>"
    }

    A "<h2>Security log entries for the account</h2><table><tr><th>Time</th><th>Event</th><th>Status</th><th>Address</th><th>Workstation</th><th>Process</th></tr>"
    foreach ($s in $Sec) { A "<tr><td class='mono'>$(E $s.Time.ToString('HH:mm:ss.fff'))</td><td>$($s.Id)</td><td class='mono'>$(E $s.Status)</td><td class='mono'>$(E $s.Address)</td><td>$(E $s.Workstation)</td><td class='mono'>$(E $s.Process)</td></tr>" }
    A "</table><p class='sub'>Trace: $(E $EtlPath) &middot; CSV: $(E $CsvOut)</p></div></body></html>"

    [IO.File]::WriteAllText($Html, $sb.ToString(), [Text.Encoding]::UTF8)
    Write-Host "`nFailures: $($Fails.Count)   Decoded: $($Rows.Count)   Security: $($Sec.Count)"
    Write-Host "Verdict : $Verdict" -ForegroundColor Yellow
    Write-Host "Report  : $Html"
    Write-Host "CSV     : $CsvOut"
    if (-not $NoOpen) { Start-Process $Html }

    [pscustomobject]@{ User=$User; Failures=$Fails.Count; Verdict=$Verdict; Tone=$Tone
        TopCaller=$TopCaller; TopProcess=$Top; ReportPath=$Html; CsvPath=$CsvOut }
}
