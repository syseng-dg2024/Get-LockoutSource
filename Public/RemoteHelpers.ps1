# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 6: Device Analysis
# ==============================================================================

# ======= Session sweep (all servers) =======
Write-Host "`n[Phase 5b] Sweeping servers for sessions..."

$SweepServerNames = @($AllServers | ForEach-Object {
    if ($_ -is [string]) { $_ } else { $_.Name }
})

$SweepScriptBlock = {
    param($SweepUserName)
    $SessionPattern =
        "\\$([regex]::Escape($SweepUserName))\s"
    $MatchingSessions = @(klist sessions 2>$null |
        Where-Object { $_ -match $SessionPattern })
    if ($MatchingSessions.Count) {
        [PSCustomObject]@{
            Server       = $env:COMPUTERNAME
            SessionCount = $MatchingSessions.Count
        }
    }
}

$SweepResults = Invoke-Command `
    -ComputerName $SweepServerNames `
    -ScriptBlock $SweepScriptBlock `
    -ArgumentList $UserName `
    -ThrottleLimit 32 `
    -ErrorAction SilentlyContinue `
    -ErrorVariable SweepErrors

foreach ($SweepResult in $SweepResults) {
    $ServerName = $SweepResult.Server.ToUpper()
    Write-Host ("  + (Session) $ServerName " +
        "($($SweepResult.SessionCount))")
    if (-not $TargetComputers.Contains($ServerName)) {
        $TargetComputers.Add($ServerName)
    }
}

$UnreachableServers = @($SweepErrors.TargetObject |
    Sort-Object -Unique)
if ($UnreachableServers.Count) {
    Write-Warning ("  Sweep unreachable: " +
        ($UnreachableServers -join ', '))
}

Write-Host ("`n[Phase 6] Device analysis on {0} target(s)..." -f $TargetComputers.Count)

# --- Optional: path to PsExec (put it on the DC running the script) ---
# Recommended: store in same folder as script
$PsExecPath = Join-Path $script:ModuleRoot 'PsExec.exe'
$UsePsExec  = (Test-Path $PsExecPath)
Import-Module ActiveDirectory -ErrorAction Stop

function Invoke-RemoteCmdWmi {
    param(
        [Parameter(Mandatory=$true)] [string] $ComputerName,
        [Parameter(Mandatory=$true)] [string] $CommandLine,
        [int] $TimeoutSec = 60
    )

    $guid = [guid]::NewGuid().ToString('N')
    $outRemote = "C:\Windows\Temp\wmi_{0}.txt" -f $guid
    $uncOut    = "\\{0}\admin$\Temp\wmi_{1}.txt" -f $ComputerName, $guid

    $wrapped = "cmd.exe /c $CommandLine 1>`"$outRemote`" 2>&1"
    $r = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $wrapped -ErrorAction Stop
    if ($r.ReturnValue -ne 0) { throw ("WMI Win32_Process.Create failed (ReturnValue={0})" -f $r.ReturnValue) }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (Test-Path $uncOut) { break }
        Start-Sleep -Milliseconds 300
    }
    $sw.Stop()

    if (-not (Test-Path $uncOut)) { throw ("Timed out waiting for output file: {0}" -f $uncOut) }

    $text = (Get-Content -Path $uncOut -ErrorAction Stop) -join [Environment]::NewLine
    Remove-Item -Path $uncOut -Force -ErrorAction SilentlyContinue | Out-Null
    return $text
}

function Invoke-RemotePSWmi {
    param(
        [Parameter(Mandatory=$true)] [string] $ComputerName,
        [Parameter(Mandatory=$true)] [string] $PsCode,
        [int] $TimeoutSec = 90
    )
    $guid      = [guid]::NewGuid().ToString('N')
    $remoteOut = "C:\Windows\Temp\wmi_{0}.txt" -f $guid
    $uncOut    = "\\{0}\admin$\Temp\wmi_{1}.txt" -f $ComputerName, $guid
    $bytes     = [Text.Encoding]::Unicode.GetBytes($PsCode)
    $enc       = [Convert]::ToBase64String($bytes)
    $cmd       = "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc 1>`"$remoteOut`" 2>&1"
    try {
        $r = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $cmd -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw ("WMI process create failed (ReturnValue={0})" -f $r.ReturnValue) }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
            if (Test-Path $uncOut) { break }
            Start-Sleep -Milliseconds 350
        }
        $sw.Stop()
        if (-not (Test-Path $uncOut)) { throw ("Timed out waiting for output: {0}" -f $uncOut) }
        return (Get-Content -Path $uncOut -ErrorAction Stop) -join [Environment]::NewLine
    } finally {
        Remove-Item -Path $uncOut -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Get-LoadedUserRunKeysTextWmi {
    param([Parameter(Mandatory=$true)] [string] $ComputerName)

    $sidListRaw = Invoke-RemoteCmdWmi -ComputerName $ComputerName `
        -CommandLine 'reg query "HKU" | findstr /r /c:"HKEY_USERS\\S-1-5-21-"' -TimeoutSec 45

    $sids = $sidListRaw -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^HKEY_USERS\\S-1-5-21-' }

    if (-not $sids -or $sids.Count -eq 0) {
        return "No loaded user hives found under HKU (no interactive users loaded)."
    }

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($sid in $sids) {
        $out.Add("============================================================")
        $out.Add($sid)
        $out.Add("---- Run ----")
        $out.Add((Invoke-RemoteCmdWmi -ComputerName $ComputerName -CommandLine ('reg query "{0}\Software\Microsoft\Windows\CurrentVersion\Run"' -f $sid) -TimeoutSec 30))
        $out.Add("---- RunOnce ----")
        $out.Add((Invoke-RemoteCmdWmi -ComputerName $ComputerName -CommandLine ('reg query "{0}\Software\Microsoft\Windows\CurrentVersion\RunOnce"' -f $sid) -TimeoutSec 30))
    }

    return ($out -join [Environment]::NewLine)
}

function Get-InteractiveSessionsTextWmi {
    param([Parameter(Mandatory=$true)] [string] $ComputerName)

    # query user output example:
    # USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
    # username              console             1  Active      none   4/17/2026 8:01 AM
    return Invoke-RemoteCmdWmi -ComputerName $ComputerName -CommandLine 'query user' -TimeoutSec 30
}

function Get-SessionIdsForUser {
    param(
        [Parameter(Mandatory=$true)] [string] $QueryUserText,
        [Parameter(Mandatory=$true)] [string] $UserName
    )

    $ids = New-Object System.Collections.Generic.List[int]
    $lines = $QueryUserText -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    foreach ($ln in $lines) {
        # Normalize whitespace and split
        $parts = ($ln -replace '\s{2,}', ' ') -split ' '
        if ($parts.Count -lt 3) { continue }

        $u = $parts[0].Trim()
        # sometimes query user prepends ">" to current session
        $u = $u.TrimStart('>')

        if ($u -ieq $UserName -or $u -ilike "*\$UserName") {
            # ID is usually the 3rd column (index 2) after USERNAME SESSIONNAME ID ...
            # But SESSIONNAME may be missing; try to find the first int token in the row
            $idToken = ($parts | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
            if ($idToken) {
                [void]$ids.Add([int]$idToken)
            }
        }
    }

    return ($ids | Select-Object -Unique)
}

function Invoke-PsExecInteractiveNetUse {
    param(
        [Parameter(Mandatory=$true)] [string] $ComputerName,
        [Parameter(Mandatory=$true)] [int] $SessionId
    )

    # -accepteula: avoid prompt
    # -nobanner: cleaner output
    # -i <id>: interactive session
    # -s: run as SYSTEM *in that session* so it can see that session's mapped drives
    $args = @(
        '-accepteula','-nobanner',
        "\\$ComputerName",
        '-i', $SessionId.ToString(),
        '-s',
        'cmd.exe','/c','net use'
    )

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $p.StartInfo.FileName = $PsExecPath
    $p.StartInfo.Arguments = ($args -join ' ')
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError  = $true
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.CreateNoWindow  = $true

    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    return ($stdout + [Environment]::NewLine + $stderr).Trim()
}

