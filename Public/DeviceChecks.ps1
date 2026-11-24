# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
$DeviceDetails = New-Object 'System.Collections.Generic.List[object]'

foreach ($Computer in $TargetComputers) {

    Write-Host ("  [{0}] Starting checks..." -f $Computer)

    $Detail = [PSCustomObject]@{
        ComputerName      = $Computer
        ADUserDetails  = ''
        Services          = ''
        MappedDrives      = ''
        CachedCredentials = ''
        SavedWifi         = ''
        ScheduledTasks    = ''
        StartupItems      = ''
        #Sessions          = ''
        LogonSessions     = ''
    }

    # ======= AD User Details (runs locally on DC; no remote execution) =======
    Write-Host ("  [{0}] AD User Details..." -f $Computer)
    try {
        $adUser = Get-ADUser $UserName -Properties `
            HomeDrive, HomeDirectory, ProfilePath, ScriptPath,
            LockedOut, BadLogonCount, LastBadPasswordAttempt,
            PasswordLastSet, LastLogonDate, LogonWorkstations,
            'msDS-SupportedEncryptionTypes' -ErrorAction Stop

        $adInfo = [PSCustomObject]@{
            LockedOut                    = $adUser.LockedOut
            BadLogonCount                = $adUser.BadLogonCount
            LastBadPasswordAttempt       = $adUser.LastBadPasswordAttempt
            PasswordLastSet              = $adUser.PasswordLastSet
            LastLogonDate                = $adUser.LastLogonDate
            HomeDrive                    = $adUser.HomeDrive
            HomeDirectory                = $adUser.HomeDirectory
            ProfilePath                  = $adUser.ProfilePath
            LogonScript                  = $adUser.ScriptPath
            AllowedWorkstations          = if ($adUser.LogonWorkstations) { $adUser.LogonWorkstations } else { 'All' }
            msDSSupportedEncryptionTypes = $adUser.'msDS-SupportedEncryptionTypes'
        }
        $Detail.ADUserDetails = $adInfo | ConvertTo-Html -Fragment | Out-String
    } catch {
        $Detail.ADUserDetails = "<p>Unable to query AD user: $($_.Exception.Message)</p>"
    }

    # ======= Services (WMI query) =======
    Write-Host ("  [{0}] Services..." -f $Computer)
    try {
        $svc = Get-WmiObject -ComputerName $Computer -Class Win32_Service -ErrorAction Stop |
               Where-Object { $_.StartName -like ("*{0}*" -f $UserName) } |
               Select-Object Name, DisplayName, StartName, State, StartMode
        $Detail.Services = $svc | ConvertTo-Html -Fragment | Out-String
    } catch {
        $Detail.Services = "<p>Unable to query services: $($_.Exception.Message)</p>"
    }

   # ======= Mapped Drives (HKU\<SID>\Network; loaded hives only) =======
    Write-Host ("  [{0}] MappedDrives (HKU\<SID>\Network)..." -f $Computer)
    try {
        $psMapped = @'
$ErrorActionPreference = 'SilentlyContinue'
$sids = Get-ChildItem 'Registry::HKEY_USERS' |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
        Select-Object -ExpandProperty PSChildName

if (-not $sids -or $sids.Count -eq 0) {
    'No loaded user hives found under HKU (no interactive users loaded).'
} else {
    foreach ($sid in $sids) {
        '============================================================'
        "SID: $sid"
        $netPath = "Registry::HKEY_USERS\$sid\Network"
        if (-not (Test-Path $netPath)) {
            '  (No Network subkey - no mapped drives for this hive)'
            continue
        }
        $drives = Get-ChildItem $netPath -ErrorAction SilentlyContinue
        if (-not $drives -or $drives.Count -eq 0) {
            '  (Network key exists but no drive subkeys)'
        } else {
            foreach ($d in $drives) {
                $letter     = $d.PSChildName
                $remotePath = (Get-ItemProperty -Path $d.PSPath -Name RemotePath -ErrorAction SilentlyContinue).RemotePath
                $userName   = (Get-ItemProperty -Path $d.PSPath -Name UserName   -ErrorAction SilentlyContinue).UserName
                "  Drive : $letter"
                "  Path  : $remotePath"
                if ($userName) { "  As    : $userName" }
                ''
            }
        }
    }
}
'@
        $txt = Invoke-RemotePSWmi -ComputerName $Computer -PsCode $psMapped -TimeoutSec 60
        $Detail.MappedDrives = "<pre>$txt</pre>"
    } catch {
        $Detail.MappedDrives = "<p>Unable to query mapped drives: $($_.Exception.Message)</p>"
    }


    # ======= Cached Credentials (cmdkey) =======
    Write-Host ("  [{0}] CachedCredentials..." -f $Computer)
    try {
        $txt = Invoke-RemoteCmdWmi -ComputerName $Computer -CommandLine "cmdkey /list" -TimeoutSec 30
        $Detail.CachedCredentials = "<pre>$txt</pre>"
    } catch {
        $Detail.CachedCredentials = "<p>Unable to run cmdkey: $($_.Exception.Message)</p>"
    }

    # ======= Saved WiFi Profiles (netsh wlan) =======
    Write-Host ("  [{0}] SavedWifi..." -f $Computer)
    try {
        $txt = Invoke-RemoteCmdWmi -ComputerName $Computer -CommandLine "netsh wlan show profiles" -TimeoutSec 45
        $Detail.SavedWifi = "<pre>$txt</pre>"
    } catch {
        $Detail.SavedWifi = "<p>Unable to run netsh wlan (common on servers/no WLAN): $($_.Exception.Message)</p>"
    }

    # ======= Scheduled Tasks (only Run As User matches; optional TaskName exclusions) =======
    Write-Host ("  [{0}] ScheduledTasks..." -f $Computer)
    $TaskNameExcludeRegex = ''  # set to regex to exclude tasks by TaskName, or leave blank
    try {
        $raw = Invoke-RemoteCmdWmi -ComputerName $Computer -CommandLine "schtasks /query /v /fo LIST" -TimeoutSec 150
        $blocks = $raw -split "(\r?\n){2,}" | Where-Object { $_.Trim() }

        $u = $UserName
        $fqdn = $DNSZone
        $domainNetbiosGuess = $env:USERDOMAIN

        $allowed = @(
            $u,
            "$domainNetbiosGuess\$u",
            "$fqdn\$u",
            "$u@$fqdn"
        ) | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.ToUpper() } | Select-Object -Unique

        $kept = @()
        foreach ($b in $blocks) {
            $taskName = ([regex]::Match($b, '(?im)^\s*TaskName:\s*(.+?)\s*$')).Groups[1].Value.Trim()
            $runAs    = ([regex]::Match($b, '(?im)^\s*Run As User:\s*(.+?)\s*$')).Groups[1].Value.Trim()

            if (-not $taskName -or -not $runAs) { continue }
            if ($TaskNameExcludeRegex -and ($taskName -match $TaskNameExcludeRegex)) { continue }

            if ($allowed -contains $runAs.ToUpper()) { $kept += $b }
        }

        if ($kept.Count -gt 0) {
            $sep = [Environment]::NewLine + [Environment]::NewLine
            $Detail.ScheduledTasks = "<pre>$([string]::Join($sep, $kept))</pre>"
        } else {
            $Detail.ScheduledTasks = "<p>No scheduled tasks found where <strong>Run As User</strong> matches <strong>$UserName</strong>.</p>"
        }
    } catch {
        $Detail.ScheduledTasks = "<p>Unable to query scheduled tasks: $($_.Exception.Message)</p>"
    }

    # ======= Startup Items (HKLM + loaded HKU SIDs; no NTUSER.DAT loads) =======
    Write-Host ("  [{0}] StartupItems (HKLM + loaded HKU)..." -f $Computer)
    try {
        $psStartup = @'
$ErrorActionPreference = 'SilentlyContinue'

'==================== HKLM Run ===================='
$r = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty)' }

'==================== HKLM RunOnce ===================='
$r = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty)' }

'==================== Loaded HKU User Hives ===================='
$sids = Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
if (-not $sids -or $sids.Count -eq 0) {
    'No loaded user hives found under HKU (no interactive users loaded).'
} else {
    foreach ($k in $sids) {
        $sid = $k.PSChildName
        '============================================================'
        "SID: $sid"
        '---- Run ----'
        $r = Get-ItemProperty ("Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Run" -f $sid) -ErrorAction SilentlyContinue
        if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty or key does not exist)' }
        '---- RunOnce ----'
        $r = Get-ItemProperty ("Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\RunOnce" -f $sid) -ErrorAction SilentlyContinue
        if ($r) { $r | Select-Object * -ExcludeProperty PS* | Format-List | Out-String } else { '(empty or key does not exist)' }
    }
}
'@
        $txt = Invoke-RemotePSWmi -ComputerName $Computer -PsCode $psStartup -TimeoutSec 90
        $Detail.StartupItems = "<pre>$txt</pre>"
    } catch {
        $Detail.StartupItems = "<p>Unable to query startup items: $($_.Exception.Message)</p>"
    }

    # ======= LSA Logon Sessions (klist) =======
    Write-Host ("  [{0}] LogonSessions..." -f $Computer)
    try {
        $NewLine = [Environment]::NewLine
        $KlistOutput = Invoke-RemoteCmdWmi `
            -ComputerName $Computer `
            -CommandLine "klist sessions" `
            -TimeoutSec 30
        $SessionPattern =
            "\\{0}\s" -f [regex]::Escape($UserName)
        $MatchingSessions = @($KlistOutput -split "`r?`n" |
            Where-Object { $_ -match $SessionPattern })

        $QueryUserFailed = $false
        $QueryUserOutput = try {
            Get-InteractiveSessionsTextWmi `
                -ComputerName $Computer
        } catch {
            $QueryUserFailed = $true
            "query user failed: $($_.Exception.Message)"
        }
        $UserPattern =
            "\b$([regex]::Escape($UserName))\b"
        $QueryUserMatches = @($QueryUserOutput -split "`r?`n" |
            Where-Object { $_ -match $UserPattern })

        $SectionHtml = ''
        if ($MatchingSessions.Count -gt 0) {
            $SectionHtml +=
                "<p><strong>$($MatchingSessions.Count) LSA " +
                "session(s) for $UserName.</strong> " +
                "If not listed in query user, they " +
                "are orphaned and retry Kerberos " +
                "with a stale password " +
                "(reboot to clear).</p>" +
                "<pre>$($MatchingSessions -join $NewLine)</pre>"
        }
        if ($QueryUserMatches.Count -gt 0) {
            $SectionHtml +=
                "<h4>query user</h4>" +
                "<pre>$($QueryUserMatches -join $NewLine)</pre>"
        }
        if ($QueryUserFailed) {
            $SectionHtml += "<p>$QueryUserOutput</p>"
        }
        $Detail.LogonSessions = $SectionHtml
    } catch {
        $Detail.LogonSessions =
            "<p>klist failed: " +
            "$($_.Exception.Message)</p>"
    }

    $DeviceDetails.Add($Detail)

}


# ─────────────────────────────────────────────────────────────────────────────
# Device Security Event Scan (WMI/DCOM + wevtutil export + admin$ pull)
# ─────────────────────────────────────────────────────────────────────────────

Write-Host '  Scanning Security Events on target devices (RPC, server-side user filter)...'

$AllDeviceEvents = [System.Collections.Generic.List[object]]::new()
$MaxDeviceEvents = 2000   # safety cap per computer; raise if needed

# Device scan uses ONLY failure/lockout/change IDs (Group1)
# Group2 success events (4624,4634,4672,etc) are very high volume on workstations
# and are not useful for lockout source analysis on the endpoint.
$DeviceEventIds = $EventIdsGroup1 | Sort-Object -Unique

foreach ($Computer in $TargetComputers) {
    if ($Computer -in $DCShortNames) {
        Write-Host "  [$Computer] DC - skipping event scan."
        continue
    }
    Write-Host ("  [{0}] Querying Security log (server-side filter)..." -f $Computer)
    try {
        $effectiveEnd = $EndDate
        if ($effectiveEnd -gt (Get-Date)) { $effectiveEnd = Get-Date }

        $s = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $e = $effectiveEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')

        $idFilter  = ($DeviceEventIds | ForEach-Object { "EventID=$([int]$_)" }) -join ' or '

        $userFilter = ''
        if ($UserName) {
            $userFilter = " and (EventData[Data[@Name='TargetUserName']='$UserName'] or " +
                          "EventData[Data[@Name='TargetUserName']='$UserName@$DNSZone'])"
        }

        $xPath = "*[System[($idFilter) and TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]$userFilter]"

        $filterXml = "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>$xPath</Select></Query></QueryList>"

        # Primary: FilterXml with server-side user filter (fastest)
        $Events = $null
        try {
            $Events = Get-WinEvent -ComputerName $Computer -FilterXml $filterXml `
                -MaxEvents $MaxDeviceEvents -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -like '*No events were found*') {
                Write-Host ("  [{0}] No matching events in window." -f $Computer)
                continue
            }
            # Fallback: FilterHashtable without user filter (filter user client-side)
            Write-Warning ("  [{0}] FilterXml failed ({1}), falling back..." -f $Computer, $_.Exception.Message)
            try {
                $Events = Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = $DeviceEventIds
                    StartTime = $StartDate
                } -MaxEvents $MaxDeviceEvents -ErrorAction Stop |
                Where-Object { $_.TimeCreated -le $effectiveEnd }
            } catch {
                if ($_.Exception.Message -like '*No events were found*') {
                    Write-Host ("  [{0}] No matching events in window (fallback)." -f $Computer)
                    continue
                }
                throw
            }
        }

        $matched = 0
        foreach ($Ev in $Events) {
            try {
                $x = [xml]$Ev.ToXml()
                $d = @{}
                foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
                if ($Ev.Id -eq 4740 -and
                    (-not $d['CallerComputerName'] -or
                     $d['CallerComputerName'] -eq '-')) {
                    $m = [regex]::Match($Ev.Message,
                        'Caller Computer Name:\s+(\S+)')
                    if ($m.Success) {
                        $d['CallerComputerName'] = $m.Groups[1].Value
                    }
                }

                $tu = $d['TargetUserName']
                if ($tu -ne $UserName -and $tu -ne "$UserName@$DNSZone") { continue }

                $AllDeviceEvents.Add([PSCustomObject]@{
                    TimeCreated      = $Ev.TimeCreated
                    EventId          = $Ev.Id
                    SourceComputer   = $Computer
                    TargetUserName   = $tu
                    SubjectUserName  = $d['SubjectUserName']
                    WorkstationName  = $d['WorkstationName']
                    CallerComputer   = $d['CallerComputerName']
                    IpAddress        = $d['IpAddress']
                    LogonType        = $d['LogonType']
                    AuthPackage      = $d['AuthenticationPackageName']
                    FailureReason    = $d['FailureReason']
                    Status           = $d['Status']
                    SubStatus        = $d['SubStatus']
                    ProcessName      = $d['ProcessName']
                    LogonProcessName = $d['LogonProcessName']
                })
                $matched++
            } catch {}
        }

        $capped = if ($Events.Count -ge $MaxDeviceEvents) { " (CAPPED at $MaxDeviceEvents)" } else { '' }
        Write-Host ("  [{0}] Done. Raw: {1}{2}  Matched user: {3}" -f $Computer, $Events.Count, $capped, $matched)

    } catch {
        Write-Warning ("  [{0}] RPC event query failed: {1}" -f $Computer, $_.Exception.Message)
    }
}

Write-Host "  Device event scan: $($AllDeviceEvents.Count) events."

