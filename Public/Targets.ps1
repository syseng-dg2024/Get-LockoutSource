# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 2: Build Target Computer List (PTR first, DNS Server A-record fallback)
# ==============================================================================
Write-Host "`n[Phase 2] Building target computer list..."

$DCShortNames    = @($DomainControllers | ForEach-Object { $_.Split('.')[0].ToUpper() })

#$TargetComputers = [System.Collections.Generic.List[string]]::new()
$TargetComputers = [System.Collections.Generic.List[string]]::new()
$KerbResults     = [System.Collections.Generic.List[object]]::new()

$SkipIPs         = [System.Collections.Generic.HashSet[string]]@('127.0.0.1','0.0.0.0','::1','-','')
$SeenIPs         = [System.Collections.Generic.HashSet[string]]::new()

# Fallback cache (only built if needed)
$script:IPtoHostname     = @{}
$script:ARecordCacheBuilt = $false

function Resolve-IpToShortName {
    param(
        [Parameter(Mandatory)] [string] $Ip,
        [Parameter(Mandatory)] [string] $DnsServer,
        [Parameter(Mandatory)] [string] $ZoneName
    )

    # 1) Regular DNS PTR lookup first
    try {
        # Note: some environments require the DNS server to be specified (you already have $DomainDNSServer)
        $ptr = Resolve-DnsName -Name $Ip -Type PTR -Server $DnsServer -ErrorAction Stop |
               Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1

        if ($ptr -and $ptr.NameHost) {
            return ($ptr.NameHost.TrimEnd('.').Split('.')[0].ToUpper())
        }
    } catch {
        # ignore and fall back
    }

    # 2) Fallback: build A-record cache once via Get-DnsServerResourceRecord (only if needed)
    if (-not $script:ARecordCacheBuilt) {
        Write-Host "  PTR lookup failed for at least one IP; fetching A records from $DnsServer zone: $ZoneName ..."
        try {
            $ARecords = Invoke-Command -ComputerName $DnsServer -ErrorAction Stop -ScriptBlock {
                Get-DnsServerResourceRecord -ZoneName $Using:ZoneName -RRType A -ErrorAction Stop
            }

            foreach ($rec in $ARecords) {
                $ipAddr = $rec.RecordData.IPv4Address.ToString()
                if ($ipAddr -and -not $script:IPtoHostname.ContainsKey($ipAddr)) {
                    $script:IPtoHostname[$ipAddr] = $rec.HostName
                }
            }

            $script:ARecordCacheBuilt = $true
            Write-Host "  A record cache built: $($script:IPtoHostname.Count) entries."
        } catch {
            $script:ARecordCacheBuilt = $true  # prevent repeated attempts
            Write-Warning "  Could not fetch A records from $DnsServer : $($_.Exception.Message)"
        }
    }

    if ($script:IPtoHostname.ContainsKey($Ip)) {
        return ($script:IPtoHostname[$Ip].ToUpper())
    }

    return $null
}

foreach ($Ev in $AllDCEvents) {

    # CallerComputer from 4740
    if ($Ev.EventId -eq 4740 -and $Ev.CallerComputer) {
        $c = $Ev.CallerComputer.TrimEnd('$').ToUpper().Trim()
        if ($c -and $c -ne '-' -and
            -not $TargetComputers.Contains($c)) {
            Write-Host "  + (4740 CallerComputer) $c"
            $TargetComputers.Add($c)
        }
    }

    # Loopback = the logging DC is the caller
    $lb = '^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$'
    if ($Ev.EventId -in @(4625,4771,4776) -and
        $Ev.IpAddress -match $lb) {
        $c = $Ev.SourceDC.ToUpper()
        if (-not $TargetComputers.Contains($c)) {
            Write-Host "  + (Loopback) $c [DC]"
            $TargetComputers.Add($c)
        }
    }

    # WorkstationName from 4625 / 4771 / 4776
    if ($Ev.EventId -in @(4625,4771,4776) -and $Ev.WorkstationName) {
        $c = $Ev.WorkstationName.TrimEnd('$').ToUpper().Trim()
        if ($c -and $c -ne '-' -and $c -notin $DCShortNames -and -not $TargetComputers.Contains($c)) {
            Write-Host "  + (WorkstationName) $c"
            $TargetComputers.Add($c)
        }
    }

    # IpAddress -> PTR first, fallback to A-record zone cache only if PTR fails
    $ip          = $Ev.IpAddress
    $isValidIPv4 = ($ip -match '^\d{1,3}(\.\d{1,3}){3}$')

    if ($ip -and
        $isValidIPv4 -and
        -not $SkipIPs.Contains($ip) -and
        $ip -notmatch '^::' -and
        $ip -notmatch '^fe80' -and
        $ip -notmatch '^169\.254' -and
        -not $SeenIPs.Contains($ip)) {

        $null = $SeenIPs.Add($ip)

        $resolved = Resolve-IpToShortName -Ip $ip -DnsServer $DomainDNSServer -ZoneName $DNSZone

        if ($resolved) {
            if ($resolved -notin $DCShortNames -and -not $TargetComputers.Contains($resolved)) {
                Write-Host "  + (DNS: $ip -> $resolved)"
                $TargetComputers.Add($resolved)
            }
        } else {
            Write-Warning "  IP $ip could not be resolved (PTR/A). Using raw IP."
            if (-not $TargetComputers.Contains($ip)) {
                $TargetComputers.Add($ip)
            }
        }
    }
}

if ($TargetComputers.Count -gt 0) {
    Write-Host "  Target computers ($($TargetComputers.Count)): $($TargetComputers -join ', ')"
} else {
    Write-Host "  No target computers found for analysis."
}


