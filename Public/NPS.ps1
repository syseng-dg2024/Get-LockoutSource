# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 3: NPS Service Discovery
# ==============================================================================
Write-Host "`n[Phase 3] Checking $($AllServers.Count) servers for NPS (IAS) service..."
$SvcJobs = @()
foreach ($Server in $AllServers) {
    try {
        $Job = Invoke-Command -ComputerName $Server -AsJob -JobName "NPSSVC_$Server" -ErrorAction Stop -ScriptBlock {
            $svc = Get-Service -Name 'IAS' -ErrorAction SilentlyContinue
            [PSCustomObject]@{ ComputerName=$env:COMPUTERNAME; IsNPS=($svc -and $svc.Status -eq 'Running') }
        }
        $SvcJobs += [PSCustomObject]@{ ServerName=$Server; Job=$Job }
    } catch {}
}

$ConfirmedNPSServers = @()
foreach ($Entry in $SvcJobs) {
    try {
        $R = $Entry.Job | Wait-Job -Timeout 30 | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
        if ($R.IsNPS) { Write-Host "  NPS found: $($R.ComputerName)"; $ConfirmedNPSServers += $R.ComputerName }
    } catch {}
}


# ==============================================================================
# Safety init: Phase 3 (NPS service discovery via WinRM) is commented out.
# $ConfirmedNPSServers will be empty; Phase 4 will skip gracefully.
if (-not (Get-Variable -Name ConfirmedNPSServers -ErrorAction SilentlyContinue)) {
    $ConfirmedNPSServers = @()
}
#  Phase 4: NPS Log Parse
# ==============================================================================
$AllNPSRaw = [System.Collections.Generic.List[object]]::new()

if ($ConfirmedNPSServers.Count -eq 0) {
    Write-Warning 'No NPS servers found or running. Skipping NPS parse.'
} else {
    Write-Host "`n[Phase 4] Parsing NPS logs on $($ConfirmedNPSServers.Count) server(s)..."
    $NPSJobs = @()

    foreach ($Server in $ConfirmedNPSServers) {
        try {
            $Job = Invoke-Command -ComputerName $Server -AsJob -JobName "NPSLOG_$Server" -ErrorAction Stop -ScriptBlock {

                $LocalUser    = $Using:UserName
                $LocalStart   = $Using:StartDate
                $LocalEnd     = $Using:EndDate
                $LocalHeaders = $Using:CsvHeaders

                # Locate log directory from ias.xml
                $iasXmlPath = 'C:\Windows\System32\ias\ias.xml'
                if (-not (Test-Path $iasXmlPath)) {
                    Write-Warning "$env:COMPUTERNAME: ias.xml not found"
                    return @()
                }

                $logPath = $null
                try {
                    [xml]$iasConfig = Get-Content $iasXmlPath -Raw
                    $logDirNode = $iasConfig.SelectSingleNode('//Log_File_Directory//DefaultValue')
                    if (-not $logDirNode) {
                        foreach ($n in $iasConfig.SelectNodes('//*[local-name()="DefaultValue"]')) {
                            if ($n.ParentNode.Name -like '*Log*') {
                                $logDirNode = $n
                                break
                            }
                        }
                    }
                    if ($logDirNode) {
                        $logPath = [System.Environment]::ExpandEnvironmentVariables(
                            ($logDirNode.InnerText -replace '%windir%', 'C:\Windows\System32'))
                    }
                } catch {
                    Write-Warning "$env:COMPUTERNAME: ias.xml parse error - $($_.Exception.Message)"
                    return @()
                }

                if (-not $logPath -or -not (Test-Path $logPath)) {
                    Write-Warning "$env:COMPUTERNAME: Log path not found: $logPath"
                    return @()
                }

                $LogFiles = Get-ChildItem -Path $logPath -Filter '*.log' -ErrorAction SilentlyContinue
                Write-Output "$env:COMPUTERNAME: $($LogFiles.Count) log file(s) in $logPath"
                $Results = @()

                foreach ($file in $LogFiles) {

                    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
                    if (-not $content) { continue }

                    foreach ($line in $content) {

                        $t = $line.Trim()
                        if (-not $t) { continue }

                        $parsed = $null

                        # IAS CSV format
                        if ($t.StartsWith('"')) {
                            try {
                                $row  = ($t | ConvertFrom-Csv -Header $LocalHeaders)[0]
                                $user = $row.'User-Name'

                                $matchesUser = (-not $LocalUser) -or
                                              ($user -like "*$LocalUser*") -or
                                              ($row.'Fully-Qualified-Distinguished-Name' -like "*$LocalUser*")

                                if ($matchesUser) {
                                    $ts = $null
                                    try {
                                        $ts = [datetime]::ParseExact(
                                            "$($row.'Record-Date') $($row.'Record-Time')",
                                            'MM/dd/yyyy HH:mm:ss', $null)
                                    } catch {
                                        $ts = $null
                                    }

                                    $inRange = (-not $ts) -or ($ts -ge $LocalStart -and $ts -le $LocalEnd)

                                    if ($inRange) {
                                        $clientIpOverride = ''
                                        if ($row.Class -and ($row.Class -split ' ').Count -ge 3) {
                                            $maybe = ($row.Class -split ' ')[2]
                                            if ($maybe -match '^\d{1,3}(\.\d{1,3}){3}$') {
                                                $clientIpOverride = $maybe
                                            }
                                        }

                                        $obj = [ordered]@{
                                            SourceServer     = $env:COMPUTERNAME
                                            Timestamp        = $ts
                                            ClientIPOverride = $clientIpOverride
                                        }
                                        foreach ($h in $LocalHeaders) {
                                            $obj[$h] = $row.$h
                                        }
                                        $parsed = [PSCustomObject]$obj
                                    }
                                }
                            } catch {
                                $parsed = $null
                            }

                        # IAS XML format
                        } elseif ($t.StartsWith('<')) {
                            try {
                                [xml]$xmlObj = $t
                                $en = $xmlObj.SelectSingleNode('//Event')

                                if ($en) {
                                    $user = ''
                                    if ($en.'User-Name') { $user = $en.'User-Name'.InnerText }

                                    $matchesUser = (-not $LocalUser) -or ($user -like "*$LocalUser*")

                                    if ($matchesUser) {
                                        $tsXml = $null
                                        if ($en.Timestamp) {
                                            try {
                                                $tsXml = [datetime]::ParseExact(
                                                    $en.Timestamp.InnerText,
                                                    'MM/dd/yyyy HH:mm:ss.fff', $null)
                                            } catch {
                                                $tsXml = $null
                                            }
                                        }

                                        $inRange = (-not $tsXml) -or ($tsXml -ge $LocalStart -and $tsXml -le $LocalEnd)

                                        if ($inRange) {
                                            $obj = [ordered]@{
                                                SourceServer     = $env:COMPUTERNAME
                                                Timestamp        = $tsXml
                                                ClientIPOverride = ''
                                            }
                                            foreach ($h in $LocalHeaders) {
                                                $node = $en.SelectSingleNode("*[local-name()='$h']")
                                                if ($node) {
                                                    $obj[$h] = $node.InnerText
                                                } else {
                                                    $obj[$h] = ''
                                                }
                                            }
                                            $parsed = [PSCustomObject]$obj
                                        }
                                    }
                                }
                            } catch {
                                $parsed = $null
                            }
                        }

                        if ($parsed) { $Results += $parsed }

                    } # end foreach line
                } # end foreach file

                Write-Output "$env:COMPUTERNAME: $($Results.Count) matching NPS entries"
                return $Results

            } # end scriptblock
            $NPSJobs += [PSCustomObject]@{ ServerName = $Server; Job = $Job }

        } catch {
            Write-Warning "  Could not queue NPS job for $Server : $($_.Exception.Message)"
        }
    } # end foreach Server

    foreach ($Entry in $NPSJobs) {
        try {
            $R = $Entry.Job | Wait-Job -Timeout 300 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "  Failed NPS job $($Entry.ServerName)"
            continue
        }
        $R | Where-Object { $_ -is [string] } | ForEach-Object { Write-Host "  [NPS] $_" }
        foreach ($O in @($R | Where-Object { $_ -isnot [string] -and $_ -ne $null })) {
            $AllNPSRaw.Add($O)
        }
    }
}

Write-Host "  NPS parse complete: $($AllNPSRaw.Count) raw entries."

