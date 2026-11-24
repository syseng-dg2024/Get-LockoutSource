# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 1: DC Scan
# ==============================================================================
Write-Host "`n[Phase 1] Scanning Domain Controllers..."
$DCJobs = @()
foreach ($DC in $DomainControllers) {
    Write-Host "  Queuing: $DC"
    try {
        $Job = Invoke-Command -ComputerName $DC -AsJob -JobName "DC_$DC" -ErrorAction Stop -ScriptBlock {
            $LocalUser  = $Using:UserName
            $LocalZone  = $Using:DNSZone
            $LocalGrp1  = $Using:EventIdsGroup1
            $LocalGrp2  = $Using:EventIdsGroup2
            $LocalStart = $Using:StartDate
            $LocalEnd   = $Using:EndDate

            if ($LocalGrp1.Count -eq 0 -or $LocalGrp2.Count -eq 0) {
                Write-Warning "$env:COMPUTERNAME: EventId arrays did not deserialize."; return @()
            }

            $s   = $LocalStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
            $e   = $LocalEnd.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
            $id1 = ($LocalGrp1 | ForEach-Object { "EventID=$([int]$_)" }) -join ' or '
            $id2 = ($LocalGrp2 | ForEach-Object { "EventID=$([int]$_)" }) -join ' or '

            $uf = ''
            if ($LocalUser) {
                $uf = " and (EventData[Data[@Name='TargetUserName']='$LocalUser'] or " +
                      "EventData[Data[@Name='TargetUserName']='${LocalUser}@${LocalZone}'])"
            }

            $xp1 = "*[System[($id1) and TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]$uf]"
            $xp2 = "*[System[($id2) and TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]$uf]"

            $doc = New-Object System.Xml.XmlDocument
            $doc.LoadXml(
                "<QueryList><Query Id='0' Path='Security'>" +
                "<Select Path='Security'>P1</Select>" +
                "<Select Path='Security'>P2</Select>" +
                "</Query></QueryList>"
            )
            $sel = $doc.SelectNodes('//Select')
            $sel[0].InnerText = $xp1
            $sel[1].InnerText = $xp2

            try {
                $Events = Get-WinEvent -FilterXml $doc -ErrorAction Stop
                Write-Host "Got $($Events.Count) events from $env:COMPUTERNAME"
            } catch {
                if ($_.Exception.Message -like '*No events*') { Write-Host "No events on $env:COMPUTERNAME"; return @() }
                Write-Warning "$env:COMPUTERNAME: $($_.Exception.Message)"; return @()
            }

            foreach ($Ev in $Events) {
                try {
                    $x = [xml]$Ev.ToXml(); $d = @{}
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
                    [PSCustomObject]@{
                        TimeCreated         = $Ev.TimeCreated
                        EventId             = $Ev.Id
                        SourceDC            = $env:COMPUTERNAME
                        TargetUserName      = $d['TargetUserName']
                        SubjectUserName     = $d['SubjectUserName']
                        WorkstationName     = $d['WorkstationName']
                        CallerComputer      = $d['CallerComputerName']
                        IpAddress           = $d['IpAddress']
                        IpPort              = $d['IpPort']
                        LogonType           = $d['LogonType']
                        AuthPackage         = $d['AuthenticationPackageName']
                        LogonProcessName    = $d['LogonProcessName']
                        FailureReason       = $d['FailureReason']
                        Status              = $d['Status']
                        SubStatus           = $d['SubStatus']
                        ProcessName         = $d['ProcessName']
                        TargetDomainName    = $d['TargetDomainName']
                        ServiceName         = $d['ServiceName']
                        SubjectLogonId      = $d['SubjectLogonId']
                        TargetLogonId       = $d['TargetLogonId']
                        TransmittedServices = $d['TransmittedServices']
                        TicketOptions       = $d['TicketOptions']
                        TicketEncryptType   = $d['TicketEncryptionType']
                        PreAuthType         = $d['PreAuthType']
                    }
                } catch {}
            }
        }
        $DCJobs += [PSCustomObject]@{ DCName=$DC; Job=$Job }
    } catch { Write-Warning "  Could not queue $DC : $($_.Exception.Message)" }
}

Write-Host '  Waiting for DC jobs...'
$AllDCEvents = [System.Collections.Generic.List[object]]::new()
foreach ($Entry in $DCJobs) {
    try {
        $R = $Entry.Job | Wait-Job -Timeout 300 | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Entry.Job -Force -ErrorAction SilentlyContinue
    } catch { Write-Warning "  Failed collecting from $($Entry.DCName)"; continue }
    $R | Where-Object { $_ -is [string] } | ForEach-Object { Write-Host "  [DC] $_" }
    foreach ($O in @($R | Where-Object { $_ -isnot [string] -and $_ -ne $null })) { $AllDCEvents.Add($O) }
}
Write-Host "  DC scan complete: $($AllDCEvents.Count) events."

