# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Phase 5: Merge DC Events + NPS Entries Unified CSV (all translations here)
# ==============================================================================
Write-Host "`n[Phase 5] Building unified dataset..."
$UnifiedRows = [System.Collections.Generic.List[object]]::new()

# == DC Events Unified =====================================================
foreach ($Ev in $AllDCEvents) {
    $eid = [int]$Ev.EventId
    $lt  = "$($Ev.LogonType)"
    $st  = Normalize-HexStatus "$($Ev.Status)"
    $sst = Normalize-HexStatus "$($Ev.SubStatus)"
    $fr  = "$($Ev.FailureReason)"
    $pat = "$($Ev.PreAuthType)"

    $UnifiedRows.Add((New-UnifiedRow @{
        Source             = 'SecurityEvent'
        Timestamp          = $Ev.TimeCreated
        EventId            = $eid
        EventDescription   = if ($EventDescriptions[$eid])        { $EventDescriptions[$eid] }        else { '' }
        SourceServer       = $Ev.SourceDC
        UserName           = $Ev.TargetUserName
        SubjectUser        = $Ev.SubjectUserName
        WorkstationName    = $Ev.WorkstationName
        CallerComputer     = $Ev.CallerComputer
        IpAddress          = $Ev.IpAddress
        LogonType          = $lt
        LogonTypeName      = if ($LogonTypes[$lt])                 { $LogonTypes[$lt] }                else { '' }
        AuthMethod         = $Ev.AuthPackage
        Result             = $fr
        FailureReasonDesc  = if ($FailureReasons[$fr])             { $FailureReasons[$fr] }            else { $fr }
        Status             = $st
        StatusDesc         = if ($StatusDescriptions[$st])         { $StatusDescriptions[$st] }        else { '' }
        SubStatus          = $sst
        SubStatusDesc      = if ($StatusDescriptions[$sst])        { $StatusDescriptions[$sst] }       else { '' }
        ProcessName        = $Ev.ProcessName
        LogonProcessName   = $Ev.LogonProcessName
        SubjectLogonId     = $Ev.SubjectLogonId
        TargetLogonId      = $Ev.TargetLogonId
        TargetDomainName   = $Ev.TargetDomainName
        ServiceName        = $Ev.ServiceName
        TicketOptions      = $Ev.TicketOptions
        TicketEncryptType  = $Ev.TicketEncryptType
        PreAuthType        = $pat
        PreAuthDescription = if ($PreAuthTypes[$pat])              { $PreAuthTypes[$pat] }             else { '' }
        TransmittedServices= $Ev.TransmittedServices
    }))
}

# == NPS Entries Unified ===================================================
foreach ($NPS in $AllNPSRaw) {
    $pt  = "$($NPS.'Packet-Type')"
    $rc  = "$($NPS.'Reason-Code')"
    $at  = "$($NPS.'Authentication-Type')"
    $pvt = "$($NPS.'Provider-Type')"
    $cv  = "$($NPS.'Client-Vendor')"
    $npt = "$($NPS.'NAS-Port-Type')"
    $st  = "$($NPS.'Service-Type')"

    # Best-effort IP: Class-embedded override > Client-IP-Address > Framed-IP-Address
    $clientIp = $NPS.ClientIPOverride
    if (-not $clientIp) { $clientIp = $NPS.'Client-IP-Address' }
    if (-not $clientIp) { $clientIp = $NPS.'Framed-IP-Address' }

    $UnifiedRows.Add((New-UnifiedRow @{
        Source              = 'NPSLog'
        Timestamp           = $NPS.Timestamp
        SourceServer        = $NPS.SourceServer
        UserName            = $NPS.'User-Name'
        FQDN                = $NPS.'Fully-Qualified-Distinguished-Name'
        IpAddress           = $clientIp
        PacketType          = if ($PacketTypeTable[$pt])           { $PacketTypeTable[$pt] }           else { $pt }
        Result              = if ($ReasonCodeTable[$rc])           { $ReasonCodeTable[$rc] }           else { $rc }
        AuthMethod          = if ($NpsAuthTypeTable[$at])          { $NpsAuthTypeTable[$at] }          else { $at }
        ProviderType        = if ($NpsProviderTypeTable[$pvt])     { $NpsProviderTypeTable[$pvt] }     else { $pvt }
        ClientVendor        = if ($NpsClientVendorTable[$cv])      { $NpsClientVendorTable[$cv] }      else { $cv }
        NASPortType         = if ($NasPortTypeTable[$npt])         { $NasPortTypeTable[$npt] }         else { $npt }
        ServiceType         = if ($NpsServiceTypeTable[$st])       { $NpsServiceTypeTable[$st] }       else { $st }
        PolicyName          = $NPS.'Policy-Name'
        ProxyPolicyName     = $NPS.'Proxy-Policy-Name'
        ProviderName        = $NPS.'Provider-Name'
        NASIdentifier       = $NPS.'NAS-Identifier'
        NASIPAddress        = $NPS.'NAS-IP-Address'
        NASPort             = $NPS.'NAS-Port'
        ClientFriendlyName  = $NPS.'Client-Friendly-Name'
        RemoteServerAddress = $NPS.'Remote-Server-Address'
        CalledStationID     = $NPS.'Called-Station-ID'
        CallingStationID    = $NPS.'Calling-Station-ID'
        CallbackNumber      = $NPS.'Callback-Number'
        FramedIPAddress     = $NPS.'Framed-IP-Address'
        FramedProtocol      = $NPS.'Framed-Protocol'
        ConnectInfo         = $NPS.'Connect-Info'
        PortLimit           = $NPS.'Port-Limit'
        MSRASClientName     = $NPS.'MS-RAS-Client-Name'
        MSRASClientVersion  = $NPS.'MS-RAS-Client-Version'
        MSRASVersion        = $NPS.'MS-RAS-Version'
        MSRASVendor         = $NPS.'MS-RAS-Vendor'
        MSCHAPError         = $NPS.'MS-CHAP-Error'
        MSCHAPDomain        = $NPS.'MS-CHAP-Domain'
        MSMPPEEncryptTypes  = $NPS.'MS-MPPE-Encryption-Types'
        MSMPPEEncryptPolicy = $NPS.'MS-MPPE-Encryption-Policy'
        MSAcctAuthType      = $NPS.'MS-Acct-Auth-Type'
        MSAcctEAPType       = $NPS.'MS-Acct-EAP-Type'
        EAPFriendlyName     = $NPS.'EAP-Friendly-Name'
        SessionTimeout      = $NPS.'Session-Timeout'
        IdleTimeout         = $NPS.'Idle-Timeout'
        TerminationAction   = $NPS.'Termination-Action'
        EventTimestamp      = $NPS.'Event-Timestamp'
        AcctStatusType      = $NPS.'Acct-Status-Type'
        AcctSessionId       = $NPS.'Acct-Session-Id'
        AcctSessionTime     = $NPS.'Acct-Session-Time'
        AcctDelay           = $NPS.'Acct-Delay-Time'
        AcctInputOctets     = $NPS.'Acct-Input-Octets'
        AcctOutputOctets    = $NPS.'Acct-Output-Octets'
        AcctInputPackets    = $NPS.'Acct-Input-Packets'
        AcctOutputPackets   = $NPS.'Acct-Output-Packets'
        AcctTerminateCause  = $NPS.'Acct-Terminate-Cause'
        AcctLinkCount       = $NPS.'Acct-Link-Count'
        AcctInterimInterval = $NPS.'Acct-Interim-Interval'
        MSMultiSsnID        = $NPS.'Acct-Multi-Ssn-ID'
        TunnelType          = $NPS.'Tunnel-Type'
        TunnelMediumType    = $NPS.'Tunnel-Medium-Type'
        TunnelClientEndpt   = $NPS.'Tunnel-Client-Endpt'
        TunnelServerEndpt   = $NPS.'Tunnel-Server-Endpt'
        TunnelPvtGroupID    = $NPS.'Tunnel-Pvt-Group-ID'
        TunnelAssignmentID  = $NPS.'Tunnel-Assignment-ID'
        TunnelPreference    = $NPS.'Tunnel-Preference'
        AcctTunnelConn      = $NPS.'Acct-Tunnel-Conn'
    }))
}

<# Export a CSV
$UnifiedRows | Sort-Object Timestamp -Descending |
    Export-Csv -Path $UnifiedOutputPath -NoTypeInformation -Force

Write-Host "  Unified CSV: $($UnifiedRows.Count) rows ($($AllDCEvents.Count) DC + $($AllNPSRaw.Count) NPS) -> $UnifiedOutputPath"
#>

