# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Helper: Normalize-HexStatus
# ==============================================================================
function Normalize-HexStatus {
    param([string]$h)
    if (-not $h -or $h -in @('','-')) { return $h }
    $h = $h.Trim()
    if ($h -match '^0[xX]([0-9a-fA-F]+)$') { return ('0x' + $Matches[1].ToUpper()) }
    if ($h -match '^[0-9a-fA-F]{4,}$')     { return ('0x' + $h.ToUpper()) }
    return $h
}

# ==============================================================================
#  Helper: New-UnifiedRow  (hashtable-based, all fields defaulted to '')
# ==============================================================================
function New-UnifiedRow {
    param([hashtable]$F)
    $d = [ordered]@{
        # == Core ==============================================================
        Source='';Timestamp=$null;EventId='';EventDescription='';SourceServer=''
        # == User ==============================================================
        UserName='';FQDN='';SubjectUser=''
        # == Location ==========================================================
        WorkstationName='';CallerComputer='';IpAddress=''
        # == Authentication ====================================================
        LogonType='';LogonTypeName='';AuthMethod='';PacketType=''
        # == Status / Result ===================================================
        Result='';Status='';StatusDesc='';SubStatus='';SubStatusDesc=''
        FailureReasonDesc=''
        # == Process ===========================================================
        ProcessName='';LogonProcessName=''
        # == Logon Session IDs =================================================
        SubjectLogonId='';TargetLogonId=''
        # == Kerberos ==========================================================
        TargetDomainName='';ServiceName='';TicketOptions='';TicketEncryptType=''
        PreAuthType='';PreAuthDescription='';TransmittedServices=''
        # == NPS Policy ========================================================
        PolicyName='';ProxyPolicyName='';ServiceType='';ProviderType='';ProviderName=''
        # == NPS NAS ===========================================================
        NASIdentifier='';NASIPAddress='';NASPort='';NASPortType=''
        # == NPS Client ========================================================
        ClientFriendlyName='';ClientVendor='';RemoteServerAddress=''
        # == NPS Station IDs ===================================================
        CalledStationID='';CallingStationID='';CallbackNumber=''
        # == NPS Framing =======================================================
        FramedIPAddress='';FramedProtocol='';ConnectInfo='';PortLimit=''
        # == NPS MS Extensions =================================================
        MSRASClientName='';MSRASClientVersion='';MSRASVersion='';MSRASVendor=''
        MSCHAPError='';MSCHAPDomain='';MSMPPEEncryptTypes='';MSMPPEEncryptPolicy=''
        MSAcctAuthType='';MSAcctEAPType='';EAPFriendlyName=''
        # == NPS Session Control ===============================================
        SessionTimeout='';IdleTimeout='';TerminationAction='';EventTimestamp=''
        # == NPS Accounting ====================================================
        AcctStatusType='';AcctSessionId='';AcctSessionTime='';AcctDelay=''
        AcctInputOctets='';AcctOutputOctets='';AcctInputPackets='';AcctOutputPackets=''
        AcctTerminateCause='';AcctLinkCount='';AcctInterimInterval='';MSMultiSsnID=''
        # == NPS Tunnel ========================================================
        TunnelType='';TunnelMediumType='';TunnelClientEndpt='';TunnelServerEndpt=''
        TunnelPvtGroupID='';TunnelAssignmentID='';TunnelPreference='';AcctTunnelConn=''
    }
    foreach ($k in $F.Keys) { $d[$k] = $F[$k] }
    [PSCustomObject]$d
}

