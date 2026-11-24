# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  Configuration
# ==============================================================================

[int[]]$EventIdsGroup1 = @(4625,4740,4776,4771,5816,5817,4724,<#4688,#>4648,4723,4767,4768,4770,4777,4779,4769)
[int[]]$EventIdsGroup2 = @(4624,4634,4647,4672,4722,4725,4738,4778,4800,4801)

# ==============================================================================
#  NPS Lookup Tables
# ==============================================================================
$PacketTypeTable = @{
    '1'='Access-Request';     '2'='Access-Accept'
    '3'='Access-Reject';      '4'='Accounting-Request'
    '5'='Accounting-Response';'11'='Access-Challenge'
}
$ReasonCodeTable = @{
    '0'='The specified reason code is not defined.'
    '1'='The user has provided an incorrect password.'
    '2'='The user has provided an incorrect user name.'
    '3'='The user has provided an incorrect user name and password.'
}
$NpsAuthTypeTable     = @{ '1'='EAP';'2'='MS-CHAP-v2';'3'='MS-CHAP';'4'='PAP';'5'='CHAP';'8'='Custom' }
$NpsProviderTypeTable = @{ '1'='Windows';'2'='NetWare';'3'='RADIUS' }
$NpsClientVendorTable = @{ '0'='Unknown';'1'='Microsoft';'2'='Cisco' }
$NasPortTypeTable     = @{ '5'='Ethernet';'15'='Wireless - IEEE 802.11';'19'='Wireless - IEEE 802.11' }
$NpsServiceTypeTable  = @{ '2'='Framed' }

$CsvHeaders = @(
    'ComputerName','ServiceName','Record-Date','Record-Time','Packet-Type','User-Name',
    'Fully-Qualified-Distinguished-Name','Called-Station-ID','Calling-Station-ID','Callback-Number',
    'Framed-IP-Address','NAS-Identifier','NAS-IP-Address','NAS-Port','Client-Vendor',
    'Client-IP-Address','Client-Friendly-Name','Event-Timestamp','Port-Limit','NAS-Port-Type',
    'Connect-Info','Framed-Protocol','Service-Type','Authentication-Type','Policy-Name','Reason-Code',
    'Class','Session-Timeout','Idle-Timeout','Termination-Action','EAP-Friendly-Name','Acct-Status-Type',
    'Acct-Delay-Time','Acct-Input-Octets','Acct-Output-Octets','Acct-Session-Id','Acct-Authentic',
    'Acct-Session-Time','Acct-Input-Packets','Acct-Output-Packets','Acct-Terminate-Cause',
    'Acct-Multi-Ssn-ID','Acct-Link-Count','Acct-Interim-Interval','Tunnel-Type','Tunnel-Medium-Type',
    'Tunnel-Client-Endpt','Tunnel-Server-Endpt','Acct-Tunnel-Conn','Tunnel-Pvt-Group-ID',
    'Tunnel-Assignment-ID','Tunnel-Preference','MS-Acct-Auth-Type','MS-Acct-EAP-Type','MS-RAS-Version',
    'MS-RAS-Vendor','MS-CHAP-Error','MS-CHAP-Domain','MS-MPPE-Encryption-Types',
    'MS-MPPE-Encryption-Policy','Proxy-Policy-Name','Provider-Type','Provider-Name',
    'Remote-Server-Address','MS-RAS-Client-Name','MS-RAS-Client-Version'
)

# ==============================================================================
#  Security Event Translations
# ==============================================================================
$EventDescriptions = @{
    4624='An account was successfully logged on.'
    4625='An account failed to log on.'
    4634='An account was logged off.'
    4647='User initiated logoff.'
    4648='A logon was attempted using explicit credentials.'
    4672='Special privileges assigned to new logon.'
    4688='A new process has been created.'
    4722='A user account was enabled.'
    4723='An attempt was made to change an account password.'
    4724='An attempt was made to reset an account password.'
    4725='A user account was disabled.'
    4738='A user account was changed.'
    4740='A user account was locked out.'
    4767='A user account was unlocked.'
    4768='A Kerberos authentication ticket (TGT) was requested.'
    4769='A Kerberos service ticket was requested.'
    4770='A Kerberos service ticket was renewed.'
    4771='Kerberos pre-authentication failed.'
    4776='The computer attempted to validate the credentials for an account.'
    4777='The domain controller failed to validate the credentials for an account.'
    4778='A session was reconnected to a Window Station.'
    4779='A session was disconnected from a Window Station.'
    4800='The workstation was locked.'
    4801='The workstation was unlocked.'
    5379='Credential Manager credentials were read.'
    5816='Netlogon has failed an authentication. Request timed out.'
    5817='Netlogon has failed an authentication. Request timed out.'
    5823='User or Computer password has been changed.'
    6273='Network Policy Server denied access to a user.'
    5156='The Windows Filtering Platform has permitted a connection.'
    5158='The Windows Filtering Platform has permitted a bind to a local port.'
}

$LogonTypes = @{
    '2'='Interactive';'3'='Network';'4'='Batch';'5'='Service'
    '8'='Plain Text';'9'='RunAs';'10'='Remote Interactive';'11'='Cached Interactive'
}

$StatusDescriptions = @{
    '0xC0000064'='User not found. Bad username.'
    '0xC000006A'='Wrong password (NTLM / interactive).'
    '0xC000006D'='Generic logon failure (bad username or password).'
    '0xC000006F'='Account logon outside authorized hours.'
    '0xC0000070'='Account logon from unauthorized workstation.'
    '0xC0000071'='Password expired. Apps/services retrying with stale creds WILL loop and lock the account.'
    '0xC0000072'='Account disabled by administrator.'
    '0xC0000133'='Clocks out of sync (>5 min). Kerberos will fail; may cause lockout loops via NTLM fallback.'
    '0xC000015B'='User not granted requested logon type (logon right missing).'
    '0xC0000193'='Account expired.'
    '0xC0000224'='Password change required at next logon.'
    '0xC0000234'='Account locked out.'
    '0xC0000371'='No credential material for the specified account.'
    '0xC0000413'='Authentication firewall policy prevents this logon.'
    '0x0'       ='No error / Success.'
    '0x12'      ='Credentials revoked (Kerberos: account disabled, expired, or locked).'
    '0x17'      ='Password expired (Kerberos pre-auth).'
    '0x18'      ='Wrong password (Kerberos pre-auth). PRIMARY lockout cause - bad credential source.'
    '0x25'      ='Clock skew too great (>5 min). Fix time sync to resolve Kerberos failures.'
}

# 4776 NTLM error codes (ErrorCode field on DCs)
$NtlmErrorTable = @{
    '0x0'        ='Success.'
    '0xC0000064' ='User not found.'
    '0xC000006A' ='Wrong password.'
    '0xC000006D' ='Generic failure (bad user or password).'
    '0xC000006F' ='Outside logon hours.'
    '0xC0000070' ='Workstation restriction.'
    '0xC0000071' ='Password expired - primary cause of repeated lockouts from stale app or service creds.'
    '0xC0000072' ='Account disabled.'
    '0xC0000193' ='Account expired.'
    '0xC0000224' ='Must change password at next logon.'
    '0xC0000234' ='Account locked out.'
}

# 4771 Kerberos pre-authentication failure codes (FailureCode field)
$KerberosFailureTable = @{
    '0x1' ='Client not found in Kerberos database.'
    '0x2' ='Server not found in Kerberos database.'
    '0x6' ='Client not found in database (username typo or missing account).'
    '0x12'='Account disabled, expired, or locked. Check account status immediately.'
    '0x17'='Password expired - service or app retrying with old credentials will lock the account.'
    '0x18'='Pre-authentication failed (wrong password). Primary lockout cause - find the credential source.'
    '0x19'='Pre-authentication integrity check failed.'
    '0x20'='Ticket expired (clock skew or very long operation).'
    '0x25'='Clock skew too great (>5 min). Fix time sync to resolve Kerberos failures.'
    '0x3F'='Generic error - check other events for detail.'
}

$FailureReasons = @{
    '%%2305'='The specified user account has expired.'
    '%%2307'='Account locked out.'
    '%%2309'='Password expired.'
    '%%2310'='Account disabled.'
    '%%2311'='Logon time restriction violation.'
    '%%2312'='User not allowed to logon at this computer.'
    '%%2313'='Unknown user name or bad password.'
    '%%2304'='Error occurred during Logon.'
}

$PreAuthTypes = @{
    '0'  ='0 = Logon without Pre-Authentication.'
    '2'  ='2 = PA-ENC-TIMESTAMP - Normal type for standard password authentication.'
    '11' ='11 = PA-ETYPE-INFO - Requirement for additional pre-authentication.'
    '15' ='15 = PA-PK-AS-REP_OLD - Used for Smart Card logon authentication.'
    '16' ='16 = PA-PK-AS-REQ - Request sent to KDC in Smart Card authentication scenarios.'
    '17' ='17 = PA-PK-AS-REP - Smart Card authentication.'
    '19' ='19 = PA-ETYPE-INFO2 - Sent by the KDC in a KRB-ERROR.'
    '20' ='20 = PA-SVR-REFERRAL-INFO - Used in KDC Referrals tickets.'
    '138'='138 = PA-ENCRYPTED-CHALLENGE - Logon using Kerberos Armoring (FAST).'
}

