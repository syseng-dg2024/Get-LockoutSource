# DISCLAIMER: This script was written in part by AI. Please review before executing.
function Get-LockoutSource {
<#
.SYNOPSIS
  Finds the source of account lockouts: DC Security log scan, NPS logs, target discovery,
  device checks, and (for DC-local failures still happening) a live Kerberos ETW correlation.
.EXAMPLE
  Get-LockoutSource                                  # GUI prompt, as before
.EXAMPLE
  Get-LockoutSource -UserName sysengadmin -HoursBack 4 -HoursForward 1
.EXAMPLE
  Get-LockoutSource -UserName sysengadmin -ActiveLockout   # lockout still happening: also runs the live Kerberos trace
#>
    [CmdletBinding()]
    param(
        [string]  $UserName,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [int]     $HoursBack         = 12,
        [int]     $HoursForward      = 12,
        [string]  $TempPath          = $(if ($env:LOCKOUT_OUTDIR) { $env:LOCKOUT_OUTDIR } else { 'C:\Windows\Temp' }),
        [switch]  $ActiveLockout,
        [int]     $KerbSeconds       = 180,
        [int]     $KerbRecentMinutes = 10
    )

    $LockoutAbort = $false
    $PartDir = Join-Path $script:ModuleRoot "Public"
    . (Join-Path $PartDir 'Config.ps1')
    . (Join-Path $PartDir 'Gui.ps1')
    if ($LockoutAbort) { return }
    . (Join-Path $PartDir 'ADQuery.ps1')
    if ($LockoutAbort) { return }
    . (Join-Path $PartDir 'Helpers.ps1')
    . (Join-Path $PartDir 'DCScan.ps1')
    . (Join-Path $PartDir 'Targets.ps1')
    . (Join-Path $PartDir 'KerberosCheck.ps1')
    . (Join-Path $PartDir 'NPS.ps1')
    . (Join-Path $PartDir 'UnifiedData.ps1')
    . (Join-Path $PartDir 'RemoteHelpers.ps1')
    . (Join-Path $PartDir 'DeviceChecks.ps1')
    . (Join-Path $PartDir 'Report.ps1')

    [PSCustomObject]@{
        UserName        = $UserName
        StartDate       = $StartDate
        EndDate         = $EndDate
        TargetComputers = @($TargetComputers)
        DCEvents        = $AllDCEvents
        NPSEntries      = $AllNPSRaw
        UnifiedRows     = $UnifiedRows
        DeviceDetails   = $DeviceDetails
        KerbResults     = @($KerbResults)
        ReportPath      = $DeviceOutputPath
    }
}
