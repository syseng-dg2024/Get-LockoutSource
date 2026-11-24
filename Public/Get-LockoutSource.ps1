# DISCLAIMER: This script was written in part by AI. Please review before executing.
function Get-LockoutSource {
<#
.SYNOPSIS
  Finds the source of account lockouts: DC Security log scan, NPS logs, target discovery,
  device checks, and (for DC-local failures still happening) a live Kerberos ETW correlation.
.EXAMPLE
  Get-LockoutSource
.EXAMPLE
  Get-LockoutSource -UserName Username -HoursBack 4
.EXAMPLE
  Get-LockoutSource -UserName Username -ActiveLockout   # lockout still happening: also runs the live Kerberos trace
#>
[CmdletBinding()]
    param(
        [string]  $UserName,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [int]     $HoursBack         = 12,
        [string]  $AppRoot           = $script:ModuleRoot,
        [switch]  $ActiveLockout,
        [int]     $KerbSeconds       = 180,
        [int]     $KerbRecentMinutes = 10
    )

    if (-not $EndDate)   { $EndDate   = Get-Date }
    if (-not $StartDate) { $StartDate = $EndDate.AddHours(-$HoursBack) }

    $ReportPath = Join-Path $AppRoot 'Report'
    $LogPath    = Join-Path $AppRoot 'Log'
    foreach ($Dir in $ReportPath, $LogPath) {
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    }
    $LockoutAbort = $false
    $Public = Join-Path $script:ModuleRoot 'Public'
    $PublicFiles  = Get-ChildItem $Public -Filter '[0-9][0-9]-*.ps1' | Sort-Object Name
    foreach ($File in $PublicFiles) {
        Write-Verbose "Running $($File.Name)"
        . $File.FullName
        if ($LockoutAbort) { return }
    }

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
