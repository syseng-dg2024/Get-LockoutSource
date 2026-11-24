# Part of Get-LockoutSource. Dot-sourced inside Get-LockoutSource (shares its variables). Do not run on its own.
# ==============================================================================
#  GUI
# ==============================================================================
if (-not $UserName) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $Form                 = New-Object System.Windows.Forms.Form
    $Form.Text            = 'Lockout Source Analyzer v150'
    $Form.Size            = New-Object System.Drawing.Size(440,265)
    $Form.StartPosition   = 'CenterScreen'
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.MaximizeBox     = $false

    $LabelUser          = New-Object System.Windows.Forms.Label
    $LabelUser.Text     = 'Username:'
    $LabelUser.Location = New-Object System.Drawing.Point(20,20)
    $LabelUser.Size     = New-Object System.Drawing.Size(130,20)

    $TextBox          = New-Object System.Windows.Forms.TextBox
    $TextBox.Location = New-Object System.Drawing.Point(160,17)
    $TextBox.Size     = New-Object System.Drawing.Size(250,20)

    $LabelStart              = New-Object System.Windows.Forms.Label
    $LabelStart.Text         = 'Start Date / Time:'
    $LabelStart.Location     = New-Object System.Drawing.Point(20,57)
    $LabelStart.Size         = New-Object System.Drawing.Size(130,20)

    $DatePickerStart              = New-Object System.Windows.Forms.DateTimePicker
    $DatePickerStart.Format       = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $DatePickerStart.CustomFormat = 'MM/dd/yyyy hh:mm:ss tt'
    $DatePickerStart.ShowUpDown   = $true
    $DatePickerStart.Location     = New-Object System.Drawing.Point(160,54)
    $DatePickerStart.Size         = New-Object System.Drawing.Size(250,22)
    $DatePickerStart.Value        = $StartDate

    $LabelEnd              = New-Object System.Windows.Forms.Label
    $LabelEnd.Text         = 'End Date / Time:'
    $LabelEnd.Location     = New-Object System.Drawing.Point(20,95)
    $LabelEnd.Size         = New-Object System.Drawing.Size(130,20)

    $DatePickerEnd              = New-Object System.Windows.Forms.DateTimePicker
    $DatePickerEnd.Format       = [System.Windows.Forms.DateTimePickerFormat]::Custom
    $DatePickerEnd.CustomFormat = 'MM/dd/yyyy hh:mm:ss tt'
    $DatePickerEnd.ShowUpDown   = $true
    $DatePickerEnd.Location     = New-Object System.Drawing.Point(160,92)
    $DatePickerEnd.Size         = New-Object System.Drawing.Size(250,22)
    $DatePickerEnd.Value        = $EndDate

    $OKButton              = New-Object System.Windows.Forms.Button
    $OKButton.Text         = 'OK'
    $ActiveBox          = New-Object System.Windows.Forms.CheckBox
    $ActiveBox.Text     = 'Lockout is still active (run live Kerberos trace)'
    $ActiveBox.Location = New-Object System.Drawing.Point(20,128)
    $ActiveBox.Size     = New-Object System.Drawing.Size(390,22)
    $ActiveBox.Checked  = [bool]$ActiveLockout

    $OKButton.Location     = New-Object System.Drawing.Point(170,165)
    $OKButton.Size         = New-Object System.Drawing.Size(80,28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $Form.AcceptButton     = $OKButton
    $Form.Controls.AddRange(@($LabelUser,$TextBox,$LabelStart,$DatePickerStart,$LabelEnd,$DatePickerEnd,$ActiveBox,$OKButton))

    if ($Form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or [string]::IsNullOrWhiteSpace($TextBox.Text)) {
        Write-Warning 'Cancelled or no username entered. Exiting.'
        $LockoutAbort = $true; return
    }

    $UserName  = $TextBox.Text.Trim()
    $StartDate = $DatePickerStart.Value
    $EndDate   = $DatePickerEnd.Value
    $ActiveLockout = [switch]$ActiveBox.Checked
}

$DateStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not (Test-Path $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath | Out-Null }
#Export a CSV
#$UnifiedOutputPath = Join-Path $ReportPath "LockoutAnalysis_${UserName}_${DateStamp}.csv"
$DeviceOutputPath  = Join-Path $ReportPath "LockoutReport_${UserName}_${DateStamp}.html"

$ScriptStart = Get-Date
Write-Host "Script Started:  $($ScriptStart.ToString('MM/dd/yyyy hh:mm:ss tt'))"
Write-Host "Username:        $UserName"
Write-Host "Start:           $($StartDate.ToString('MM/dd/yyyy hh:mm:ss tt'))"
Write-Host "End:             $($EndDate.ToString('MM/dd/yyyy hh:mm:ss tt'))"
#Write-Host "Unified CSV:     $UnifiedOutputPath"
Write-Host "Device Report:   $DeviceOutputPath"

